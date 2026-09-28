#!/usr/bin/env python3
"""Restore readable node references and binding constants from a DTB.

The result uses binding headers from this kernel tree. Original source layout,
comments and macro names are not stored in a DTB; names are inferred where the
provider and numeric value identify them. Addresses, masks and phandle IDs stay
hexadecimal, while counts and human-readable quantities become decimal.

Usage: scripts/dtb_to_readable_dts.py sm8650-mp.dtb
Compile with the kernel's usual CPP step, for example:
  cpp -nostdinc -undef -D__DTS__ -I include -x assembler-with-cpp \
      sm8650-mp.dts > /tmp/sm8650-mp.pp.dts
  dtc -I dts -O dtb -o /tmp/sm8650-mp.dtb /tmp/sm8650-mp.pp.dts
"""

import argparse
import ast
import collections
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
NODE = re.compile(r"^(\s*)(?:(\w+):\s*)?([^\s{}]+)\s*\{$")
PROP = re.compile(r"^(\s*)([\w,#+.\-]+) = <((?:0x[0-9a-fA-F]+\s*)+)>;$")
DEFINE = re.compile(r"^#define\s+(\w+)\s+(0x[\da-fA-F]+|\d+)\s*(?:/\*.*)?$")
INCLUDE = re.compile(r"^#include\s+<([^>]+)>", re.MULTILINE)
SOURCE_REF = re.compile(r"&(\w+)\s+([A-Z][A-Z0-9_]+)\b")
DECIMAL_PROPERTIES = {
    "width", "height", "stride", "clock-frequency", "clock-mult", "clock-div",
    "bus-width", "num-lanes", "max-frequency", "spi-max-frequency",
    "capacity-dmips-mhz", "dynamic-power-coefficient", "cache-level",
    "i-cache-size", "d-cache-size", "cache-size", "cache-line-size",
    "i-cache-line-size", "d-cache-line-size", "clock-lanes", "data-lanes",
    "polling-delay", "polling-delay-passive", "sustainable-power",
    "min-residency-us", "entry-latency-us", "exit-latency-us",
    "regulator-min-microvolt", "regulator-max-microvolt", "regulator-ramp-delay",
    "regulator-enable-ramp-delay", "regulator-min-microamp", "regulator-max-microamp",
    "opp-level", "opp-microvolt", "opp-microamp", "opp-peak-kBps", "opp-avg-kBps",
}
DECIMAL_REF_KINDS = {"clock", "reset", "power-domain", "interconnect", "gpio",
                     "phy", "dma", "pwm", "cooling", "thermal-sensor", "io-channel",
                     "sound-dai"}
REFS = {
    "clocks": "clock", "assigned-clocks": "clock", "assigned-clock-parents": "clock",
    "resets": "reset", "power-domains": "power-domain", "interconnects": "interconnect",
    "iommus": "iommu", "dmas": "dma", "mboxes": "mbox", "phys": "phy",
    "pwms": "pwm", "io-channels": "io-channel", "thermal-sensors": "thermal-sensor",
    "interrupts-extended": "interrupt", "gpios": "gpio", "cs-gpios": "gpio",
    "sound-dai": "sound-dai", "nvmem-cells": "nvmem-cell", "memory-region": None,
    "remote-endpoint": None, "interrupt-parent": None, "msi-parent": None,
    "next-level-cache": None, "operating-points-v2": None, "cpu": None,
    "required-opps": None, "domain-idle-states": None, "qcom,bcm-voters": None,
    "trip": None, "cooling-device": "cooling", "qcom,freq-domain": "clock",
    "gpio-ranges": "gpio-range", "gpio": "gpio",
}
SINGLE_REF = {"memory-region", "remote-endpoint", "interrupt-parent", "msi-parent",
              "next-level-cache", "operating-points-v2", "cpu", "nvmem-cells",
              "required-opps", "domain-idle-states", "qcom,bcm-voters", "trip"}


def node_path(stack, name):
    return "/" if name == "/" else (stack[-1].rstrip("/") + "/" + name)


def source_labels(files):
    labels = {}
    for file in files:
        stack = []
        for line in file.read_text(errors="replace").splitlines():
            m = NODE.match(line)
            if m:
                path = node_path(stack, m[3]) if stack else ("/" if m[3] == "/" else None)
                if path:
                    stack.append(path)
                    if m[2]:
                        labels.setdefault(path, m[2])
            elif re.match(r"^\s*};", line) and stack:
                stack.pop()
    return labels


def parse_dts(lines):
    nodes, props, line_paths, stack = {}, {}, {}, []
    for i, line in enumerate(lines):
        m = NODE.match(line)
        if m:
            path = node_path(stack, m[3]) if stack else "/"
            stack.append(path)
            nodes[path] = i
        elif re.match(r"^\s*};", line) and stack:
            stack.pop()
        elif stack:
            p = re.match(r"^\s*([\w,#+.\-]+) = (.*);$", line)
            if p:
                props.setdefault(stack[-1], {})[p[1]] = p[2]
                line_paths[i] = (stack[-1], p[1])
    return nodes, props, line_paths


def number_prop(props, path, name):
    value = props.get(path, {}).get(name, "")
    m = re.fullmatch(r"<0x([\da-fA-F]+)>", value)
    return int(m[1], 16) if m else None


def header_lines(file, seen=None):
    """Read a binding header and its local quoted includes."""
    seen = set() if seen is None else seen
    if file in seen or not file.is_file():
        return []
    seen.add(file)
    lines = file.read_text().splitlines()
    result = lines[:]
    for line in lines:
        m = re.match(r'^#include\s+"([^"]+)"', line)
        if m:
            result.extend(header_lines(file.parent / m[1], seen))
    return result


def make_labels(nodes, preferred):
    result, used = {}, set()
    for path in nodes:
        if path == "/":
            continue
        label = preferred.get(path)
        if not label or label in used:
            parts = path.strip("/").split("/")
            label = "_".join(parts[-2:] if len(parts) > 1 else parts)
            label = re.sub(r"[^\w]", "_", label)
            if not re.match(r"[A-Za-z_]", label):
                label = "node_" + label
        base, suffix = label, 2
        while label in used:
            label = f"{base}_{suffix}"
            suffix += 1
        used.add(label)
        result[path] = label
    return result


def constant_value(expression):
    """Evaluate a preprocessed integer macro without executing arbitrary text."""
    operations = {ast.BitOr: int.__or__, ast.BitAnd: int.__and__, ast.LShift: int.__lshift__,
                  ast.RShift: int.__rshift__, ast.Add: int.__add__, ast.Sub: int.__sub__}

    def walk(node):
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in operations:
            return operations[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Invert):
            return ~walk(node.operand)
        raise ValueError("not an integer constant")

    return walk(ast.parse(expression, mode="eval").body)


def source_constants(sources):
    """Resolve binding macros used by the current kernel's SM8650 DTS sources."""
    contents = [file.read_text(errors="replace") for file in sources if file.is_file()]
    includes = list(dict.fromkeys(name for content in contents for name in INCLUDE.findall(content)))
    names = set(name for content in contents for _, name in SOURCE_REF.findall(content))
    names.update(("QCOM_ICC_TAG_ACTIVE_ONLY", "QCOM_ICC_TAG_ALWAYS"))
    names.update(name for content in contents
                 for name in re.findall(r"\bopp-level\s*=\s*<([A-Z][A-Z0-9_]+)>", content))
    snippet = "".join(f"#include <{name}>\n" for name in includes)
    snippet += "".join(f"__DTS_CONST_{i} {name}\n" for i, name in enumerate(sorted(names)))
    proc = subprocess.run(["cpp", "-P", "-nostdinc", "-undef", "-D__DTS__",
                           "-I", str(ROOT / "include"), "-x", "assembler-with-cpp", "-"],
                          input=snippet, text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(proc.stderr.strip() or "cpp failed on binding headers")
    values = {}
    ordered = sorted(names)
    for line in proc.stdout.splitlines():
        m = re.match(r"__DTS_CONST_(\d+)\s+(.+)", line)
        if m:
            try:
                values[ordered[int(m[1])]] = constant_value(m[2])
            except (SyntaxError, ValueError, KeyError):
                pass
    header_for = {}
    for header in includes:
        file = ROOT / "include" / header
        if file.is_file():
            for name in re.findall(r"^#define\s+(\w+)\s+", "\n".join(header_lines(file)), re.MULTILINE):
                header_for.setdefault(name, header)
    hints = collections.defaultdict(set)
    for content in contents:
        for provider, name in SOURCE_REF.findall(content):
            if name in values and name in header_for:
                hints[(provider, values[name])].add(name)
    return values, header_for, hints


def constants():
    """SM8650 specific numeric bindings, selected by provider compatible."""
    tables = {}
    for kind in ("clock", "reset", "interconnect"):
        for header in (ROOT / "include/dt-bindings" / kind).glob("*sm8650*.h"):
            vals = collections.defaultdict(list)
            for line in header_lines(header):
                m = DEFINE.match(line)
                if m:
                    vals[int(m[2], 0)].append(m[1])
            tables[(kind, header.stem)] = vals
    return tables


def binding_name(kind, provider, props, value, tables, preferred, source_data):
    def belongs(name):
        if kind == "clock":
            return not (name.endswith(("_GDSC", "_BCR", "_ARES")) or "_RESET" in name)
        if kind == "reset":
            return "RESET" in name or name.endswith(("_BCR", "_ARES"))
        if kind == "power-domain":
            return name.endswith("_GDSC") or name.startswith(("RPMHPD_", "RPMPD_"))
        return True

    _, header_for, hints = source_data
    source_label = preferred.get(provider)
    if source_label:
        candidates = hints.get((source_label, value), set())
        folders = {"power-domain": ("power", "clock"),
                   "reset": ("reset", "clock")}.get(kind, (kind,))
        candidates = {name for name in candidates
                      if any(header_for[name].startswith(f"dt-bindings/{folder}/") for folder in folders)
                      and belongs(name)
                      and (kind != "interconnect" or name.startswith(("MASTER_", "SLAVE_")))}
        if len(candidates) == 1:
            name = next(iter(candidates))
            return name, header_for[name]
    compat = props.get(provider, {}).get("compatible", "")
    for (header_kind, stem), values in tables.items():
        if header_kind != kind and not (header_kind == "clock" and kind in ("reset", "power-domain")):
            continue
        if f'"{stem}"' not in compat:
            continue
        names = [name for name in values.get(value, []) if belongs(name)]
        if len(names) == 1:
            return names[0], f"dt-bindings/{header_kind}/{stem}.h"
    return None, None


def property_kind(name):
    if name in REFS:
        return REFS[name]
    if re.fullmatch(r"pinctrl-\d+", name):
        return None
    if name.endswith("-gpios") or name.endswith("-gpio"):
        return "gpio"
    if name.endswith("-supply") or name.endswith("-handle"):
        return None
    return False


def convert_property(name, cells, phandles, labels, props, tables, preferred,
                     source_data, used_headers):
    kind = property_kind(name)
    if kind is False:
        return None
    output = []
    pos = 0
    while pos < len(cells):
        value = int(cells[pos], 16)
        provider = phandles.get(value)
        if provider is None:
            # A missing phandle or gpio placeholder must stay numeric.
            if kind in ("gpio", "clock") and value == 0:
                output.append("0")
                pos += 1
                continue
            return None
        count = 0
        if kind == "gpio-range":
            count = 3
        elif kind:
            count = number_prop(props, provider, f"#{kind}-cells")
            if count is None:
                # Some bindings use a different spelling for their specifier.
                count = 0 if name in SINGLE_REF else None
        if count is None or pos + count >= len(cells):
            return None
        output.append("&" + labels[provider])
        for index, raw in enumerate(cells[pos + 1:pos + 1 + count]):
            rendered = str(int(raw, 16)) if kind in DECIMAL_REF_KINDS else raw
            # Only the first argument is an ID from these binding headers;
            # later cells may be flags or another independent namespace.
            if index == 0 and kind in ("clock", "reset", "interconnect", "power-domain"):
                macro, header = binding_name(kind, provider, props, int(raw, 16),
                                             tables, preferred, source_data)
                if macro:
                    rendered = macro
                    used_headers.add(header)
            if kind == "interconnect" and index == 1:
                tag = {source_data[0].get("QCOM_ICC_TAG_ACTIVE_ONLY"): "QCOM_ICC_TAG_ACTIVE_ONLY",
                       source_data[0].get("QCOM_ICC_TAG_ALWAYS"): "QCOM_ICC_TAG_ALWAYS"}.get(int(raw, 16))
                if tag:
                    rendered = tag
                    used_headers.add(source_data[1][tag])
            output.append(rendered)
        pos += count + 1
    return "<" + " ".join(output) + ">"


def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dtb", type=pathlib.Path, help="input DTB")
    parser.add_argument("-o", "--output", type=pathlib.Path, help="output DTS (default: DTB stem.dts)")
    parser.add_argument("--kernel", type=pathlib.Path, default=ROOT, help="kernel source tree")
    args = parser.parse_args()
    ROOT = args.kernel.resolve()
    output = args.output or args.dtb.with_suffix(".dts")
    if output.resolve() == args.dtb.resolve():
        parser.error("output must differ from input")
    proc = subprocess.run(["dtc", "-q", "-I", "dtb", "-O", "dts", "-o", "-", str(args.dtb)],
                          text=True, capture_output=True)
    if proc.returncode:
        parser.error(proc.stderr.strip() or "dtc failed")
    lines = proc.stdout.splitlines(keepends=True)
    nodes, props, line_paths = parse_dts(lines)
    source_dir = ROOT / "arch/arm64/boot/dts/qcom"
    sources = [source_dir / "sm8650.dtsi"] + sorted(source_dir.glob("sm8650*.dts*"))
    phandles = {}
    for path in nodes:
        phandle = number_prop(props, path, "phandle")
        if phandle:
            if phandle in phandles:
                parser.error(f"duplicate phandle {phandle:#x}")
            phandles[phandle] = path
    preferred = source_labels(file for file in sources if file.is_file())
    labels = make_labels({path: nodes[path] for path in nodes if path in phandles.values()}, preferred)
    tables = constants()
    source_data = source_constants(sources)
    headers = set()
    converted = 0
    for path, i in nodes.items():
        if path in labels:
            m = NODE.match(lines[i])
            lines[i] = f"{m[1]}{labels[path]}: {m[3]} {{\n"
    for i, (path, name) in line_paths.items():
        m = PROP.match(lines[i])
        if not m:
            continue
        cells = re.findall(r"0x[\da-fA-F]+", m[3])
        rendered = convert_property(name, cells, phandles, labels, props, tables,
                                    preferred, source_data, headers)
        if rendered is not None:
            lines[i] = f"{m[1]}{name} = {rendered};\n"
            converted += 1
        elif name == "opp-level" and len(cells) == 1 and "/power-controller/opp-table/" in path:
            matches = [macro for macro, value in source_data[0].items()
                       if macro.startswith("RPMH_REGULATOR_LEVEL_") and value == int(cells[0], 16)]
            if len(matches) == 1:
                lines[i] = f"{m[1]}{name} = <{matches[0]}>;\n"
                headers.add(source_data[1][matches[0]])
            else:
                lines[i] = f"{m[1]}{name} = <{int(cells[0], 16)}>;\n"
        elif name in DECIMAL_PROPERTIES or re.fullmatch(r"#[\w-]+-cells", name):
            lines[i] = f"{m[1]}{name} = <{' '.join(str(int(cell, 16)) for cell in cells)}>;\n"
    include_lines = "".join(f"#include <{header}>\n" for header in sorted(headers))
    # DTS includes need a C preprocessor, just as kernel DTS sources do.
    lines.insert(1, include_lines)
    output.write_text("".join(lines))
    print(f"{output}: {len(labels)} labels, {converted} reference properties, "
          f"{len(headers)} binding headers", file=sys.stderr)


if __name__ == "__main__":
    main()
