#!/usr/bin/env python3
"""Extract /dev/buses/qupac* devcfg data from a Qualcomm devcfg ELF/MBN.

The extractor focuses on the QUP access-control properties used by files like
QUPAC_Access.c/xml:

  qupv3_perms, qupv3_perms_size
  gpii_perms, gpii_perms_size
  ssc_qupv3_perms, ssc_qupv3_perms_size
  ssc_gpii_perms, ssc_gpii_perms_size

It supports 32-bit and 64-bit little-endian ELF containers without section
headers, and handles the memory-optimised DAL property format.
"""

from __future__ import annotations

import argparse
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


PT_LOAD = 1
PROP_END = 0xFF00FF00

PROP_TYPES = {
    0x02: "DALPROP_ATTR_TYPE_UINT32",
    0x08: "DALPROP_ATTR_TYPE_BYTE_SEQ",
    0x11: "DALPROP_ATTR_TYPE_STRING_PTR",
    0x12: "DALPROP_ATTR_TYPE_STRUCT_PTR",
    0x14: "DALPROP_ATTR_TYPE_UINT32_SEQ_PTR",
    0x18: "DALPROP_ATTR_TYPE_BYTE_SEQ_PTR",
}

QUP_PROP_ORDER = (
    ("qupv3_perms", "qupv3_perms_size", "se"),
    ("gpii_perms", "gpii_perms_size", "gpii"),
    ("ssc_qupv3_perms", "ssc_qupv3_perms_size", "se"),
    ("ssc_gpii_perms", "ssc_gpii_perms_size", "gpii"),
)

PROP_SYMBOL_BASE = {
    "qupv3_perms": "qupv3_perms",
    "gpii_perms": "qupv3_gpii_perms",
    "ssc_qupv3_perms": "ssc_qupv3_perms",
    "ssc_gpii_perms": "ssc_qupv3_gpii_perms",
}

SIZE_SYMBOL_BASE = {
    "qupv3_perms": "qupv3_perms_size",
    "gpii_perms": "qupv3_gpii_perms_size",
    "ssc_qupv3_perms": "ssc_qupv3_perms_size",
    "ssc_gpii_perms": "ssc_qupv3_gpii_perms_size",
}

PROTOCOL_NAMES = {
    0: "QUPV3_PROTOCOL_NONE",
    1: "QUPV3_PROTOCOL_SPI",
    2: "QUPV3_PROTOCOL_UART_2W",
    3: "QUPV3_PROTOCOL_I2C",
    4: "QUPV3_PROTOCOL_I3C",
    5: "QUPV3_PROTOCOL_SPI_SLAVE",
    6: "QUPV3_PROTOCOL_AFC",
    7: "QUPV3_PROTOCOL_SPMI",
    8: "QUPV3_PROTOCOL_QSPI_HID",
    9: "QUPV3_PROTOCOL_QSPI",
    13: "QUPV3_PROTOCOL_UFCS",
    18: "QUPV3_PROTOCOL_UART_4W",
    34: "QUPV3_PROTOCOL_UART_4W",
    0x104: "QUPV3_PROTOCOL_I3C_IBI",
}

MODE_NAMES = {
    0: "QUPV3_MODE_FIFO",
    1: "QUPV3_MODE_CPU_DMA",
    2: "QUPV3_MODE_GSI",
}

AC_NAMES = {
    0: "AC_NONE",
    1: "AC_TZ",
    2: "AC_HLOS_GSI",
    3: "AC_HLOS",
    4: "AC_HYP",
    5: "AC_SSC_Q6_ELF",
    6: "AC_ADSP_Q6_ELF",
    7: "AC_SOCCP",
    8: "AC_DCP",
    9: "AC_HLOS_SOCCP",
    10: "AC_SOCCP_DCP",
    11: "AC_HLOS_SOCCP_MODEM",
    12: "AC_VIDEO_FW",
    13: "AC_CP_CAMERA",
    14: "AC_HLOS_UNMAPPED",
    15: "AC_MSS_MSA",
    16: "AC_MSS_NONMSA",
    17: "AC_UNMAPPED",
    18: "AC_LPASS",
    19: "AC_NON_SECURE",
    20: "AC_HLOS_MODEM",
    21: "AC_GVM_TUI",
    22: "AC_SPSS_SP",
    0xFF: "AC_DEFAULT",
}


@dataclass(frozen=True)
class LoadSegment:
    offset: int
    vaddr: int
    filesz: int


@dataclass
class PropsInfo:
    addr: int
    offset: int
    propbin_addr: int
    propbin_off: int
    structptr_addr: int
    structptr_off: int
    num_devices: int
    stringdev_addr: int
    stringdev_off: int
    propbin_len: int
    name_section: int
    string_section: int
    byte_section: int
    uint32_section: int
    device_names: List[str] = field(default_factory=list)


@dataclass
class StringDevice:
    index: int
    name: str
    hash_value: int
    prop_offset: int


@dataclass
class Prop:
    name: str
    type_id: int
    value: int


@dataclass(frozen=True)
class StructTarget:
    index: int
    size_field: int
    ptr: int
    offset: int


@dataclass
class ArrayInfo:
    prop_name: str
    kind: str
    count: int
    ptr: int
    offset: int
    records: Tuple[Tuple[int, ...], ...]
    raw_bytes: bytes
    symbol: str = ""
    size_symbol: str = ""

    @property
    def key(self) -> Tuple[str, bytes, int]:
        return (self.kind, self.raw_bytes, self.count)


@dataclass
class DeviceOut:
    name: str
    region_addr: int
    prop_symbols: Dict[str, Tuple[str, str]]

    @property
    def signature(self) -> Tuple[Tuple[str, str, str], ...]:
        return tuple((k, v[0], v[1]) for k, v in sorted(self.prop_symbols.items()))


class ElfImage:
    def __init__(self, data: bytes, path: Path) -> None:
        self.data = data
        self.path = path
        self.elf_class = 0
        self.ptr_size = 0
        self.loads: List[LoadSegment] = []
        self._parse()

    def _parse(self) -> None:
        if len(self.data) < 0x34 or self.data[:4] != b"\x7fELF":
            raise ValueError(f"{self.path} is not an ELF file")
        if self.data[5] != 1:
            raise ValueError("only little-endian ELF files are supported")

        self.elf_class = self.data[4]
        if self.elf_class == 1:
            self.ptr_size = 4
            hdr = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
            phoff, phentsize, phnum = hdr[5], hdr[9], hdr[10]
            ph_fmt = "<IIIIIIII"
        elif self.elf_class == 2:
            self.ptr_size = 8
            hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
            phoff, phentsize, phnum = hdr[5], hdr[9], hdr[10]
            ph_fmt = "<IIQQQQQQ"
        else:
            raise ValueError(f"unsupported ELF class {self.elf_class}")

        for idx in range(phnum):
            off = phoff + idx * phentsize
            if off + struct.calcsize(ph_fmt) > len(self.data):
                continue
            fields = struct.unpack_from(ph_fmt, self.data, off)
            if self.elf_class == 1:
                p_type, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_flags, _p_align = fields
            else:
                p_type, _p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = fields
            if p_type == PT_LOAD and p_filesz:
                self.loads.append(LoadSegment(p_offset, p_vaddr, p_filesz))

        if not self.loads:
            raise ValueError("no PT_LOAD segments found")

    def vaddr_to_offset(self, addr: int) -> Optional[int]:
        for seg in self.loads:
            if seg.vaddr <= addr < seg.vaddr + seg.filesz:
                return seg.offset + (addr - seg.vaddr)
        return None

    def offset_to_vaddr(self, off: int) -> Optional[int]:
        for seg in self.loads:
            if seg.offset <= off < seg.offset + seg.filesz:
                return seg.vaddr + (off - seg.offset)
        return None

    def is_range(self, off: Optional[int], size: int) -> bool:
        return off is not None and 0 <= off <= len(self.data) - size

    def read_u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def read_c_string(self, addr: int, max_len: int = 256) -> Optional[str]:
        off = self.vaddr_to_offset(addr)
        if off is None or off >= len(self.data):
            return None
        end_limit = min(len(self.data), off + max_len)
        end = self.data.find(b"\x00", off, end_limit)
        if end < 0:
            return None
        raw = self.data[off:end]
        if not raw:
            return ""
        if any(b < 0x20 or b > 0x7E for b in raw):
            return None
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            return None


def read_props_info_at(img: ElfImage, off: int) -> Optional[PropsInfo]:
    if img.ptr_size == 8:
        fmt = "<QQI4xQ"
    else:
        fmt = "<IIII"
    size = struct.calcsize(fmt)
    if not img.is_range(off, size):
        return None

    propbin_addr, structptr_addr, num_devices, stringdev_addr = struct.unpack_from(fmt, img.data, off)
    if not (0 < num_devices <= 4096):
        return None

    propbin_off = img.vaddr_to_offset(propbin_addr)
    structptr_off = img.vaddr_to_offset(structptr_addr)
    stringdev_off = img.vaddr_to_offset(stringdev_addr)
    if not (img.is_range(propbin_off, 24) and img.is_range(structptr_off, img.ptr_size * 2)):
        return None

    entry_size = 40 if img.ptr_size == 8 else 24
    if not img.is_range(stringdev_off, num_devices * entry_size):
        return None

    propbin_len, name_sec, string_sec, byte_sec, uint32_sec, _legacy_count = struct.unpack_from(
        "<IIIIII", img.data, propbin_off
    )
    if not (24 <= name_sec <= string_sec <= byte_sec <= uint32_sec <= propbin_len):
        return None
    if not img.is_range(propbin_off, propbin_len):
        return None

    addr = img.offset_to_vaddr(off)
    if addr is None:
        return None

    return PropsInfo(
        addr=addr,
        offset=off,
        propbin_addr=propbin_addr,
        propbin_off=propbin_off,
        structptr_addr=structptr_addr,
        structptr_off=structptr_off,
        num_devices=num_devices,
        stringdev_addr=stringdev_addr,
        stringdev_off=stringdev_off,
        propbin_len=propbin_len,
        name_section=name_sec,
        string_section=string_sec,
        byte_section=byte_sec,
        uint32_section=uint32_sec,
    )


def iter_string_devices(img: ElfImage, pi: PropsInfo) -> Iterable[StringDevice]:
    entry_size = 40 if img.ptr_size == 8 else 24
    for idx in range(pi.num_devices):
        off = pi.stringdev_off + idx * entry_size
        if img.ptr_size == 8:
            name_addr, hash_value, prop_offset, _entry_func, _num_col, _collision = struct.unpack_from(
                "<QIIQI4xQ", img.data, off
            )
        else:
            name_addr, hash_value, prop_offset, _entry_func, _num_col, _collision = struct.unpack_from(
                "<IIIIII", img.data, off
            )
        name = img.read_c_string(name_addr)
        if name is None:
            continue
        yield StringDevice(idx, name, hash_value, prop_offset)


def prop_name_from_offset(img: ElfImage, pi: PropsInfo, name_off: int) -> Optional[str]:
    if name_off < 0 or name_off >= pi.string_section - pi.name_section:
        return None
    off = pi.propbin_off + pi.name_section + name_off
    end_limit = pi.propbin_off + pi.string_section
    end = img.data.find(b"\x00", off, end_limit)
    if end < 0:
        return None
    raw = img.data[off:end]
    if not raw or any(b < 0x20 or b > 0x7E for b in raw):
        return None
    return raw.decode("ascii")


def parse_props_memory_optimised(img: ElfImage, pi: PropsInfo, prop_offset: int) -> List[Prop]:
    props: List[Prop] = []
    pos = pi.propbin_off + prop_offset
    end = pi.propbin_off + pi.propbin_len
    for _ in range(512):
        if pos + 4 > end:
            raise ValueError("property list exceeded PropBin")
        word0 = img.read_u32(pos)
        if word0 == PROP_END:
            return props
        if pos + 8 > end:
            raise ValueError("truncated memory-optimised property")
        type_id = (word0 >> 24) & 0xFF
        if type_id not in PROP_TYPES:
            raise ValueError(f"unknown property type 0x{type_id:x}")
        name_bits = word0 & 0x00FFFFFF
        if name_bits & 0x800000:
            name = prop_name_from_offset(img, pi, name_bits & 0x7FFFFF)
            if name is None:
                raise ValueError("bad property name offset")
        else:
            name = f"id_{name_bits}"
        value = img.read_u32(pos + 4)
        props.append(Prop(name, type_id, value))
        pos += 8
    raise ValueError("unterminated property list")


def parse_props_legacy(img: ElfImage, pi: PropsInfo, prop_offset: int) -> List[Prop]:
    props: List[Prop] = []
    pos = pi.propbin_off + prop_offset
    end = pi.propbin_off + pi.propbin_len
    for _ in range(512):
        if pos + 4 > end:
            raise ValueError("property list exceeded PropBin")
        type_id = img.read_u32(pos)
        if type_id == PROP_END:
            return props
        if type_id not in PROP_TYPES or pos + 12 > end:
            raise ValueError("bad legacy property")
        name_off = img.read_u32(pos + 4)
        name = prop_name_from_offset(img, pi, name_off)
        if name is None:
            name = f"id_{name_off}"
        value = img.read_u32(pos + 8)
        props.append(Prop(name, type_id, value))

        if type_id == 0x08:
            seq_len = img.data[pos + 8] + 1
            padded = (seq_len + 1 + 3) & ~3
            pos += 8 + padded
        else:
            pos += 12
    raise ValueError("unterminated property list")


def parse_props(img: ElfImage, pi: PropsInfo, prop_offset: int) -> List[Prop]:
    try:
        return parse_props_memory_optimised(img, pi, prop_offset)
    except ValueError:
        return parse_props_legacy(img, pi, prop_offset)


def find_props_infos(img: ElfImage) -> List[PropsInfo]:
    found: Dict[int, PropsInfo] = {}
    scan_size = 32 if img.ptr_size == 8 else 16
    for seg in img.loads:
        start = seg.offset
        stop = min(len(img.data), seg.offset + seg.filesz - scan_size + 1)
        for off in range(start, stop, 4):
            pi = read_props_info_at(img, off)
            if pi is None:
                continue
            devices = list(iter_string_devices(img, pi))
            pi.device_names = [dev.name for dev in devices]
            if any(name.startswith("/dev/buses/qupac") for name in pi.device_names):
                found[pi.addr] = pi
    return list(found.values())


def read_struct_target(img: ElfImage, pi: PropsInfo, index: int) -> Optional[StructTarget]:
    entry_size = img.ptr_size * 2
    off = pi.structptr_off + index * entry_size
    if not img.is_range(off, entry_size):
        return None
    if img.ptr_size == 8:
        size_field, ptr = struct.unpack_from("<QQ", img.data, off)
    else:
        size_field, ptr = struct.unpack_from("<II", img.data, off)
    ptr_off = img.vaddr_to_offset(ptr)
    if ptr_off is None:
        return None
    return StructTarget(index=index, size_field=size_field, ptr=ptr, offset=ptr_off)


def read_count_from_size_prop(img: ElfImage, pi: PropsInfo, prop: Prop) -> Optional[int]:
    target = read_struct_target(img, pi, prop.value)
    if target is None or not img.is_range(target.offset, 4):
        return None
    count = img.read_u32(target.offset)
    if count > 4096:
        return None
    return count


def score_se_records(records: Sequence[Tuple[int, ...]]) -> int:
    score = 0
    for periph, protocol, mode, owner, allow_fifo, load, mod_excl in records:
        score += int(0 <= periph < 256)
        score += int(protocol in PROTOCOL_NAMES or 0 <= protocol < 0x200)
        score += int(mode in MODE_NAMES)
        score += int(0 <= owner <= 0xFF)
        score += int(allow_fifo in (0, 1))
        score += int(load in (0, 1))
        score += int(mod_excl in (0, 1))
    return score


def decode_se_array(img: ElfImage, off: int, count: int) -> Tuple[int, Tuple[Tuple[int, ...], ...], bytes]:
    candidates: List[Tuple[int, int, Tuple[Tuple[int, ...], ...], bytes]] = []
    if img.is_range(off, count * 20):
        records = []
        for idx in range(count):
            rec_off = off + idx * 20
            records.append(struct.unpack_from("<IIIIBBB", img.data, rec_off))
        raw = img.data[off : off + count * 20]
        candidates.append((score_se_records(records), 20, tuple(records), raw))

    if img.is_range(off, count * 28):
        records = []
        for idx in range(count):
            rec_off = off + idx * 28
            records.append(struct.unpack_from("<IIIIIII", img.data, rec_off))
        raw = img.data[off : off + count * 28]
        candidates.append((score_se_records(records), 28, tuple(records), raw))

    if not candidates:
        raise ValueError("SE array points outside file")
    candidates.sort(key=lambda item: item[0], reverse=True)
    _score, stride, records, raw = candidates[0]
    return stride, records, raw


def decode_gpii_array(img: ElfImage, off: int, count: int) -> Tuple[Tuple[Tuple[int, ...], ...], bytes]:
    size = count * 12
    if not img.is_range(off, size):
        raise ValueError("GPII array points outside file")
    records = tuple(struct.unpack_from("<III", img.data, off + idx * 12) for idx in range(count))
    return records, img.data[off : off + size]


def suffix_for_device(name: str) -> str:
    prefix = "/dev/buses/qupac"
    if name == prefix:
        return "default"
    suffix = name[len(prefix) :].strip("/")
    suffix = re.sub(r"[^0-9A-Za-z_]+", "_", suffix)
    suffix = suffix.strip("_")
    return suffix or "default"


def unique_symbol(base: str, used: set[str]) -> str:
    symbol = base
    idx = 2
    while symbol in used:
        symbol = f"{base}_{idx}"
        idx += 1
    used.add(symbol)
    return symbol


def collect_arrays_and_devices(
    img: ElfImage, props_infos: Sequence[PropsInfo]
) -> Tuple[List[ArrayInfo], List[DeviceOut], List[str]]:
    arrays_by_key: Dict[Tuple[str, bytes, int], ArrayInfo] = {}
    arrays: List[ArrayInfo] = []
    devices_by_name: Dict[str, DeviceOut] = {}
    devices: List[DeviceOut] = []
    used_symbols: set[str] = set()
    warnings: List[str] = []

    for pi in props_infos:
        for dev in iter_string_devices(img, pi):
            if not dev.name.startswith("/dev/buses/qupac"):
                continue
            try:
                props = {prop.name: prop for prop in parse_props(img, pi, dev.prop_offset)}
            except ValueError as exc:
                warnings.append(f"skipping {dev.name} in region 0x{pi.addr:x}: {exc}")
                continue

            prop_symbols: Dict[str, Tuple[str, str]] = {}
            for prop_name, size_name, kind in QUP_PROP_ORDER:
                prop = props.get(prop_name)
                size_prop = props.get(size_name)
                if prop is None or size_prop is None:
                    continue
                if prop.type_id != 0x12 or size_prop.type_id != 0x12:
                    warnings.append(f"skipping non-struct property {dev.name}:{prop_name}")
                    continue
                target = read_struct_target(img, pi, prop.value)
                count = read_count_from_size_prop(img, pi, size_prop)
                if target is None or count is None:
                    warnings.append(f"could not resolve {dev.name}:{prop_name}")
                    continue
                try:
                    if kind == "se":
                        _stride, records, raw = decode_se_array(img, target.offset, count)
                    else:
                        records, raw = decode_gpii_array(img, target.offset, count)
                except ValueError as exc:
                    warnings.append(f"could not decode {dev.name}:{prop_name}: {exc}")
                    continue

                array = ArrayInfo(
                    prop_name=prop_name,
                    kind=kind,
                    count=count,
                    ptr=target.ptr,
                    offset=target.offset,
                    records=records,
                    raw_bytes=raw,
                )
                existing = arrays_by_key.get(array.key)
                if existing is None:
                    suffix = suffix_for_device(dev.name)
                    base = f"{PROP_SYMBOL_BASE[prop_name]}_{suffix}_recovered"
                    array.symbol = unique_symbol(base, used_symbols)
                    size_base = f"{SIZE_SYMBOL_BASE[prop_name]}_{suffix}_recovered"
                    array.size_symbol = unique_symbol(size_base, used_symbols)
                    arrays_by_key[array.key] = array
                    arrays.append(array)
                    existing = array
                prop_symbols[prop_name] = (existing.symbol, existing.size_symbol)

            if not prop_symbols:
                warnings.append(f"no QUPAC arrays recovered for {dev.name} in region 0x{pi.addr:x}")
                continue

            device_out = DeviceOut(dev.name, pi.addr, prop_symbols)
            previous = devices_by_name.get(dev.name)
            if previous is None:
                devices_by_name[dev.name] = device_out
                devices.append(device_out)
            elif previous.signature != device_out.signature:
                warnings.append(
                    f"device {dev.name} differs between regions 0x{previous.region_addr:x} "
                    f"and 0x{pi.addr:x}; keeping the first one"
                )

    return arrays, devices, warnings


def gpii_start_from_arrays(arrays: Sequence[ArrayInfo]) -> int:
    ids = [record[0] for array in arrays if array.kind == "gpii" for record in array.records]
    if not ids:
        return 33
    min_id = min(ids)
    if min_id <= 32:
        return 32
    return 33


def periph_name(raw: int, gpii_start: int, context: str) -> str:
    if 0 <= raw < 24:
        return f"QUPV3_{raw // 8}_SE{raw % 8}"
    if 24 <= raw < 32:
        return f"QUPV3_SSC_SE{raw - 24}"
    if raw == 32 and gpii_start == 33 and context == "se":
        return "QUPV3_SSC_SE8"

    if context == "gpii" and gpii_start == 32:
        return f"(QUPV3_PERIPHID){raw}"

    if gpii_start <= raw < gpii_start + 48:
        idx = raw - gpii_start
        return f"QUPV3_{idx // 16}_GPII{idx % 16}"
    if gpii_start + 48 <= raw < gpii_start + 64:
        return f"QUPV3_SSC_GPII{raw - (gpii_start + 48)}"
    return f"(QUPV3_PERIPHID){raw}"


def source_periph_comment(raw: int, gpii_start: int) -> str:
    if gpii_start != 32:
        return ""
    if 32 <= raw < 80:
        idx = raw - 32
        return f" /* source enum: QUPV3_{idx // 16}_GPII{idx % 16} */"
    if 80 <= raw < 96:
        return f" /* source enum: QUPV3_SSC_GPII{raw - 80} */"
    return ""


def enum_value(mapping: Dict[int, str], raw: int, cast_type: str) -> str:
    if raw in mapping:
        return mapping[raw]
    return f"({cast_type})0x{raw:x}"


def ac_value(raw: int) -> str:
    return AC_NAMES.get(raw, f"0x{raw:x}")


def c_bool(raw: int) -> str:
    return "TRUE" if raw else "FALSE"


def render_c(input_path: Path, props_infos: Sequence[PropsInfo], arrays: Sequence[ArrayInfo]) -> str:
    gpii_start = gpii_start_from_arrays(arrays)
    lines: List[str] = []
    lines.append("/*")
    lines.append(f" * Recovered from {input_path}.")
    if props_infos:
        lines.append(" *")
        lines.append(" * DALProps regions containing /dev/buses/qupac*:")
        for pi in props_infos:
            lines.append(f" *   - DALPROP_PropsInfo @ 0x{pi.addr:x}, file offset 0x{pi.offset:x}")
    lines.append(" *")
    lines.append(" * QUPv3_se_security_permissions_type is emitted as C initializers.")
    lines.append(" * The extractor decodes the binary layout as 4 uint32 fields,")
    lines.append(" * followed by three uint8 boolean fields.")
    if gpii_start == 32:
        lines.append(" *")
        lines.append(" * This binary uses an older QUPV3_PERIPHID layout without QUPV3_SSC_SE8;")
        lines.append(" * raw GPII IDs start at 32. GPII entries are emitted as raw casts so")
        lines.append(" * they do not shift when compiled with newer makena headers.")
    lines.append(" */")
    lines.append("")
    lines.append('#include "QupACCommonIds.h"')
    lines.append("")

    for array in arrays:
        if array.kind == "se":
            lines.append(f"const QUPv3_se_security_permissions_type {array.symbol}[] =")
            lines.append("{")
            lines.append(
                "  /*   PeriphID,      ProtocolID,               Mode,          "
                "NsOwner,        bAllowFifo, bLoad, bModExcl */"
            )
            for record in array.records:
                periph, protocol, mode, owner, allow_fifo, load, mod_excl = record
                lines.append(
                    "  { %-14s, %-25s, %-15s, %-14s, %-5s, %-5s, %-5s },"
                    % (
                        periph_name(periph, gpii_start, "se"),
                        enum_value(PROTOCOL_NAMES, protocol, "QUPv3_protocol_type"),
                        enum_value(MODE_NAMES, mode, "QUPv3_mode_type"),
                        ac_value(owner),
                        c_bool(allow_fifo),
                        c_bool(load),
                        c_bool(mod_excl),
                    )
                )
            lines.append("};")
        else:
            lines.append(f"const QUPv3_gpii_security_permissions_type {array.symbol}[] =")
            lines.append("{")
            lines.append("  /*   PeriphID,        uAC,            uGsiAC */")
            for record in array.records:
                periph, owner, gsi_owner = record
                comment = source_periph_comment(periph, gpii_start)
                lines.append(
                    "  { %-16s, %-14s, %-14s },%s"
                    % (
                        periph_name(periph, gpii_start, "gpii"),
                        ac_value(owner),
                        ac_value(gsi_owner),
                        comment,
                    )
                )
            lines.append("};")

        lines.append(f"const uint32 {array.size_symbol} =")
        lines.append(f"  sizeof({array.symbol}) / sizeof({array.symbol}[0]);")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_xml(input_path: Path, props_infos: Sequence[PropsInfo], devices: Sequence[DeviceOut]) -> str:
    lines: List[str] = []
    lines.append("<!--")
    lines.append(f"  Recovered from {input_path}.")
    if props_infos:
        lines.append("")
        lines.append("  DALProps regions containing /dev/buses/qupac*:")
        for pi in props_infos:
            lines.append(f"    - DALPROP_PropsInfo @ 0x{pi.addr:x}, file offset 0x{pi.offset:x}")
    lines.append("-->")
    lines.append("")
    lines.append('<driver name="NULL">')
    for device in devices:
        lines.append(f'  <device id="{device.name}">')
        for prop_name, size_name, _kind in QUP_PROP_ORDER:
            symbols = device.prop_symbols.get(prop_name)
            if symbols is None:
                continue
            array_symbol, size_symbol = symbols
            lines.append(f'    <props name="{prop_name}" type=DALPROP_ATTR_TYPE_STRUCT_PTR>')
            lines.append(f"      {array_symbol}")
            lines.append("    </props>")
            lines.append(f'    <props name="{size_name}" type=DALPROP_ATTR_TYPE_STRUCT_PTR>')
            lines.append(f"      {size_symbol}")
            lines.append("    </props>")
        lines.append("  </device>")
        lines.append("")
    if lines[-1] == "":
        lines.pop()
    lines.append("</driver>")
    return "\n".join(lines) + "\n"


def default_prefix(path: Path) -> Path:
    return Path.cwd() / f"{path.stem}_qupac_recovered"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract /dev/buses/qupac* QUP access-control data from a devcfg ELF/MBN."
    )
    parser.add_argument("devcfg_bin", type=Path, help="input devcfg ELF/MBN")
    parser.add_argument(
        "-o",
        "--out-prefix",
        type=Path,
        help="output prefix; writes <prefix>.c and <prefix>.xml",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    data = args.devcfg_bin.read_bytes()
    img = ElfImage(data, args.devcfg_bin)

    props_infos = find_props_infos(img)
    if not props_infos:
        print("error: no DALProps region with /dev/buses/qupac* was found", file=sys.stderr)
        return 2

    arrays, devices, warnings = collect_arrays_and_devices(img, props_infos)
    if not devices:
        print("error: found qupac device names, but no QUPAC arrays could be decoded", file=sys.stderr)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        return 3

    prefix = args.out_prefix or default_prefix(args.devcfg_bin)
    c_path = prefix.with_suffix(".c")
    xml_path = prefix.with_suffix(".xml")
    c_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.parent.mkdir(parents=True, exist_ok=True)

    c_path.write_text(render_c(args.devcfg_bin, props_infos, arrays), encoding="ascii")
    xml_path.write_text(render_xml(args.devcfg_bin, props_infos, devices), encoding="ascii")

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"wrote {c_path}")
    print(f"wrote {xml_path}")
    print(f"recovered {len(devices)} device(s), {len(arrays)} unique array(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
