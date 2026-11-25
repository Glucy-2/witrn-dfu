#!/usr/bin/env python3
"""Firmware updater for WITRN USB meters in bootloader ("DFU") mode.

Reimplements the protocol of the official Windows tool WITRNUP (WITRN_UP_V30, .NET 8).
On Linux the device is accessed through /dev/hidraw* with the standard library only; on
Windows and macOS (or with --backend hidapi) the `hidapi` package is used.
See README.md for the protocol description.
"""

import argparse
import os
import select
import struct
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

VID = 0x0716


@dataclass(frozen=True)
class Model:
    name: str
    pid: int
    guid: uuid.UUID     # identifies the firmware image's target model
    app_base: int       # application start address
    info_base: int      # factory info block (copyright text + obfuscated Struct10), 1024 B
    page_size: int
    page_count: int
    arm_vectors: bool   # image starts with a Cortex-M vector table linked at app_base

    @property
    def app_size(self) -> int:
        return self.page_size * self.page_count


# Device table from WITRNUP (Class5); addresses there are decimal literals.
# arm_vectors: published images were checked to start with a vector table for every model except
# CC1 (its images do not), CL01 (assumed, like the other 0x0800xxxx models; a wrong guess only
# makes the tool refuse an image) and W96D (unknown, shares CC1's layout, so not checked).
MODELS = (
    Model("A2", 0x5045, uuid.UUID("920ea417-1cad-4527-b7b8-0558c3466a12"), 0x08004000, 0x08003C00, 1024, 111, True),
    Model("A2L", 0x5050, uuid.UUID("18253dd5-b099-429f-bf30-29eb6fd44316"), 0x08004000, 0x08003C00, 1024, 109, True),
    Model("A2C", 0x5058, uuid.UUID("550f2c0a-0f6b-405e-be7f-2b398bd7a22e"), 0x08004000, 0x08003C00, 1024, 111, True),
    Model("U3", 0x5044, uuid.UUID("b793053a-236b-4f99-a6e1-5a48a08b86d1"), 0x08004000, 0x08003800, 2048, 500, True),
    Model("U3L", 0x5054, uuid.UUID("5b00bda5-4e5e-4aa5-86f4-e66a89b07302"), 0x08004000, 0x08003800, 2048, 500, True),
    Model("C4/5 Series", 0x5053, uuid.UUID("687b3def-3b2c-4d63-93b9-22b17b051a12"), 0x08004000, 0x08003800, 2048, 500, True),
    Model("C0 Series", 0x5055, uuid.UUID("ca445a7e-22e7-4669-a451-0aec67b74de8"), 0x08004000, 0x08003C00, 1024, 109, True),
    Model("CL01", 0x5057, uuid.UUID("6b2a3481-8ed4-4d68-827d-b5ce9b14a7fa"), 0x08004800, 0x08004000, 2048, 115, True),
    Model("CC1", 0x5100, uuid.UUID("af895554-2c74-4a63-b609-e5bc54011092"), 0x08002400, 0x08002000, 1024, 52, False),
    Model("K2", 0x5060, uuid.UUID("5a3f8522-366b-46cc-aacc-dbfbe2fee02a"), 0x08003800, 0x08003000, 2048, 447, True),
    Model("W96D", 0x5103, uuid.UUID("a3dc1bc1-8fd1-4374-85b9-fc9a2650fdda"), 0x08002400, 0x08002000, 1024, 50, False),
)

BOOT_INFO = 0x08001400      # bootloader build strings, 256 B, same on every model (Class4.method_52)
W96D_SERIAL = 0x08010800    # W96D keeps its serial as a u32 here instead of in the info block
VERSION_OFFSET = 2048       # firmware version byte (BCD-ish: 0x60 = 6.0) at app_base + 2048
MARK_OFFSET = 0xC00         # bootloader starts the app only if the word at app_base + 0xC00 != 0xFFFFFFFF
MARK = 0xFFFFFFFE

HEADER = struct.Struct("<7sHBB9s16sIII")  # Struct8, 48 bytes
MAGIC = b"gzutapp"

CMD_NAK, CMD_ACK, CMD_PING, CMD_LOCK, CMD_UNLOCK = 1, 2, 3, 4, 5
CMD_ERASE, CMD_WRITE, CMD_READ, CMD_BULK_READ = 8, 9, 10, 11
CMD_LOG, CMD_LOG_CLEAR, CMD_REBOOT = 21, 22, 23

# Class3.byte_0: firmware file de-obfuscation table (byte substitution)
FILE_SUB = bytes([
    26, 182, 183, 241, 123, 140, 213, 60, 124, 144, 210, 244, 53, 242, 27, 233, 219, 18, 119, 91,
    61, 127, 63, 189, 45, 71, 42, 80, 220, 195, 255, 87, 130, 131, 96, 252, 155, 78, 136, 208,
    0, 95, 46, 89, 43, 249, 198, 56, 240, 200, 142, 128, 68, 253, 115, 126, 11, 41, 25, 175,
    216, 150, 113, 179, 98, 230, 229, 17, 145, 156, 70, 21, 196, 194, 165, 82, 185, 102, 172, 178,
    34, 83, 238, 84, 170, 180, 116, 207, 176, 108, 114, 167, 146, 90, 86, 231, 133, 236, 193, 159,
    206, 110, 174, 59, 120, 143, 93, 75, 226, 100, 12, 76, 19, 99, 192, 65, 79, 186, 228, 16,
    4, 166, 62, 49, 225, 184, 72, 103, 5, 211, 152, 105, 191, 54, 101, 190, 6, 81, 92, 199,
    139, 9, 55, 197, 169, 168, 112, 212, 135, 29, 218, 13, 243, 118, 48, 173, 23, 148, 224, 177,
    20, 237, 14, 8, 66, 154, 51, 181, 85, 217, 69, 57, 227, 125, 77, 1, 203, 39, 239, 37,
    106, 58, 122, 121, 109, 22, 64, 97, 164, 2, 171, 134, 15, 52, 111, 235, 107, 247, 40, 222,
    163, 204, 117, 44, 202, 94, 129, 10, 250, 104, 248, 7, 3, 36, 205, 31, 162, 47, 50, 67,
    157, 245, 215, 188, 158, 187, 73, 74, 214, 138, 132, 161, 33, 223, 151, 254, 32, 209, 30, 147,
    28, 141, 251, 38, 24, 149, 246, 201, 221, 234, 153, 35, 232, 160, 88, 137,
])

# Class3.byte_1: de-obfuscation table for the info block (Struct10)
INFO_SUB = bytes([
    40, 175, 189, 212, 120, 128, 136, 211, 163, 141, 207, 56, 110, 151, 162, 192, 119, 67, 17, 112,
    160, 71, 185, 156, 244, 58, 0, 14, 240, 149, 238, 215, 236, 232, 80, 251, 213, 179, 243, 177,
    198, 57, 26, 44, 203, 24, 42, 217, 154, 123, 218, 166, 193, 12, 133, 142, 47, 171, 181, 103,
    7, 20, 122, 22, 186, 115, 164, 219, 52, 170, 70, 25, 126, 226, 227, 107, 111, 174, 37, 116,
    27, 137, 75, 81, 83, 168, 94, 31, 254, 43, 93, 19, 138, 106, 205, 41, 34, 187, 64, 113,
    109, 134, 77, 127, 209, 131, 180, 196, 89, 184, 101, 194, 146, 62, 90, 54, 86, 202, 153, 18,
    104, 183, 182, 4, 8, 173, 55, 21, 51, 206, 32, 33, 230, 96, 191, 148, 38, 255, 229, 140,
    5, 241, 50, 105, 9, 68, 92, 239, 157, 245, 61, 234, 130, 250, 165, 36, 69, 220, 224, 99,
    253, 231, 216, 200, 188, 74, 121, 91, 145, 144, 84, 190, 78, 155, 102, 59, 88, 159, 79, 63,
    85, 167, 1, 2, 125, 76, 117, 225, 223, 23, 135, 132, 114, 98, 73, 29, 72, 143, 46, 139,
    49, 247, 204, 176, 201, 214, 100, 87, 39, 237, 10, 129, 147, 6, 228, 222, 60, 169, 150, 16,
    28, 248, 199, 233, 158, 124, 108, 172, 118, 66, 65, 95, 252, 15, 249, 195, 97, 161, 82, 178,
    48, 3, 13, 152, 11, 221, 246, 197, 210, 45, 208, 242, 35, 53, 235, 30,
])


class DfuError(Exception):
    pass


def version_str(v: int) -> str:
    return f"{v >> 4}.{v & 0xF}"


# ---------------------------------------------------------------- firmware file

class Firmware:
    def __init__(self, path: Path):
        data = bytes(FILE_SUB[b] for b in path.read_bytes())
        if len(data) < HEADER.size + VERSION_OFFSET + 1:
            raise DfuError(f"{path}: file too small")
        magic, self.year, self.month, self.day, _, guid, size, xor, add = HEADER.unpack_from(data)
        self.payload = data[HEADER.size:]
        self.file_size = len(data)
        # Same checks as Class4.method_50
        if magic != MAGIC or self.year >= 2050 or self.month >= 13 or self.day >= 32:
            raise DfuError(f"{path}: not a WITRN firmware image")
        guid = uuid.UUID(bytes_le=guid)
        model = next((m for m in MODELS if m.guid == guid), None)
        if model is None:
            raise DfuError(f"{path}: unknown target model (GUID {guid})")
        self.model = model
        if size != len(self.payload):
            raise DfuError(f"{path}: size mismatch (header {size}, payload {len(self.payload)})")
        x = 0
        for b in self.payload:
            x ^= b
        if x != xor or sum(self.payload) & 0xFFFFFFFF != add:
            raise DfuError(f"{path}: checksum mismatch")
        if len(self.payload) > model.app_size:
            raise DfuError(f"{path}: payload larger than the {model.name} application flash")
        if model.arm_vectors:
            sp, reset = struct.unpack_from("<II", self.payload)
            if sp >> 18 != 0x800 or not model.app_base <= (reset & ~1) < model.app_base + len(self.payload):
                raise DfuError(f"{path}: vector table (SP 0x{sp:08X}, reset 0x{reset:08X}) "
                               f"does not match load address 0x{model.app_base:08X}")
        self.version = self.payload[VERSION_OFFSET]  # Class4.method_51

    @property
    def erase_pages(self) -> int:
        # The official tool erases pages until it has covered the whole file *including* the
        # 48-byte header (Class4.method_54) and loops forever when that exceeds the flash
        # (happens with CC1 3.4 images); clip to the application area instead.
        m = self.model
        return min(-(-self.file_size // m.page_size), m.page_count)

    def describe(self) -> str:
        return (f"{self.model.name} firmware v{version_str(self.version)}, "
                f"built {self.year:04}-{self.month:02}-{self.day:02}, {len(self.payload)} bytes")


# ---------------------------------------------------------------- transport

class HidrawTransport:
    """Linux /dev/hidraw*, standard library only."""

    @staticmethod
    def enumerate() -> list[tuple[str, int]]:
        found = []
        root = Path("/sys/class/hidraw")
        for node in sorted(root.iterdir()) if root.exists() else ():
            for line in (node / "device" / "uevent").read_text().splitlines():
                if line.startswith("HID_ID="):
                    _, vid, pid = line[len("HID_ID="):].split(":")
                    if int(vid, 16) == VID:
                        found.append((f"/dev/{node.name}", int(pid, 16)))
        return found

    def __init__(self, path: str):
        try:
            self.fd = os.open(path, os.O_RDWR)
        except PermissionError:
            raise DfuError(f"no permission to open {path}; install 70-witrn.rules (see README)") from None

    def write(self, report: bytes):
        os.write(self.fd, report)

    def read(self, timeout: float) -> bytes | None:
        if not select.select([self.fd], [], [], max(timeout, 0))[0]:
            return None
        return os.read(self.fd, 64)

    def close(self):
        os.close(self.fd)


LINUX = sys.platform.startswith("linux")


class HidapiTransport:
    """PyPI package `hidapi`: native HID API on Windows/macOS, its hidraw module on Linux."""

    module = "hidraw" if LINUX else "hid"

    @classmethod
    def _hid(cls):
        try:
            return __import__(cls.module)
        except ImportError:
            raise DfuError("this backend needs the `hidapi` package (pip install hidapi)") from None

    @classmethod
    def enumerate(cls) -> list[tuple[str, int]]:
        return [(d["path"].decode(), d["product_id"]) for d in cls._hid().enumerate(VID, 0)]

    def __init__(self, path: str):
        self.dev = self._hid().device()
        try:
            self.dev.open_path(path.encode())
        except OSError as e:
            hint = "; check permissions, install 70-witrn.rules (see README)" if LINUX else ""
            raise DfuError(f"cannot open {path}: {e}{hint}") from None

    def write(self, report: bytes):
        if self.dev.write(report) < 0:
            raise DfuError("HID write failed")

    def read(self, timeout: float) -> bytes | None:
        data = self.dev.read(64, max(1, int(timeout * 1000)))  # 0 would block forever
        return bytes(data) if data else None

    def close(self):
        self.dev.close()


class HidapiLibusbTransport(HidapiTransport):
    """Linux only: the hidapi package's default `hid` module, which talks to the USB device
    through libusb (detaching usbhid while open) instead of /dev/hidraw."""

    module = "hid"


BACKENDS = {"hidraw": HidrawTransport, "hidapi": HidapiTransport}
if LINUX:
    BACKENDS["hidapi-libusb"] = HidapiLibusbTransport
DEFAULT_BACKEND = "hidraw" if LINUX else "hidapi"


def find_devices(backend) -> list[tuple[str, Model]]:
    by_pid = {m.pid: m for m in MODELS}
    return [(path, by_pid[pid]) for path, pid in backend.enumerate() if pid in by_pid]


def select_device(backend, path: str | None, model: Model | None) -> tuple[str, Model]:
    devices = find_devices(backend)
    if path:
        match = [d for d in devices if d[0] == path]
        if not match:
            raise DfuError(f"{path} is not a supported WITRN device (see `witrn-dfu devices`)")
        devices = match
    if model:
        others = [d for d in devices if d[1] != model]
        devices = [d for d in devices if d[1] == model]
        if not devices:
            hint = f"; connected: {', '.join(f'{p} ({m.name})' for p, m in others)}" if others else ""
            raise DfuError(f"no {model.name} (0716:{model.pid:04x}) connected{hint}")
    if not devices:
        raise DfuError("no WITRN device found; enter DFU mode (hold the DFU key while plugging in)")
    if len(devices) > 1:
        raise DfuError("several devices found, pick one with --device: "
                       + ", ".join(f"{p} ({m.name})" for p, m in devices))
    return devices[0]


def _sum8(data) -> int:
    return sum(data) & 0xFF


def build_packet(cmd: int, data: bytes = b"", want_reply: bool = True) -> bytes:
    if len(data) > 52:
        raise ValueError("payload > 52 bytes")
    t = int(time.monotonic() * 1000) & 0xFFFFFFFF
    pkt = bytearray(64)
    pkt[0], pkt[1] = 0xFF, 0x55
    pkt[2] = (t // 1000) & 0xFF
    pkt[3] = (t % 1000) & 0xFF
    pkt[4] = ((t // 30) & 0x7F) | (0x80 if want_reply else 0)
    pkt[5] = (t // 100) & 0xFF
    pkt[6] = t % 100
    pkt[7] = (t // 80) & 0xFF
    pkt[8] = cmd
    pkt[9] = len(data)
    pkt[10:10 + len(data)] = data
    pkt[62] = _sum8(pkt[8:62])
    pkt[63] = _sum8(pkt[0:62])
    return bytes(pkt)


def packet_valid(pkt: bytes) -> bool:
    return (len(pkt) == 64 and pkt[0] == 0xFF and pkt[1] == 0x55
            and pkt[62] == _sum8(pkt[8:62]) and pkt[63] == _sum8(pkt[0:62]))


class Device:
    def __init__(self, backend, path: str, model: Model, verbose: bool = False):
        self.path = path
        self.model = model
        self.verbose = verbose
        self.io = backend(path)
        self.log_index = 0

    def close(self):
        self.io.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _drain(self):
        while self.io.read(0) is not None:
            pass

    def _send(self, cmd: int, data: bytes = b"", want_reply: bool = True):
        pkt = build_packet(cmd, data, want_reply)
        if self.verbose:
            print(f">> {pkt.hex()}", file=sys.stderr)
        self.io.write(b"\x00" + pkt)  # report ID 0: the report descriptor has none

    def _recv(self, cmds, timeout: float = 1.0) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            pkt = self.io.read(left) if left > 0 else None
            if pkt is None:
                raise DfuError(f"timeout waiting for reply {cmds}")
            if self.verbose:
                print(f"<< {pkt.hex()}", file=sys.stderr)
            if packet_valid(pkt) and pkt[8] in cmds:
                return pkt

    def command(self, cmd: int, data: bytes = b"", timeout: float = 1.0):
        """Request answered by ACK/NAK (Class4.method_28)."""
        self._drain()
        self._send(cmd, data)
        if self._recv((CMD_ACK, CMD_NAK), timeout)[8] != CMD_ACK:
            raise DfuError(f"command {cmd} rejected (NAK)")

    def ping(self):
        try:
            self.command(CMD_PING)
        except DfuError:
            raise DfuError(f"{self.model.name} at {self.path} does not answer; is it in DFU mode?") from None

    def unlock(self):
        self.command(CMD_UNLOCK)

    def lock(self):
        self.command(CMD_LOCK)

    def reboot(self):
        self.command(CMD_REBOOT)

    def erase_page(self, addr: int):
        self._send(CMD_ERASE, struct.pack("<I", addr), want_reply=False)

    def write(self, addr: int, data: bytes):
        for off in range(0, len(data), 40):
            chunk = data[off:off + 40]
            self._send(CMD_WRITE, struct.pack("<IB", addr + off, len(chunk)) + chunk, want_reply=False)

    def read_small(self, addr: int, n: int) -> bytes:
        """cmd 10, up to 52 bytes (Class4.method_39)."""
        self._drain()
        self._send(CMD_READ, struct.pack("<IB", addr, n))
        return self._recv((CMD_READ,))[10:10 + n]

    def read(self, addr: int, n: int, chunk: int = 1024) -> bytes:
        """cmd 11, streamed back 40 bytes per packet (Class4.method_43/41)."""
        out = bytearray()
        while len(out) < n:
            size = min(chunk, n - len(out))
            self._drain()
            self._send(CMD_BULK_READ, struct.pack("<IH", addr + len(out), size))
            got = 0
            while got < size:
                pkt = self._recv((CMD_BULK_READ,))
                take = min(40, size - got)
                out += pkt[10:10 + take]
                got += take
        return bytes(out)

    def log(self, text: str):
        """Append a line to the bootloader's upgrade log (Class4.method_48)."""
        raw = text.encode("ascii")
        data = bytearray(52)
        struct.pack_into("<HHB", data, 0, 1, self.log_index * 8, len(raw))
        data[5:5 + len(raw)] = raw
        self.command(CMD_LOG, bytes(data))
        self.log_index += 1

    def log_clear(self):
        self.log_index = 0
        self.command(CMD_LOG_CLEAR)


# ---------------------------------------------------------------- high level

def progress(label: str, done: int, total: int):
    pct = done * 100 // total
    print(f"\r{label}: {pct:3d}% ({done}/{total})", end="" if done < total else "\n", flush=True)


def read_info(dev: Device) -> dict:
    m = dev.model
    area = dev.read(m.info_base, 1024)  # Struct12: 202 B copyright text + Struct10 (Class4.method_58)
    info = bytes(INFO_SUB[b] for b in area[202:202 + 822])
    result = {"model": m.name}
    if m.name == "W96D":
        result["serial"] = str(struct.unpack("<I", dev.read_small(W96D_SERIAL, 4))[0])
    else:
        result["serial"] = info[48:54][::-1].decode("latin-1")
        year, month, day = struct.unpack_from("<III", info, 36)
        result["manufactured"] = f"{year:04}-{month:02}-{day:02}"
    # Variant names as shown by the official tool (Class11.method_12)
    if m.name == "C4/5 Series":
        hw = struct.unpack_from("<I", info, 224 - 202)[0]
        name = "C4" if hw < 3 else "C5"
        result["model"] = name + ("L" if info[236 - 202:238 - 202] != b"C4" else "")
    elif m.name == "U3L" and info[224 - 202] == 1:
        result["model"] = "U3LP"
    boot = dev.read(BOOT_INFO, 256)
    # date, time and name, NUL-terminated; code follows (Class4.method_52 also stops after three)
    result["bootloader"] = " ".join(s.decode("utf-8", "replace") for s in boot.split(b"\0")[:3])
    v = dev.read_small(m.app_base + VERSION_OFFSET, 1)[0]
    result["app_version"] = version_str(v) if v != 0xFF else "none"
    return result


def print_info(info: dict):
    for k, v in info.items():
        print(f"{k:13}{v}")


def cmd_models(args):
    print(f"{'model':12} {'usb id':10} {'app base':10} {'flash':>8}  {'guid'}")
    for m in MODELS:
        print(f"{m.name:12} 0716:{m.pid:04x}  0x{m.app_base:08X} {m.app_size // 1024:6}K  {m.guid}")


def cmd_check(args):
    print(Firmware(Path(args.firmware)).describe() + ", checksums OK")


def cmd_devices(args):
    devices = find_devices(BACKENDS[args.backend])
    if not devices:
        print("no WITRN device found")
    for path, m in devices:
        print(f"{m.name:12} 0716:{m.pid:04x}  {path}")


def cmd_info(args):
    backend = BACKENDS[args.backend]
    path, model = select_device(backend, args.device, None)
    with Device(backend, path, model, args.verbose) as dev:
        dev.ping()
        print_info(read_info(dev))


def cmd_flash(args):
    fw = Firmware(Path(args.firmware))
    m = fw.model
    print("image: " + fw.describe())
    backend = BACKENDS[args.backend]
    path, _ = select_device(backend, args.device, m)
    with Device(backend, path, m, args.verbose) as dev:
        dev.ping()
        print_info(read_info(dev))

        dev.log_clear()
        dev.log("earsing...")  # sic, same text as the official tool
        dev.unlock()
        for i in range(fw.erase_pages):
            dev.erase_page(m.app_base + i * m.page_size)
            progress("erase ", i + 1, fw.erase_pages)
        dev.lock()
        dev.log("ok")

        dev.log("install app...")
        dev.unlock()
        total = len(fw.payload)
        for off in range(0, total, 1024):
            dev.write(m.app_base + off, fw.payload[off:off + 1024])
            progress("write ", min(off + 1024, total), total)
        dev.lock()
        dev.log("ok")

        dev.log("verify app...")
        for off in range(0, total, 1024):
            want = fw.payload[off:off + 1024]
            got = dev.read(m.app_base + off, len(want))
            if got != want:
                bad = next(i for i in range(len(want)) if got[i] != want[i])
                raise DfuError(f"verify failed at 0x{m.app_base + off + bad:08X}")
            progress("verify", min(off + 1024, total), total)
        dev.log("ok")

        mark_addr = m.app_base + MARK_OFFSET
        dev.unlock()
        try:
            dev.write(mark_addr, struct.pack("<I", MARK))
            if dev.read_small(mark_addr, 4) != struct.pack("<I", MARK):
                raise DfuError("failed to set the installed marker")
        finally:
            dev.lock()

        dev.reboot()
        print("done; unplug and replug the device to start the new firmware")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-v", "--verbose", action="store_true", help="dump raw HID packets")
    ap.add_argument("-d", "--device", help="device path (see `devices`) when several devices are connected")
    ap.add_argument("-b", "--backend", choices=BACKENDS, default=DEFAULT_BACKEND,
                    help=f"HID access method (default: {DEFAULT_BACKEND})")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("models", help="list supported models").set_defaults(func=cmd_models)
    p = sub.add_parser("check", help="validate a firmware file and show its target model (offline)")
    p.add_argument("firmware")
    p.set_defaults(func=cmd_check)
    sub.add_parser("devices", help="list connected WITRN devices").set_defaults(func=cmd_devices)
    sub.add_parser("info", help="read device info (read-only)").set_defaults(func=cmd_info)
    p = sub.add_parser("flash", help="erase, write, verify and reboot")
    p.add_argument("firmware")
    p.set_defaults(func=cmd_flash)
    args = ap.parse_args()
    try:
        args.func(args)
    except (DfuError, OSError) as e:  # OSError: device unplugged or USB error mid-transfer
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
