from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import sys

CREATE_SUSPENDED = 0x00000004
PAGE_EXECUTE_READWRITE = 0x40

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

PROCESS_WOW64_INFORMATION = 26


class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wintypes.BOOL, wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hex_bytes(value: str) -> bytes:
    return bytes.fromhex(value.replace(" ", ""))


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve_game_exe(base: Path, configured: str) -> Path:
    candidate = Path(configured)
    if not candidate.is_absolute():
        candidate = (base / candidate).resolve()
    if candidate.is_file():
        return candidate

    common = [
        Path(r"D:\Games\Farmers Dynasty\FarmersDynasty.exe"),
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Farmer's Dynasty\FarmersDynasty.exe"),
        Path(r"C:\Program Files (x86)\Steam\steamapps\common\Farmers Dynasty\FarmersDynasty.exe"),
    ]
    for path in common:
        if path.is_file():
            return path

    fail("FarmersDynasty.exe introuvable. Renseigne game_exe dans config.json.")


def discover_mods(mods_dir: Path) -> list[tuple[Path, dict]]:
    result = []
    if not mods_dir.exists():
        return result
    for manifest in sorted(mods_dir.glob("*/mod.json")):
        mod = load_json(manifest)
        if mod.get("enabled", True):
            result.append((manifest, mod))
    return result


def validate_mods(mods: list[tuple[Path, dict]], exe_hash: str) -> None:
    for manifest, mod in mods:
        supported = [x.lower() for x in mod.get("game", {}).get("exe_sha256", [])]
        if supported and exe_hash.lower() not in supported:
            fail(
                f"{mod.get('name', manifest.parent.name)} n'est pas compatible "
                "avec cette version de FarmersDynasty.exe."
            )


def create_suspended(exe: Path) -> PROCESS_INFORMATION:
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer(f'"{exe}"')
    ok = kernel32.CreateProcessW(
        str(exe), cmd, None, None, False, CREATE_SUSPENDED,
        None, str(exe.parent), ctypes.byref(si), ctypes.byref(pi)
    )
    if not ok:
        fail(f"CreateProcessW a échoué (erreur Windows {ctypes.get_last_error()}).")
    return pi


def get_image_base(process) -> int:
    # Farmer's Dynasty est un processus PE32. Depuis un Python 64 bits sous
    # Windows, ProcessWow64Information fournit l'adresse de son PEB 32 bits.
    peb32 = ctypes.c_void_p()
    status = ntdll.NtQueryInformationProcess(
        process,
        PROCESS_WOW64_INFORMATION,
        ctypes.byref(peb32),
        ctypes.sizeof(peb32),
        None,
    )
    if status != 0 or not peb32.value:
        fail("Impossible de récupérer le PEB 32 bits du jeu.")

    # Dans le PEB32, ImageBaseAddress est à l'offset +0x08.
    raw = read_memory(process, peb32.value + 0x08, 4)
    return int.from_bytes(raw, "little")


def read_memory(process, address: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process, ctypes.c_void_p(address), buf, size, ctypes.byref(read)
    ) or read.value != size:
        fail(f"Lecture mémoire impossible à 0x{address:08X}.")
    return bytes(buf)


def write_memory(process, address: int, payload: bytes) -> None:
    old_protect = wintypes.DWORD()
    if not kernel32.VirtualProtectEx(
        process, ctypes.c_void_p(address), len(payload),
        PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
    ):
        fail(f"VirtualProtectEx a échoué à 0x{address:08X}.")

    try:
        buf = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        written = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            process, ctypes.c_void_p(address), buf,
            len(payload), ctypes.byref(written)
        ) or written.value != len(payload):
            fail(f"Écriture mémoire impossible à 0x{address:08X}.")
        kernel32.FlushInstructionCache(
            process, ctypes.c_void_p(address), len(payload)
        )
    finally:
        restored = wintypes.DWORD()
        kernel32.VirtualProtectEx(
            process, ctypes.c_void_p(address), len(payload),
            old_protect.value, ctypes.byref(restored)
        )


def apply_mod(process, mod: dict, image_base: int) -> None:
    for patch in mod.get("patches", []):
        rva = int(patch["rva"], 0)
        address = image_base + rva
        original = hex_bytes(patch["original"])
        replacement = hex_bytes(patch["replace"])

        if len(original) != len(replacement):
            fail(f"Patch {patch.get('name', '')}: tailles original/replace différentes.")

        current = read_memory(process, address, len(original))
        if current != original:
            fail(
                f"Patch {patch.get('name', '')}: octets inattendus à "
                f"0x{address:08X}. Patch annulé."
            )

        write_memory(process, address, replacement)


def main() -> int:
    if sys.platform != "win32":
        print("Ce loader fonctionne uniquement sous Windows.")
        return 1

    base = Path(__file__).resolve().parent
    config = load_json(base / "config.json")
    exe = resolve_game_exe(base, config.get("game_exe", "FarmersDynasty.exe"))
    mods_dir = base / config.get("mods_directory", "Mods")
    mods = discover_mods(mods_dir)

    print(f"Jeu : {exe}")
    print(f"Mods activés : {len(mods)}")
    for _, mod in mods:
        print(f"  - {mod.get('name', mod.get('id', 'Mod'))}")

    exe_hash = sha256_file(exe)
    validate_mods(mods, exe_hash)

    pi = create_suspended(exe)
    patched = False

    try:
        image_base = get_image_base(pi.hProcess)
        print(f"Base mémoire du jeu : 0x{image_base:08X}")
        for _, mod in mods:
            apply_mod(pi.hProcess, mod, image_base)
        patched = True
    finally:
        if patched:
            kernel32.ResumeThread(pi.hThread)
        else:
            kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hThread)
        kernel32.CloseHandle(pi.hProcess)

    print("Mods appliqués. Farmer's Dynasty est lancé.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERREUR : {exc}")
        input("Appuie sur Entrée pour fermer...")
        raise SystemExit(1)
