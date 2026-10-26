"""Groups imported functions into things a program can do: network, writing files, starting processes...

An import doesn't mean the program calls it, so each capability keeps the imports behind it.
"""
from __future__ import annotations

from dataclasses import dataclass

from .loader import Binary

# kept small on purpose: the common C runtime, POSIX and Win32 names for each group
_TABLE: dict[str, set[str]] = {
    "network": {
        "socket", "connect", "send", "sendto", "recv", "recvfrom", "bind", "listen", "accept",
        "getaddrinfo", "gethostbyname", "inet_pton", "inet_addr", "WSAStartup", "WSASocket",
        "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest", "InternetReadFile",
        "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest", "URLDownloadToFile",
    },
    "file write": {
        "fopen", "fwrite", "fputs", "fprintf", "open", "write", "creat", "rename", "unlink", "remove",
        "CreateFile", "WriteFile", "DeleteFile", "MoveFile", "CopyFile",
    },
    "file read": {"fread", "read", "ReadFile", "FindFirstFile", "FindNextFile", "opendir", "readdir"},
    "process": {
        "fork", "execve", "execv", "execvp", "system", "popen", "kill", "ptrace",
        "CreateProcess", "ShellExecute", "ShellExecuteEx", "WinExec", "OpenProcess", "TerminateProcess",
    },
    "memory of other processes": {
        "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "process_vm_writev",
    },
    "registry": {"RegOpenKey", "RegOpenKeyEx", "RegCreateKey", "RegCreateKeyEx", "RegSetValueEx", "RegQueryValueEx", "RegDeleteKey"},
    "crypto": {
        "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash", "CryptHashData",
        "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt", "BCryptHash",
        "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_DigestInit_ex", "SHA256_Init", "MD5_Init",
    },
    "dynamic loading": {"LoadLibrary", "LoadLibraryEx", "GetProcAddress", "dlopen", "dlsym"},
    # stdio_common_vfscanf is how the Windows UCRT imports every scanf variant
    "user input": {"scanf", "__isoc99_scanf", "__isoc23_scanf","stdio_common_vfscanf", "fgets", "getchar", "getline", "ReadConsole"},
}

_LOOKUP = {name: group for group, names in _TABLE.items() for name in names}


def _group_of(name: str) -> str | None:
    if name in _LOOKUP:
        return _LOOKUP[name]
    # Win32 functions come in an ANSI and a wide version: CreateFileA, CreateFileW
    if name[-1:] in ("A", "W") and name[:-1] in _LOOKUP:
        return _LOOKUP[name[:-1]]
    # MinGW and the UCRT add prefixes to some C runtime names (_open, __stdio_common_vfprintf)
    stripped = name.lstrip("_")
    return _LOOKUP.get(stripped)


@dataclass
class Capability:
    name: str
    evidence: list[str]  # the imports that point to it
    # none of the evidence is called from main or what it calls, so it's probably the compiler's
    # startup code (MinGW imports LoadLibraryA for that); False when main isn't known
    not_from_main: bool = False


def find(binary: Binary, from_main: set[str] | None = None) -> list[Capability]:
    """`from_main` is the imports main reaches, when the code could be followed from it."""
    found: dict[str, set[str]] = {}
    for imp in binary.imports:
        group = _group_of(imp.name)
        if group:
            found.setdefault(group, set()).add(imp.name)
    return [
        Capability(name, sorted(evidence), not_from_main=from_main is not None and not evidence & from_main)
        for name, evidence in sorted(found.items())
    ]
