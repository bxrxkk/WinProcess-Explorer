# Win32 Process Memory Analyzer

A lightweight&open-sourced, read-only diagnostic tool for inspecting the virtual memory layout of running Windows processes. Built directly on the Win32 API (no external dependencies) to enumerate committed memory regions, classify their protection attributes, and surface indicators commonly associated with code injection or unpacking activity.

## What it does

- Enumerates running processes via `CreateToolhelp32Snapshot`
- Opens a target process with minimal, read-only access rights (`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`) — no write or injection capability
- Walks the full virtual address space with `VirtualQueryEx`, since ASLR means module, heap, and stack addresses vary per run and cannot be assumed
- Classifies each committed region by state, type (private/image/mapped), and protection (readable/writable/executable)
- Flags **RWX regions** (writable + executable) as a heuristic for potential shellcode staging or self-modifying code
- Performs an optional bounded read (32 bytes) from the first readable region as a safe proof-of-concept for memory access
- Generates a timestamped plaintext report of the full memory map and summary statistics

## Why

Memory region enumeration is a foundational technique in both defensive tooling (EDR, memory forensics) and offensive security research (process inspection, cheat/debugger development). This project implements that primitive from scratch in C++ using raw Win32 calls, as a way of building low-level Windows internals knowledge rather than relying on higher-level frameworks.

## Design notes

- No write, allocation, or thread-injection primitives are implemented — the tool only reads process metadata and memory
- Access is scoped to the minimum privilege needed for inspection
- Errors from every Win32 call are surfaced via `FormatMessageW`, rather than silently failing

## Usage

Requires Windows + a process ID you have permission to inspect. Some processes will require running elevated due to Windows access control on protected processes.

## Disclaimer

Built for educational and legitimate diagnostic purposes (security research, debugging, systems programming). You are responsible for ensuring you have authorization to inspect any process you target with this tool.
