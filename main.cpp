#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>

struct ProcessInfo {
    DWORD pid{};
    std::wstring name;
};

struct ProcessMemoryRegion {
    uintptr_t baseAddress{};
    uintptr_t endAddress{};
    SIZE_T size{};
    DWORD state{};
    DWORD protect{};
    DWORD type{};
    bool readable{};
    bool writable{};
    bool executable{};
};

struct MemorySummary {
    uint64_t totalCommittedBytes{};
    size_t regionCount{};
    size_t readableCount{};
    size_t writableCount{};
    size_t executableCount{};
    size_t rwxCount{};
};

std::wstring GetLastErrorMessage(DWORD errorCode) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD langId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);

    DWORD size = FormatMessageW(
        flags,
        nullptr,
        errorCode,
        langId,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr
    );

    if (size == 0 || buffer == nullptr) {
        std::wstringstream fallback;
        fallback << L"Unknown error (" << errorCode << L")";
        return fallback.str();
    }

    std::wstring message(buffer, size);
    LocalFree(buffer);

    while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) {
        message.pop_back();
    }
    return message;
}

std::vector<ProcessInfo> EnumerateProcesses() {
    std::vector<ProcessInfo> processes;

    // CreateToolhelp32Snapshot gives a point-in-time snapshot of running processes.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"[!] CreateToolhelp32Snapshot failed: "
                   << GetLastErrorMessage(GetLastError()) << L"\n";
        return processes;
    }

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Process32First/Next walk the process list stored in the snapshot handle.
    if (!Process32FirstW(snapshot, &pe32)) {
        std::wcerr << L"[!] Process32FirstW failed: "
                   << GetLastErrorMessage(GetLastError()) << L"\n";
        CloseHandle(snapshot);
        return processes;
    }

    do {
        processes.push_back(ProcessInfo{pe32.th32ProcessID, pe32.szExeFile});
    } while (Process32NextW(snapshot, &pe32));

    DWORD walkError = GetLastError();
    if (walkError != ERROR_NO_MORE_FILES) {
        std::wcerr << L"[!] Process32NextW terminated unexpectedly: "
                   << GetLastErrorMessage(walkError) << L"\n";
    }

    CloseHandle(snapshot);
    return processes;
}

void PrintProcesses(const std::vector<ProcessInfo>& processes) {
    std::wcout << L"=== Running Processes ===\n";
    for (const auto& p : processes) {
        std::wcout << L"[PID: " << p.pid << L"] " << p.name << L"\n";
    }
    std::wcout << L"\n";
}

std::optional<DWORD> PromptForPid(const std::vector<ProcessInfo>& processes) {
    std::wcout << L"Enter target PID: ";
    unsigned long long rawPid = 0;

    if (!(std::wcin >> rawPid)) {
        std::wcerr << L"[!] Invalid input. Please enter a numeric PID.\n";
        return std::nullopt;
    }

    if (rawPid == 0 || rawPid > (std::numeric_limits<DWORD>::max)()) {
        std::wcerr << L"[!] PID out of valid range.\n";
        return std::nullopt;
    }

    DWORD pid = static_cast<DWORD>(rawPid);
    bool exists = false;
    for (const auto& p : processes) {
        if (p.pid == pid) {
            exists = true;
            break;
        }
    }

    if (!exists) {
        std::wcerr << L"[!] PID not found in current process snapshot.\n";
        return std::nullopt;
    }

    return pid;
}

std::wstring StateToString(DWORD state) {
    switch (state) {
    case MEM_COMMIT:
        return L"MEM_COMMIT";
    case MEM_RESERVE:
        return L"MEM_RESERVE";
    case MEM_FREE:
        return L"MEM_FREE";
    default:
        return L"UNKNOWN_STATE";
    }
}

std::wstring TypeToString(DWORD type) {
    switch (type) {
    case MEM_PRIVATE:
        return L"MEM_PRIVATE";
    case MEM_IMAGE:
        return L"MEM_IMAGE";
    case MEM_MAPPED:
        return L"MEM_MAPPED";
    default:
        return L"UNKNOWN_TYPE";
    }
}

std::wstring ProtectionToString(DWORD protect) {
    if (protect == 0) {
        return L"NONE";
    }
    if (protect & PAGE_GUARD) {
        return L"GUARD";
    }
    if (protect & PAGE_NOACCESS) {
        return L"NOACCESS";
    }

    DWORD base = protect & 0xFF;
    std::wstring text;
    switch (base) {
    case PAGE_READONLY:
        text = L"READONLY";
        break;
    case PAGE_READWRITE:
        text = L"READWRITE";
        break;
    case PAGE_WRITECOPY:
        text = L"WRITECOPY";
        break;
    case PAGE_EXECUTE:
        text = L"EXECUTE";
        break;
    case PAGE_EXECUTE_READ:
        text = L"EXECUTE_READ";
        break;
    case PAGE_EXECUTE_READWRITE:
        text = L"EXECUTE_READWRITE";
        break;
    case PAGE_EXECUTE_WRITECOPY:
        text = L"EXECUTE_WRITECOPY";
        break;
    default:
        text = L"UNKNOWN_PROTECT";
        break;
    }

    if (protect & PAGE_GUARD) {
        text += L" | GUARD";
    }
    if (protect & PAGE_NOCACHE) {
        text += L" | NOCACHE";
    }
    if (protect & PAGE_WRITECOMBINE) {
        text += L" | WRITECOMBINE";
    }
    return text;
}

bool IsReadable(DWORD protect) {
    if (protect & (PAGE_NOACCESS | PAGE_GUARD)) {
        return false;
    }
    DWORD base = protect & 0xFF;
    return base == PAGE_READONLY ||
           base == PAGE_READWRITE ||
           base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

bool IsWritable(DWORD protect) {
    if (protect & (PAGE_NOACCESS | PAGE_GUARD)) {
        return false;
    }
    DWORD base = protect & 0xFF;
    return base == PAGE_READWRITE ||
           base == PAGE_WRITECOPY ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

bool IsExecutable(DWORD protect) {
    if (protect & (PAGE_NOACCESS | PAGE_GUARD)) {
        return false;
    }
    DWORD base = protect & 0xFF;
    return base == PAGE_EXECUTE ||
           base == PAGE_EXECUTE_READ ||
           base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

HANDLE OpenTargetProcess(DWORD pid) {
    // Read-only rights: query metadata and read process memory (no write/injection rights).
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (processHandle == nullptr) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) {
            std::wcerr << L"[!] Access denied when opening PID " << pid
                       << L". Try running elevated if needed.\n";
        } else {
            std::wcerr << L"[!] OpenProcess failed for PID " << pid << L": "
                       << GetLastErrorMessage(err) << L"\n";
        }
    }
    return processHandle;
}

std::vector<ProcessMemoryRegion> ScanCommittedMemoryRegions(HANDLE processHandle, MemorySummary& summary) {
    std::vector<ProcessMemoryRegion> committedRegions;

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    uintptr_t current = reinterpret_cast<uintptr_t>(systemInfo.lpMinimumApplicationAddress);
    const uintptr_t maxAddress = reinterpret_cast<uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    while (current < maxAddress) {
        MEMORY_BASIC_INFORMATION mbi{};
        // VirtualQueryEx describes the region that contains "current" in the target process.
        SIZE_T queried = VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(current), &mbi, sizeof(mbi));
        if (queried == 0) {
            DWORD err = GetLastError();
            if (err != ERROR_INVALID_PARAMETER) {
                std::wcerr << L"[!] VirtualQueryEx failed at address 0x"
                           << std::hex << current << std::dec << L": "
                           << GetLastErrorMessage(err) << L"\n";
            }
            break;
        }

        const uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uintptr_t next = regionBase + mbi.RegionSize;

        // ASLR means module/heap/stack base addresses vary between runs and processes.
        // So we cannot assume fixed addresses; we must walk the live virtual map each time.
        // We only include committed pages in the main output (requested behavior).
        if (mbi.State == MEM_COMMIT) {
            ProcessMemoryRegion regionEntry{};
            regionEntry.baseAddress = regionBase;
            regionEntry.endAddress = next;
            regionEntry.size = mbi.RegionSize;
            regionEntry.state = mbi.State;
            regionEntry.protect = mbi.Protect;
            regionEntry.type = mbi.Type;
            regionEntry.readable = IsReadable(mbi.Protect);
            regionEntry.writable = IsWritable(mbi.Protect);
            regionEntry.executable = IsExecutable(mbi.Protect);
            committedRegions.push_back(regionEntry);

            summary.totalCommittedBytes += static_cast<uint64_t>(mbi.RegionSize);
            summary.regionCount++;
            if (regionEntry.readable) {
                summary.readableCount++;
            }
            if (regionEntry.writable) {
                summary.writableCount++;
            }
            if (regionEntry.executable) {
                summary.executableCount++;
            }
            if (regionEntry.writable && regionEntry.executable) {
                summary.rwxCount++;
            }
        }

        // Defensive progress guard: avoid infinite loops if region size is malformed.
        if (next <= current) {
            break;
        }
        current = next;
    }

    return committedRegions;
}

void PrintRegionLine(std::wostream& out, const ProcessMemoryRegion& r) {
    constexpr double bytesToKb = 1024.0;
    out << L"0x" << std::hex << std::setw(sizeof(void*) * 2) << std::setfill(L'0') << r.baseAddress
        << L" - 0x" << std::setw(sizeof(void*) * 2) << r.endAddress
        << std::dec << std::setfill(L' ')
        << L" | " << static_cast<uint64_t>(r.size / bytesToKb) << L" KB"
        << L" | " << TypeToString(r.type)
        << L" | " << ProtectionToString(r.protect)
        << L" | X:" << (r.executable ? L"Y" : L"N")
        << L" W:" << (r.writable ? L"Y" : L"N")
        << L"\n";
}

void PrintMemoryReport(std::wostream& out, const std::vector<ProcessMemoryRegion>& regions, const MemorySummary& summary) {
    out << L"\n--- Memory Regions (COMMITTED ONLY) ---\n";
    for (const auto& r : regions) {
        PrintRegionLine(out, r);
    }

    out << L"\n--- Summary ---\n";
    out << L"Total committed memory: " << (summary.totalCommittedBytes / 1024ULL) << L" KB\n";
    out << L"Committed regions: " << summary.regionCount << L"\n";
    out << L"Readable regions: " << summary.readableCount << L"\n";
    out << L"Writable regions: " << summary.writableCount << L"\n";
    out << L"Executable regions: " << summary.executableCount << L"\n";
    out << L"RWX regions (potential risk): " << summary.rwxCount << L"\n";
}

void TryReadSmallMemoryChunk(std::wostream& out, HANDLE processHandle, const std::vector<ProcessMemoryRegion>& regions) {
    // Optional safe demo: attempt to read 32 bytes from the first readable committed region.
    for (const auto& region : regions) {
        if (!region.readable) {
            continue;
        }

        std::vector<std::uint8_t> buffer(32, 0);
        SIZE_T bytesRead = 0;
        BOOL ok = ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(region.baseAddress),
            buffer.data(),
            buffer.size(),
            &bytesRead
        );

        if (!ok) {
            out << L"\n[Optional Read] ReadProcessMemory failed at 0x"
                << std::hex << region.baseAddress << std::dec
                << L": " << GetLastErrorMessage(GetLastError()) << L"\n";
            return;
        }

        out << L"\n[Optional Read] Successfully read " << bytesRead
            << L" bytes from 0x" << std::hex << region.baseAddress << std::dec << L"\n";
        out << L"Bytes: ";
        for (SIZE_T i = 0; i < bytesRead; ++i) {
            out << std::hex << std::setw(2) << std::setfill(L'0')
                << static_cast<unsigned>(buffer[i]) << L" ";
        }
        out << std::dec << std::setfill(L' ') << L"\n";
        return;
    }

    out << L"\n[Optional Read] No readable committed region found.\n";
}

std::wstring GetProcessNameFromList(DWORD pid, const std::vector<ProcessInfo>& processes) {
    for (const auto& p : processes) {
        if (p.pid == pid) {
            return p.name;
        }
    }
    return L"<unknown>";
}

std::wstring BuildReportFileName(DWORD pid) {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    std::wstringstream name;
    name << L"memory_report_pid_" << pid << L"_"
         << st.wYear
         << std::setw(2) << std::setfill(L'0') << st.wMonth
         << std::setw(2) << std::setfill(L'0') << st.wDay
         << L"_"
         << std::setw(2) << std::setfill(L'0') << st.wHour
         << std::setw(2) << std::setfill(L'0') << st.wMinute
         << std::setw(2) << std::setfill(L'0') << st.wSecond
         << L".txt";
    return name.str();
}

bool WriteReportToFile(const std::wstring& reportFileName, const std::wstring& reportText) {
    std::wofstream outFile(reportFileName);
    if (!outFile.is_open()) {
        return false;
    }
    outFile << reportText;
    return static_cast<bool>(outFile);
}

void WaitForExitKey() {
    std::wcout << L"\nPress Enter to exit...";
    std::wcin.clear();
    std::wcin.ignore((std::numeric_limits<std::streamsize>::max)(), L'\n');
    std::wcin.get();
}

int wmain() {
    std::vector<ProcessInfo> processes = EnumerateProcesses();
    if (processes.empty()) {
        std::wcerr << L"[!] No processes found or enumeration failed.\n";
        return 1;
    }

    PrintProcesses(processes);

    std::optional<DWORD> maybePid = PromptForPid(processes);
    if (!maybePid.has_value()) {
        return 1;
    }

    DWORD pid = maybePid.value();
    HANDLE processHandle = OpenTargetProcess(pid);
    if (processHandle == nullptr) {
        WaitForExitKey();
        return 1;
    }

    std::wstring processName = GetProcessNameFromList(pid, processes);
    std::wstringstream reportStream;
    reportStream << L"[PID: " << pid << L"] " << processName << L"\n";

    MemorySummary summary{};
    std::vector<ProcessMemoryRegion> regions = ScanCommittedMemoryRegions(processHandle, summary);
    PrintMemoryReport(reportStream, regions, summary);
    TryReadSmallMemoryChunk(reportStream, processHandle, regions);

    std::wstring reportText = reportStream.str();
    std::wcout << L"\n" << reportText;

    std::wstring reportFileName = BuildReportFileName(pid);
    if (WriteReportToFile(reportFileName, reportText)) {
        std::wcout << L"\n[+] Report written to: " << reportFileName << L"\n";
    } else {
        std::wcerr << L"\n[!] Failed to write report file: " << reportFileName << L"\n";
    }

    CloseHandle(processHandle);
    WaitForExitKey();
    return 0;
}
