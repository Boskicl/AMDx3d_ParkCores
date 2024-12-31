#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma comment(lib, "psapi.lib")

// -----------------------------------------------------------
// Simple “logger” style macros to keep logs consistent:
#define LOG_INFO(fmt, ...)  do { printf("[INFO]  " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_WARN(fmt, ...)  do { printf("[WARN]  " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_ERROR(fmt, ...) do { fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)

// -----------------------------------------------------------
// Global cancellation flag to emulate the C# cancellation token
std::atomic<bool> g_cancelRequested(false);

// Global “isLoading” status
std::atomic<bool> g_isLoading(false);

// -----------------------------------------------------------
// Utility: Get number of *usable* processor cores via affinity checks
int GetNumberProcessors()
{
    // We attempt the same approach as the C# code:
    // 1) Try to set the affinity mask to all '1's for Environment.ProcessorCount
    // 2) If that fails, we decrement until we find a mask that works
    int envProcs = static_cast<int>(std::thread::hardware_concurrency());
    if (envProcs <= 0) {
        envProcs = 1; 
    }

    DWORD_PTR testMask = 0;
    // Build a mask with 'envProcs' 1-bits
    for (int i = 0; i < envProcs; ++i) {
        testMask |= (static_cast<DWORD_PTR>(1) << i);
    }
    HANDLE self = GetCurrentProcess();
    if (SetProcessAffinityMask(self, testMask)) {
        // It worked; revert to letting the OS handle it
        SetProcessAffinityMask(self, ~static_cast<DWORD_PTR>(0));
        return envProcs;
    } else {
        LOG_WARN("Number of cores reported was %d, but it appears different than the affinity. Trying to find the real number...", envProcs);
    }

    // If that fails, we decrement from min(64, envProcs*2) downward
    for (int i = std::min(64, envProcs * 2); i > 0; i--) {
        DWORD_PTR altMask = 0;
        for (int bitCount = 0; bitCount < i; ++bitCount) {
            altMask |= (static_cast<DWORD_PTR>(1) << bitCount);
        }
        if (SetProcessAffinityMask(self, altMask)) {
            // revert
            SetProcessAffinityMask(self, ~static_cast<DWORD_PTR>(0));
            LOG_WARN("Calculated that we should be using %d cores. Proceeding with that number.", i);
            return i;
        }
    }

    LOG_ERROR("Could not detect the number of processors being used. Cannot continue.");
    throw std::runtime_error("Could not detect the number of processors being used.");
}

// -----------------------------------------------------------
// Get an environment variable’s integer value safely
int GetEnvInt(const char* varName, int defaultVal)
{
    char* val = std::getenv(varName);
    if (!val) {
        return defaultVal;
    }
    try {
        return std::stoi(val);
    } catch(...) {
        return defaultVal;
    }
}

// -----------------------------------------------------------
// Helper to see if a process is responding. (We do a naive check. 
// A more robust approach might involve sending WM_NULL messages, etc.)
bool IsProcessResponding(HANDLE hProcess)
{
    // WaitForInputIdle is one naive approach. If it times out, we guess it's "not responding."
    // This approach may not be accurate for all processes.
    DWORD waitRes = WaitForInputIdle(hProcess, 100);
    if (waitRes == WAIT_TIMEOUT) {
        return false;
    }
    return true;
}

// -----------------------------------------------------------
// Check for "Path of Exile 2" by enumerating processes and comparing
// the main window title and/or process name. This is not 100% robust 
// but emulates the logic from the C# code.
DWORD FindPathOfExileProcessId()
{
    // We look for a process whose main window title is "Path of Exile 2"
    // and whose process name contains "PathOfExile".
    // Because enumerating windows by title is a separate approach, 
    // we'll do a naive approach with snapshot iteration, then check each process.

    DWORD resultPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return 0;
    }

    do {
        // We do a case-insensitive check: process name “PathOfExile”
        // Then we open the process to see if the window’s title matches "Path of Exile 2".
        std::wstring exeName = pe.szExeFile;
        // naive lower-case check
        for (auto & ch : exeName) {
            ch = towlower(ch);
        }

        if (exeName.find(L"pathofexile") != std::wstring::npos) {
            // We have a candidate. Now let's see if the window title says "Path of Exile 2"
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | SYNCHRONIZE, FALSE, pe.th32ProcessID);
            if (hProc) {
                // We'll see if the process has a top-level window with the right title
                // (Naive approach, we loop over windows. Real solution might store them in a vector.)
                HWND hWnd = NULL;
                while ( (hWnd = FindWindowEx(NULL, hWnd, NULL, NULL)) != NULL ) {
                    DWORD wndPid = 0;
                    GetWindowThreadProcessId(hWnd, &wndPid);
                    if (wndPid == pe.th32ProcessID) {
                        // Check the title
                        const int bufSize = 1024;
                        WCHAR wTitle[bufSize];
                        GetWindowTextW(hWnd, wTitle, bufSize);
                        std::wstring title = wTitle;
                        // naive lower
                        for (auto & tch : title) {
                            tch = towlower(tch);
                        }
                        std::wstring cmp = L"path of exile 2";
                        // remove spaces in compare? or just do a find?
                        // We'll just check if it's exactly "path of exile 2"
                        if (title.find(L"path of exile 2") != std::wstring::npos) {
                            resultPid = pe.th32ProcessID;
                            CloseHandle(hProc);
                            CloseHandle(snap);
                            return resultPid;
                        }
                    }
                }
                CloseHandle(hProc);
            }
        }
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return 0;
}

// -----------------------------------------------------------
// Return a `Process`-like handle we can manipulate
//   - In C#, we returned `Process?`. Here we’ll return a HANDLE or NULL.
HANDLE GetPathOfExileProcess()
{
    DWORD pid = FindPathOfExileProcessId();
    if (!pid) {
        return NULL;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | SYNCHRONIZE,
        FALSE, pid
    );
    if (!hProc) {
        return NULL;
    }

    // Check if it’s alive
    DWORD exitCode = 0;
    if (GetExitCodeProcess(hProc, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            CloseHandle(hProc);
            return NULL;
        }
    }
    return hProc;
}

// -----------------------------------------------------------
// Wait until PoE process is running (like the C# code)
HANDLE WaitForExecutableToLaunch()
{
    while (!g_cancelRequested.load()) {
        HANDLE hProc = GetPathOfExileProcess();
        if (hProc != NULL) {
            return hProc;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    return NULL;
}

// -----------------------------------------------------------
// Attempt to park cores
void ParkCores(int numCores, int coresToPark)
{
    // Build an affinity mask with (numCores - coresToPark) bits set to 1, and the rest 0
    // The C# code right-justifies the 1 bits.  For instance, if we have 6 cores and want
    // to park 2, we want the lowest 4 bits = 1, and the top 2 bits = 0.
    // However, their code actually does it from the *right*, which is standard. 
    // e.g. if we have 6 cores, bits = 111111 initially. Then we set the top 2 to 0 => 001111
    // But in little-endian, that means we skip the highest index bits.
    // We'll do the same logic:

    // Start with all 1
    DWORD_PTR mask = 0;
    for (int i = 0; i < numCores; ++i) {
        mask |= (static_cast<DWORD_PTR>(1) << i);
    }
    // Turn off the highest `coresToPark` bits
    for (int i = 0; i < coresToPark; ++i) {
        int bitToClear = numCores - 1 - i;
        if (bitToClear >= 0) {
            mask &= ~(static_cast<DWORD_PTR>(1) << bitToClear);
        }
    }

    // Now apply it to the PoE process
    HANDLE hProc = GetPathOfExileProcess();
    if (hProc) {
        if (SetProcessAffinityMask(hProc, mask)) {
            LOG_INFO("Parked cores: %d (mask) => 0x%llX", coresToPark, static_cast<unsigned long long>(mask));
            g_isLoading.store(true);
        } else {
            LOG_ERROR("Detected loading screen, but could not set PoE process affinity (error=%lu).", GetLastError());
        }
        CloseHandle(hProc);
    } else {
        LOG_ERROR("Detected loading screen, but could not find any process to park.");
    }
}

// -----------------------------------------------------------
// Resume all cores
void ResumeCores(int numCores)
{
    // Re-enable all bits
    DWORD_PTR mask = 0;
    for (int i = 0; i < numCores; ++i) {
        mask |= (static_cast<DWORD_PTR>(1) << i);
    }

    HANDLE hProc = GetPathOfExileProcess();
    if (hProc) {
        if (SetProcessAffinityMask(hProc, mask)) {
            LOG_INFO("Unparked cores %d: (mask) => 0x%llX", numCores, static_cast<unsigned long long>(mask));
            g_isLoading.store(false);
        } else {
            LOG_ERROR("Detected end of loading screen, but could not set PoE process affinity (error=%lu).", GetLastError());
        }
        CloseHandle(hProc);
    } else {
        LOG_ERROR("Detected end of loading screen, but could not find any process to unpark.");
    }
}

// -----------------------------------------------------------
// Logic to handle "realtime" or "normal" priority
// Replicates the separate thread that checks if the game is not responding, 
// then tries to set it to REALTIME priority, and eventually resets it.
void PriorityThreadFunc()
{
    bool isRealtime = false;
    while (!g_cancelRequested.load()) {
        if (g_isLoading.load()) {
            // We want to see if the process is responding. If not, set REALTIME to attempt recovery.
            HANDLE hProc = GetPathOfExileProcess();
            if (hProc) {
                if (!isRealtime) {
                    // If not responding
                    if (!IsProcessResponding(hProc)) {
                        LOG_WARN("PoE Process not responding: Attempting to recover by setting it to REALTIME.");
                        BOOL success = SetPriorityClass(hProc, REALTIME_PRIORITY_CLASS);
                        if (success) {
                            isRealtime = true;
                        } else {
                            LOG_ERROR("Failed to set process priority to REALTIME (error=%lu).", GetLastError());
                        }
                    }
                } else {
                    // If we are in realtime, check if PoE is gone
                    DWORD exitCode = 0;
                    if (!GetExitCodeProcess(hProc, &exitCode) || (exitCode != STILL_ACTIVE)) {
                        isRealtime = false;
                        g_isLoading.store(false);
                        LOG_ERROR("PoE quit while set to realtime; resetting loading and realtime status.");
                    }
                }
                CloseHandle(hProc);
            }
        } else {
            // If we are not in a loading state but we are still in realtime, revert to normal
            if (HANDLE hProc = GetPathOfExileProcess()) {
                if (isRealtime) {
                    LOG_INFO("Loading is done, falling back from REALTIME.");
                    SetPriorityClass(hProc, NORMAL_PRIORITY_CLASS);
                    isRealtime = false;
                }
                CloseHandle(hProc);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

// -----------------------------------------------------------
// A small function that reads lines from stdin (console)
// and if it's an integer, we treat it as the new “coresToPark”.
void ConsoleThreadFunc(int& coresToPark, int numCores)
{
    while (!g_cancelRequested.load()) {
        // Attempt a non-blocking read from stdin
        // A simple approach: check if there's data on cin
        std::string line;
        if (!std::cin.eof() && std::cin.good()) {
            if (std::getline(std::cin, line)) {
                try {
                    int newVal = std::stoi(line);
                    // If user types something invalid (like a string), it’ll throw
                    if (newVal >= numCores) {
                        LOG_ERROR("You can't override more cores than you have.");
                    } else {
                        coresToPark = newVal;
                        LOG_INFO("Future attempts at parking cores will park %d cores.", newVal);
                    }
                } catch(...) {
                    // Not an integer, ignore
                }
            } else {
                // Sleep a bit if no data
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } else {
            // Sleep a bit
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// -----------------------------------------------------------
// The main “worker” that reads lines from the PoE log file
// and triggers Park/Resume accordingly.
void LogReaderThreadFunc(const std::string& clientTxtPath, int numCores, int& coresToPark)
{
    // Our three regexes:
    std::regex startGameMatcher(R"(^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \d+ [A-Fa-f0-9]+ \[INFO Client \d+\] \[ENGINE\] Init$)");
    std::regex startLoadMatcher(R"(^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \d+ [A-Fa-f0-9]+ \[INFO Client \d+\] \[SHADER\] Delay: OFF$)");
    std::regex endLoadMatcher(R"(^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} \d+ [A-Fa-f0-9]+ \[INFO Client \d+\] \[SHADER\] Delay: ON$)");

    std::ifstream inFile(clientTxtPath, std::ios::in);
    if (!inFile.is_open()) {
        LOG_ERROR("Failed to open client log file: %s", clientTxtPath.c_str());
        return;
    }
    // Seek to end
    inFile.seekg(0, std::ios::end);

    // Start reading lines as they come in
    while (!g_cancelRequested.load()) {
        std::streampos curPos = inFile.tellg();
        std::string line;
        if (std::getline(inFile, line)) {
            // If the line is too large or empty, skip
            if (line.size() > 256 || line.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
                continue;
            }

            if (std::regex_search(line, startGameMatcher) || std::regex_search(line, startLoadMatcher)) {
                ParkCores(numCores, coresToPark);
            } else if (std::regex_search(line, endLoadMatcher)) {
                ResumeCores(numCores);
            }
        } else {
            // If no new line, check if we are at end or error
            if (inFile.eof()) {
                // Clear EOF state
                inFile.clear();
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            } else {
                // Some error we might want to handle
                // For now, just sleep a bit
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}

// -----------------------------------------------------------
int main()
{
    // Setup basic info
    LOG_INFO("Starting up...");

    // 1) Figure out how many CPU cores we can manipulate
    int numCores = 0;
    try {
        numCores = GetNumberProcessors();
    } catch (...) {
        // If we fail, we must exit
        return 1;
    }
    LOG_INFO("Detected %d cores.", numCores);

    // 2) Read environment variable for CORES_TO_PARK
    int coresToPark = 2;
    {
        int fromEnv = GetEnvInt("CORES_TO_PARK", -1);
        if (fromEnv > 0) {
            coresToPark = fromEnv;
        }
    }
    LOG_INFO("Will attempt to park %d cores when needed.", coresToPark);

    // 3) Wait for PoE process. If not running, wait for launch
    LOG_INFO("Waiting for Path of Exile process to launch before doing anything.");
    HANDLE hPoE = GetPathOfExileProcess();
    if (!hPoE) {
        // Wait for it to show up
        hPoE = WaitForExecutableToLaunch();
        if (!hPoE) {
            // user canceled or something
            LOG_INFO("Cancellation requested or PoE never launched. Exiting.");
            return 0;
        }
        // If the game wasn't already running, we do an initial park to prevent launch crashes 
        // (as the original code says).
        ParkCores(numCores, coresToPark);
    }

    // 4) Detect game directory. The naive approach:
    //    In C#, we used proc.MainModule. In C++ we can try to query it via 
    //    GetModuleFileNameEx (requires psapi). Let’s do that:
    char pathBuf[MAX_PATH] = {0};
    if (!GetModuleFileNameExA(hPoE, NULL, pathBuf, MAX_PATH)) {
        LOG_ERROR("Couldn't detect game directory from PoE process. Falling back to default path...");
        strcpy_s(pathBuf, R"(D:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2)");
    }
    std::filesystem::path gamePath(pathBuf);
    std::filesystem::path gameDirectory = gamePath.parent_path();
    // fallback
    if (gameDirectory.empty()) {
        gameDirectory = R"(D:\Program Files (x86)\Steam\steamapps\common\Path of Exile 2")";
    }
    CloseHandle(hPoE); // We can close for now; we’ll re-open if needed

    // 5) Build the client.txt path
    auto clientTxtLocation = gameDirectory / "logs" / "client.txt";
    auto kakaoClientTxtLocation = gameDirectory / "logs" / "KakaoClient.txt";

    std::string clientTxtPath = clientTxtLocation.string();
    if (std::filesystem::exists(kakaoClientTxtLocation)) {
        LOG_INFO("Detected KR client log file -- using KakaoClient.txt as source instead.");
        clientTxtPath = kakaoClientTxtLocation.string();
    }
    LOG_INFO("Reading client data from %s", clientTxtPath.c_str());

    // 6) Start threads:
    //    a) Priority check thread
    std::thread priorityThread(PriorityThreadFunc);

    //    b) Console reading thread
    std::thread consoleThread(ConsoleThreadFunc, std::ref(coresToPark), numCores);

    //    c) Log reading thread
    std::thread logReaderThread(LogReaderThreadFunc, clientTxtPath, numCores, std::ref(coresToPark));

    // 7) Handle Ctrl+C to emulate the .NET behavior
    //    We can’t do exactly what the .NET code does, but we can set a console handler.
    SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
        if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT) {
            g_cancelRequested.store(true);
            return TRUE; // signal handled
        }
        return FALSE;
    }, TRUE);

    // We’ll just wait for the threads. If user hits Ctrl+C, we’ll break.
    // In a real application, we might do something else (like keep the main thread alive).
    while (!g_cancelRequested.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // 8) When canceled, wait for the threads to exit
    if (consoleThread.joinable()) consoleThread.join();
    if (logReaderThread.joinable()) logReaderThread.join();
    if (priorityThread.joinable()) priorityThread.join();

    LOG_INFO("Program ended. Goodbye.");
    return 0;
}
