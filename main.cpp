#include <Windows.h>
#include <NTSecAPI.h>

#include <iostream>
#include <cstring>

struct ProcessInfo {
  HANDLE hProcess;
  HANDLE hThread;
};

static bool getMemprivileges() {
  HANDLE hToken = nullptr;

  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
  {
      std::cout << "OpenProcessToken failed: " << GetLastError() << std::endl;
      return false;
  }

  TOKEN_PRIVILEGES tp = {};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!LookupPrivilegeValue(nullptr, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid))
  {
      std::cout << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
      return false;
  }

  if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0))
  {
      std::cout << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
      return false;
  }

  CloseHandle(hToken);
  return true;
}

static ProcessInfo startProcess( const char* appName, int argc, char* argv[])
{
  std::string args;
  for (int i = 0 ; i< argc; ++i) {
    args += std::string(" \"") + argv[i] + "\"";
  }

  std::cout << "App args: " << args << std::endl;
  PROCESS_INFORMATION pi = {};
  STARTUPINFO si = {};
  si.cb = sizeof(si);
//  si.dwFlags = STARTF_USESTDHANDLES;
//  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
//  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
//  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if(!CreateProcessA(appName,
                     args.data(),
                     nullptr,
                     nullptr,
                     FALSE,
                     CREATE_SUSPENDED,
                     nullptr,
                     nullptr,
                     &si,
                     &pi))
  {
      std::cout << "CreateProcessA failed with " << GetLastError() << std::endl;
      return {nullptr, nullptr};
  }
  return {pi.hProcess, pi.hThread};
}

static int impl(int argc, char* argv[]) {
  std::cout << "Args:";
  for (int i = 0; i < argc; ++i)
    std::cout << " " << argv[i];

  std::cout << std::endl;

  // Skip exe
  --argc;
  ++argv;

  const char* proxyName = "proxy.dll";

  std::cout << "Proxy path " << proxyName << std::endl;

  const char* fact = "factorio.exe";
  if (argc > 0) {
    fact = argv[0];
    --argc;
    ++argv;
  }

  std::cout << "getMemprivileges" << std::endl;
  if(!getMemprivileges())
    return 1;

  auto largePageSize = GetLargePageMinimum();
  std::cout << "GetLargePageMinimum: " << largePageSize << std::endl;

  auto testPtr = VirtualAlloc(nullptr, largePageSize, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
  if (!testPtr) {
    std::cout << "Huge page allocation failed: " << GetLastError() << std::endl;
    return 1;
  }
  VirtualFree(testPtr, 0, MEM_RELEASE);

  SetEnvironmentVariable("TBB_MALLOC_USE_HUGE_PAGES", "1");
  SetEnvironmentVariable("TBB_VERSION", "1");

  std::cout << "Getting LoadLibraryA handle" << std::endl;
  auto hKernel32 = GetModuleHandle("Kernel32");
  auto *lb = GetProcAddress(hKernel32, "LoadLibraryA");

  std::cout << "Running " << fact << std::endl;

  auto process = startProcess(fact, argc, argv);
  if (!process.hProcess)
    return 1;

  auto proxyNameLen = std::strlen(proxyName) + 1;

  std::cout << "VirtualAllocEx" << std::endl;
  auto rb = VirtualAllocEx(process.hProcess, nullptr, proxyNameLen, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
  if (!rb) {
    std::cout << "VirtualAllocEx failed with " << GetLastError() << std::endl;
    return 1;
  }

  std::cout << "WriteProcessMemory" << std::endl;
  if (!WriteProcessMemory(process.hProcess, rb, proxyName, proxyNameLen, nullptr)) {
    std::cout << "WriteProcessMemory failed with " << GetLastError() << std::endl;
    return 1;
  }

  std::cout << "CreateRemoteThread" << std::endl;
  auto rt = CreateRemoteThread(process.hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)lb, rb, 0, nullptr);
  if (!rt) {
    std::cout << "CreateRemoteThread failed with " << GetLastError() << std::endl;
    return 1;
  }

  std::cout << "Wait for remote thread" << std::endl;
  WaitForSingleObject(rt, INFINITE);
  CloseHandle(rt);

  std::cout << "ResumeThread" << std::endl;
  if (ResumeThread(process.hThread) == (DWORD)-1) {
    std::cout << "ResumeThread failed with " << GetLastError() << std::endl;
    return 1;
  }

  std::cout << "WaitForSingleObject" << std::endl;
  WaitForSingleObject(process.hProcess, INFINITE);

  std::cout << "done" << std::endl;
  return 0;
}

int main(int argc, char* argv[]) {
  auto res = impl(argc, argv);
  std::cin.get();
  return res;
}
