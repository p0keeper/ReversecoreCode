// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "windows.h"
#include "tchar.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    TCHAR szPath[MAX_PATH] = { 0, };
    TCHAR szMsg[1024] = { 0, };
    TCHAR* p = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        GetModuleFileName(NULL, szPath, MAX_PATH);
        p = _tcsrchr(szPath, L'\\');
        if (p != NULL)
        {
            _stprintf_s(szMsg, 1024 - sizeof(TCHAR),
                L"Injected in %s(%d)",
                p + 1,
                GetCurrentProcessId()
            );
            OutputDebugString(szMsg);
        }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

