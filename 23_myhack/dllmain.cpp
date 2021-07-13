// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "windows.h"
#include "tchar.h"

#pragma comment(lib,"urlmon.lib")

#define DEF_URL         (L"http://192.168.10.11/index.html")
#define DEF_FILE_NAME   (L"index.html")

HMODULE g_hMod = NULL;

DWORD WINAPI ThreadProc(LPVOID lParam)
{
    // TCHAR szPath[_MAX_PATH] = { 0, };
    //这里书中用的_MAX_PATH在路径注入之后会导致堆栈异常，太短了，所以我直接修改为500
    TCHAR szPath[_MAX_PATH] = { 0, };
    if (!GetModuleFileName(g_hMod, szPath, MAX_PATH))
        return FALSE;

    TCHAR *p = _tcsrchr(szPath,'\\');

    if (!p)
        return FALSE;

    _tcscpy_s(p + 1, _MAX_PATH, DEF_FILE_NAME);
    URLDownloadToFile(NULL, DEF_URL, szPath, 0, NULL);
    return 0;

}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    HANDLE hThread = NULL;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugString(L"<myhack.dll> Injection!!!");

        //创建远程线程进行download
        hThread = CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);

        // 需要注意，切记随手关闭句柄，保持好习惯
        CloseHandle(hThread);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

