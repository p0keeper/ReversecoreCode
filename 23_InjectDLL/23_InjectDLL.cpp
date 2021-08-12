#include "windows.h"
#include "tchar.h"

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
    LPTHREAD_START_ROUTINE pThreadProc;
    BOOL bRet = TRUE;

    //确定路径需要占用的缓冲区大小
    dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);

    // #1. 使用OpenProcess函数获取目标进程句柄（PROCESS_ALL_ACCESS权限）
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }

    // #2. 使用VirtualAllocEx函数在目标进程中分配内存，大小为szDllName
      // VirtualAllocEx函数返回的是hProcess指向的目标进程的分配所得缓冲区的内存地址
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

    // #3.  将myhack.dll路径 ("c:\\myhack.dll")写入目标进程中分配到的内存
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);

    // #4. 获取LoadLibraryA() API的地址
      // 这里主要利用来了kernel32.dll文件在每个进程中的加载地址都相同这一特点，所以不管是获取加载到   
      // InjectDll.exe还是notepad.exe进程的kernel32.dll中的LoadLibraryW函数的地址都是一样的。这里的加载地
      // 址相同指的是在同一次系统运行中，如果再次启动系统kernel32.dll的加载地址会变，但是每个进程的
      // kernerl32.dll的加载地址还是一样的。
    hMod = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

    // #5. 在目标进程notepad.exe中运行远程线程
      // pThreadProc = notepad.exe进程内存中的LoadLibraryW()地址
      // pRemoteBuf = notepad.exe进程内存中待加载注入dll的路径字符串的地址
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    if (hThread == NULL)
    {
        _tprintf(L"[ERROR] CreateRemoteThread() failed!!! [%d]\n", GetLastError());
        bRet = FALSE;
        goto _ERROR;
    }

    WaitForSingleObject(hThread, INFINITE);

_ERROR:
    if (pRemoteBuf)
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    //同样，记得关闭句柄
    if(hThread)
        CloseHandle(hThread);
    if(hProcess)
        CloseHandle(hProcess);

    return bRet;
}

int _tmain(int argc, TCHAR* argv[])
{
    if (argc != 3)
    {
        _tprintf(L"USAGE : %s <pid> <dll_path>\n", argv[0]);
        return 1;
    }

    // inject dll
    if (InjectDll((DWORD)_tstol(argv[1]), argv[2]))
        _tprintf(L"InjectDll(\"%s\") success!!!\n", argv[2]);
    else
        _tprintf(L"InjectDll(\"%s\") failed!!!\n", argv[2]);

    return 0;
}