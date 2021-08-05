// include
#include "stdio.h"
#include "wchar.h"
#include "windows.h"


// typedef
typedef BOOL(WINAPI* PFSETWINDOWTEXTW)(HWND hWnd, LPWSTR lpString);


// globals
FARPROC g_pOrgFunc = NULL;


BOOL WINAPI MySetWindowTextW(HWND hWnd, LPWSTR lpString)
{
    wchar_t* pNum = L"零一二三四五六七八九";
    wchar_t temp[2] = { 0, };
    int i = 0, nLen = 0, nIndex = 0;

    nLen = wcslen(lpString);
    for (i = 0; i < nLen; i++)
    {
        if (L'0' <= lpString[i] && lpString[i] <= L'9')
        {
            temp[0] = lpString[i];
            nIndex = _wtoi(temp);
            lpString[i] = pNum[nIndex];
        }
    }
    return ((PFSETWINDOWTEXTW)g_pOrgFunc)(hWnd, lpString);
}


// hook_iat
BOOL hook_iat(LPCSTR szDllName, PROC pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;

    // hMod, pAddr = ImageBase of calc.exe
    //             = VA to MZ signature (IMAGE_DOS_HEADER)
    // 获取当前DLL的模块基址
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;

    // pAddr = VA to PE signature (IMAGE_NT_HEADERS)
    // 偏移0x3C的地址指向PE字符的位置
    pAddr += *((DWORD*)&pAddr[0x3C]);

    // dwRVA = RVA to IMAGE_IMPORT_DESCRIPTOR Table
    // PE字符往后偏移0x80就是IDT的起始地址,其中包含了各个DLL的IMAGE_IMPORT_DESCRIPTOR
    dwRVA = *((DWORD*)&pAddr[0x80]);

    // pImportDesc = VA to IMAGE_IMPORT_DESCRIPTOR Table
    // 这里加上DLL的基地址，就是VA地址，即虚拟地址
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);

    for (; pImportDesc->Name; pImportDesc++)
    {
        // szLibName = VA to IMAGE_IMPORT_DESCRIPTOR.Name
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
        // 判断是否是user32.dll对应的IMAGE_IMPORT_DESCRIPTOR
        if (!_stricmp(szLibName, szDllName))
        {
            // pThunk = IMAGE_IMPORT_DESCRIPTOR.FirstThunk
            //        = VA to IAT(Import Address Table)

            // pThunk的指向user32的IAT地址
            pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod +
                pImportDesc->FirstThunk);

            // pThunk->u1.Function = VA to API
            for (; pThunk->u1.Function; pThunk++)
            {
                // 这里的pfnOrg实际上就是SetWindowTextW
                if (pThunk->u1.Function == (DWORD)pfnOrg)
                {
                    // VirtualProtect修改保护权限
                    VirtualProtect((LPVOID)&pThunk->u1.Function,
                        4,
                        PAGE_EXECUTE_READWRITE,
                        &dwOldProtect);

                    // 修改IAT地址，这里pfnNew是MySetWindowTextW的地址
                    pThunk->u1.Function = (DWORD)pfnNew;

                    VirtualProtect((LPVOID)&pThunk->u1.Function,
                        4,
                        dwOldProtect,
                        &dwOldProtect);

                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}



BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // original API
        g_pOrgFunc = GetProcAddress(GetModuleHandle(L"user32.dll"),
            "SetWindowTextW");

        hook_iat("user32.dll", g_pOrgFunc, (PROC)MySetWindowTextW);
        break;

    case DLL_PROCESS_DETACH:
        // # unhook
        hook_iat("user32.dll", (PROC)MySetWindowTextW, g_pOrgFunc);
        break;
    }

    return TRUE;
}