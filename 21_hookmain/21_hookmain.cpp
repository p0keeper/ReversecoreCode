#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <conio.h>

#define DEF_DLL_NAME "KeyHook.dll"
#define DEF_HOOKSTART "HookStart"
#define DEF_HOOKSTOP "HookStop"

typedef void(*PFN_HOOKSTART)();
typedef void(*PFN_HOOKSTOP)();

int main()
{
    HMODULE hDll = NULL;
    PFN_HOOKSTART HookStart = NULL;
    PFN_HOOKSTOP HookStop = NULL;
    char ch = 0;

    // load Dll
    hDll = LoadLibraryA(DEF_DLL_NAME);
    if (hDll == NULL) {
        printf("load fail \n");
        return 0;
    }
    else {
        printf("load success \n");
    }

    HookStart = (PFN_HOOKSTART)GetProcAddress(hDll, DEF_HOOKSTART);
    HookStop = (PFN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);

    HookStart();

    printf("press 'q' to quit!\n");

    // if user push 'q' key, HookStop
    while (1) {
        if (_getch() == 'q') {
            break;
        }
        printf("Test Typing  \n");
    }

    HookStop();

    FreeLibrary(hDll);
    return 0;
}