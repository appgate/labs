//                            _____       _         _           _         
//         /\                / ____|     | |       | |         | |        
//        /  \   _ __  _ __ | |  __  __ _| |_ ___  | |     __ _| |__  ___ 
//       / /\ \ | '_ \| '_ \| | |_ |/ _` | __/ _ \ | |    / _` | '_ \/ __|
//      / ____ \| |_) | |_) | |__| | (_| | ||  __/ | |___| (_| | |_) \__ \
//     /_/    \_\ .__/| .__/ \_____|\__,_|\__\___| |______\__,_|_.__/|___/
//              | |   | |                                                 
//              |_|   |_|    
/*
    This DLL was developed as a vaccine for Dridex, making the malware to 
    load it instead of the real DLL, due a CRC32 conflict.   

    This DLL must be placed on system32 or syswow64 directories, with "hhdk0gu.dll" as name,
    so it can be loaded by Dridex instead of the original shell32.dll                                        
*/

#include "Windows.h"
#include "winbase.h"
#include <tchar.h>

#pragma comment(lib,"user32.lib");


#define DLL_EXPORT extern "C" __declspec(dllexport)

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    return TRUE;
}

DLL_EXPORT void hook_stub()
{
    MessageBox(NULL, _T("Dridex Detector DLL was executed\n"
                        "Preventing Dridex from being executed, exiting process ..."), _T("AppGate - Dridex Detection"), MB_OK | MB_ICONWARNING);
    ExitProcess(0);
}
