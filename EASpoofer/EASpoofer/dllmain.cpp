// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <math.h>
#include <iostream>

//CoCreateInstance
//GetAdapterAddress
//GetVolumeInformation
//GetMacAddress
//HRESULT (__stdcall *CoCreateInstance)(const IID *const rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, const IID *const riid, LPVOID *ppv)

int randSID[2];
inline HRESULT(org_CoCreateInstance)(const IID* const, DWORD, DWORD, const IID* const, LPVOID*);


//0xE54FC
HRESULT Hk_CoCreateInstance(IID* rclsid, DWORD pUnkOuter, DWORD dwClsContext,IID* riid, LPVOID* ppv)
{
    rclsid->Data1 = randSID[0];
    rclsid->Data2 = randSID[1];
    rclsid->Data3 = randSID[2];

    org_CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
    return 1;
}
//00007FFF028054FC
void doHooks()
{
    std::uintptr_t Process = (std::uintptr_t)GetModuleHandle(NULL);
    std::uintptr_t CoCreateInstanec_Func = *reinterpret_cast<std::uintptr_t*>(Process + 0xE54FC);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        randSID[0] = static_cast<int>(rand() % 500);
        randSID[1] = static_cast<int>(rand() % 500);
        randSID[2] = static_cast<int>(rand() % 500);

        doHooks();
    }
}

