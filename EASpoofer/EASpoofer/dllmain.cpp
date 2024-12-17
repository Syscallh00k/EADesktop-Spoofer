#include <Windows.h>
#include <TlHelp32.h>
#include <math.h>
#include <iostream>
#include <MinHook.h> 
#include "kiero/kiero.h"
#include <random>  
#include <iphlpapi.h>
#include <ctime>
#include <sstream>
#include <iomanip>

#define LOG(arg) std::cout << "LOG -> " arg << "\n";
uintptr_t GeneratedRandomSerial;
uintptr_t spoofedAdaperAddress;
GUID spoofedGuid;
std::stringstream spoofedmac;
/*
MacAddress - done
VolumeInformation
CoCreateInstance - done
GetAdapterAddress - done
*/
// Get Mac Address -> 0x52D073 
//*(void (__fastcall **)(__int64, __int64, const char **, __int128 *))
//eax::foundation::getBestMacAddress
typedef HRESULT(WINAPI* CoCreateInstance_t)(
    REFCLSID rclsid,
    DWORD pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID* ppv
    );

typedef ULONG(WINAPI* GetAdaptersAddresses_t)(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    DWORD AdapterAddresses,
    PULONG SizePointer
    );
typedef BOOL(WINAPI* GetVolumeAddresses_t)(
    HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation
    );

CoCreateInstance_t OriginalCoCreateInstance = nullptr;
GetAdaptersAddresses_t OriginalGetAdaptersAddresses = nullptr;
GetVolumeAddresses_t OriginalGetVolumeAddresse = nullptr;
GUID UIIWbem_org;
void GenerateRandomMacAddress(unsigned char* mac) {
    for (int i = 0; i < 6; ++i) {
        mac[i] = rand() % 256;
    }
    mac[0] = (mac[0] & 0xFE) | 0x02;
}
static BOOL WINAPI HookedVolumeAddress(HANDLE hFile, LPBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    BOOL status = OriginalGetVolumeAddresse(hFile, lpFileInformation);

    if (status && lpFileInformation) {

        lpFileInformation->dwVolumeSerialNumber = GeneratedRandomSerial;
    }

    return status;
}
static ULONG WINAPI HookedGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, DWORD AdapterAddresses, PULONG SizePointer)
{
    ULONG result = OriginalGetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);

    return result;
}
static HRESULT WINAPI HookedCoCreateInstance(REFCLSID rclsid, DWORD pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
    if (IsEqualGUID(rclsid, UIIWbem_org))
    {
        return E_FAIL;
    }
    else {
        HRESULT hr = OriginalCoCreateInstance(spoofedGuid, pUnkOuter, dwClsContext, riid, ppv);
        return hr;

    }
}

void doHooks()
{
    LOG("Initializing Hooks...");

    if (MH_Initialize() != MH_OK) {
        printf("LOG -> Initialization failed!\n");
        return;
    }

    LOG("Creating hooks...");

    std::uintptr_t CoCreateInstance_Func = (std::uintptr_t)GetProcAddress(GetModuleHandleA("ole32.dll"), "CoCreateInstance");
    printf("LOG -> CoCreateInstance Function: %llx\n", CoCreateInstance_Func);
    if (MH_CreateHook((LPVOID)CoCreateInstance_Func, &HookedCoCreateInstance, reinterpret_cast<LPVOID*>(&OriginalCoCreateInstance)) == MH_OK) {
        printf("LOG -> CoCreateInstance hooked...\n");
    }
   

    //TODO FIX PIP_ADAPTER_ADDRESES undefined issue
    std::uintptr_t GetAdaptersAddresses_Func = (std::uintptr_t)GetProcAddress(GetModuleHandleA("iphlpapi.dll"), "GetAdaptersAddresses");
    printf("LOG -> GetAdaptersAddresses Function: %llx\n", GetAdaptersAddresses_Func);
    if (MH_CreateHook((LPVOID)GetAdaptersAddresses_Func, &HookedGetAdaptersAddresses, reinterpret_cast<LPVOID*>(&OriginalGetAdaptersAddresses)) == MH_OK) {
        printf("LOG -> GetAdaptersAddresses hooked...\n");
    }
    
    std::uintptr_t GetVolumeInformation_Func = (std::uintptr_t)GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "GetFileInformationByHandle");
    printf("LOG -> GetVolumeInformation Function: %llx\n", GetVolumeInformation_Func);
    if (MH_CreateHook((LPVOID)GetVolumeInformation_Func, &HookedVolumeAddress, reinterpret_cast<LPVOID*>(&OriginalGetVolumeAddresse)) == MH_OK) {
        printf("LOG -> GetVolumeInformation hooked...\n");
    }
    
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        printf("Failed to enable hooks!\n");
    }
    else {
        printf("LOG -> All hooks enabled...\n");
    }   
    std::cout << "\n\n\nLOG -> Spoofed Mac Address " << spoofedmac.str() << "\n";
    printf("LOG -> Spoofed Volume Serial Number: 0x%llx\n", GeneratedRandomSerial);
    printf("LOG -> Guid Spoofed: {%08lx-%04x-%04x-",
        spoofedGuid.Data1,
        spoofedGuid.Data2,
        spoofedGuid.Data3);
    for (int i = 0; i < 2; ++i) printf("%02x", spoofedGuid.Data4[i]);
    printf("-");
    for (int i = 2; i < 8; ++i) printf("%02x", spoofedGuid.Data4[i]);
    printf("}\n");

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        std::cout << R"(

 __       ____     _______  ____   .__   __.  _______  
|  |     |___ \   /  _____||___ \  |  \ |  | |       \ 
|  |       __) | |  |  __    __) | |   \|  | |  .--.  |
|  |      |__ <  |  | |_ |  |__ <  |  . `  | |  |  |  |
|  `----. ___) | |  |__| |  ___) | |  |\   | |  '--'  |
|_______||____/   \______| |____/  |__| \__| |_______/ 
                                                       
)" << "\n";
        LOG("XEX Apex EADesktop Spoofer");

        DisableThreadLibraryCalls(hModule);

        if (kiero::init(kiero::RenderType::Auto) == kiero::Status::Success) {
        }
        GeneratedRandomSerial = (DWORD)(rand() % 0xFFFFFFFFF);
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint32_t> dis32(0, 0xFFFFFFFF);
        std::uniform_int_distribution<uint16_t> dis16(0, 0xFFFF);


        spoofedGuid.Data1 = dis32(gen);               // 4 bytes
        spoofedGuid.Data2 = dis16(gen);               // 2 bytes
        spoofedGuid.Data3 = dis16(gen);               // 2 bytes
        for (int i = 0; i < 8; ++i) {                 // 8 bytes
            spoofedGuid.Data4[i] = dis16(gen) & 0xFF; // Random byte
        }
        srand(static_cast<unsigned int>(time(0)));
        unsigned char mac[6];
        for (int i = 0; i < 6; ++i) mac[i] = rand() % 256;
        mac[0] = (mac[0] & 0xFE) | 0x02;

        std::stringstream hexMac;
        for (int i = 0; i < 6; ++i) {
            spoofedmac << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
            hexMac << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
            if (i < 5) spoofedmac << ":";
        }
        unsigned long long hexValue = std::stoull(hexMac.str(), nullptr, 16);
        spoofedAdaperAddress = hexValue;
        doHooks();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
