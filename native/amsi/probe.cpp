// Purpose: Exercise Windows AMSI dispatch and owned registration with inert test inputs.
// Works with: provider.h; scripts/lab/guest; tests/integration/verify_amsi_provider.py
// Used by: the matching native executable or library entry point

// Harmless registered-provider and Windows AMSI consumer checks. No registration.
#include "provider.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

int UnregisterOwned(const wchar_t* deployment) {
    wchar_t user[128]{};
    GetEnvironmentVariableW(L"USERNAME",user,128);
    if (_wcsicmp(user,L"WDAGUtilityAccount") || GetFileAttributesW(L"C:\\SentinelAV-Test\\preflight.json")==INVALID_FILE_ATTRIBUTES)
        return 70;
    if (wcslen(deployment)!=32 || wcsspn(deployment,L"0123456789abcdef")!=32) return 71;
    constexpr wchar_t clsid[] = L"SOFTWARE\\Classes\\CLSID\\{DE3BE5B6-4DB7-4F8F-A71C-0576CDAF4581}";
    constexpr wchar_t provider[] = L"SOFTWARE\\Microsoft\\AMSI\\Providers\\{DE3BE5B6-4DB7-4F8F-A71C-0576CDAF4581}";
    for (auto path : {clsid,provider}) {
        HKEY key=nullptr;
        LONG status=RegOpenKeyExW(HKEY_LOCAL_MACHINE,path,0,KEY_READ|KEY_WOW64_64KEY,&key);
        if (status==ERROR_FILE_NOT_FOUND) continue;
        if (status!=ERROR_SUCCESS) return 72;
        wchar_t owner[64]{}; DWORD length=sizeof(owner),type=0;
        status=RegQueryValueExW(key,L"SentinelAVDeploymentId",nullptr,&type,reinterpret_cast<BYTE*>(owner),&length);
        RegCloseKey(key);
        owner[63]=L'\0';
        if (status!=ERROR_SUCCESS || type!=REG_SZ || length>sizeof(owner) || wcscmp(owner,deployment)) return 73;
    }
    // Validate both ownership markers before removing either exact key.
    for (auto path : {provider,clsid}) {
        LONG status=RegDeleteTreeW(HKEY_LOCAL_MACHINE,path);
        if (status!=ERROR_SUCCESS && status!=ERROR_FILE_NOT_FOUND) return 74;
    }
    return 0;
}

class ProbeStream final : public IAmsiStream {
    ULONG refs = 1;
    std::string bytes;
public:
    explicit ProbeStream(const char* text) : bytes(text) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IAmsiStream)) return E_NOINTERFACE;
        *out = this; AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs; }
    HRESULT STDMETHODCALLTYPE GetAttribute(AMSI_ATTRIBUTE attr, ULONG length, BYTE* out, ULONG* returned) override {
        if (attr != AMSI_ATTRIBUTE_CONTENT_SIZE) return E_NOTIMPL;
        ULONGLONG size = bytes.size();
        if (!out || !returned || length < sizeof(size)) return E_INVALIDARG;
        memcpy(out, &size, sizeof(size)); *returned = sizeof(size); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Read(ULONGLONG offset, ULONG size, BYTE* out, ULONG* returned) override {
        if (!out || !returned || offset > bytes.size()) return E_INVALIDARG;
        ULONG count = (std::min)(size, static_cast<ULONG>(bytes.size() - offset));
        memcpy(out, bytes.data() + offset, count); *returned = count; return S_OK;
    }
};

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring(argv[1]) == L"--unregister-owned") return UnregisterOwned(argv[2]);
    if (argc != 2) return 90;
    std::wstring mode(argv[1]);
    if (mode==L"--show-error") {
        HANDLE file=CreateFileW(L"C:\\SentinelAV-Test\\integration-error.txt",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr);
        if (file==INVALID_HANDLE_VALUE) return 75;
        char bytes[4097]{}; DWORD count=0;
        BOOL ok=ReadFile(file,bytes,4096,&count,nullptr); CloseHandle(file);
        if (!ok) return 76;
        int length=MultiByteToWideChar(CP_UTF8,0,bytes,count,nullptr,0);
        std::wstring text(length,L'\0');
        MultiByteToWideChar(CP_UTF8,0,bytes,count,text.data(),length);
        MessageBoxW(nullptr,text.c_str(),L"SentinelAV guest integration diagnostic",MB_OK|MB_ICONINFORMATION);
        return 0;
    }
    constexpr char marker[] = "SENTINELAV_DEMO_THREAT_7C23A";
    constexpr char ordinary[] = "Ordinary SentinelAV benign integration fixture";
    if (mode == L"--registered" || mode == L"--absent" || mode == L"--unavailable") {
        HRESULT init = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(init)) return 91;
        IAntimalwareProvider* provider = nullptr;
        HRESULT status = CoCreateInstance(CLSID_SentinelAmsi, nullptr, CLSCTX_INPROC_SERVER,
                         __uuidof(IAntimalwareProvider), reinterpret_cast<void**>(&provider));
        if (mode == L"--absent") {
            if (provider) provider->Release();
            CoUninitialize();
            return status == REGDB_E_CLASSNOTREG ? 0 : 41;
        }
        if (FAILED(status)) { CoUninitialize(); return 42; }
        ProbeStream stream(marker);
        AMSI_RESULT result = AMSI_RESULT_CLEAN;
        status = provider->Scan(&stream, &result);
        bool ok = mode == L"--unavailable" ? FAILED(status) && result == AMSI_RESULT_NOT_DETECTED
                                          : SUCCEEDED(status) && result == AMSI_RESULT_DETECTED;
        provider->Release(); CoUninitialize();
        std::cout << "{\"hresult\":" << static_cast<long>(status) << ",\"result\":" << static_cast<int>(result) << "}\n";
        return ok ? 0 : 43;
    }
    if (mode == L"--system") {
        HAMSICONTEXT context = nullptr;
        HRESULT status = AmsiInitialize(L"SentinelAV harmless integration probe", &context);
        if (FAILED(status)) return 44;
        AMSI_RESULT result = AMSI_RESULT_CLEAN;
        status = AmsiScanBuffer(context, const_cast<char*>(ordinary), sizeof(ordinary)-1, L"benign fixture", nullptr, &result);
        bool benign = SUCCEEDED(status) && !AmsiResultIsMalware(result);
        result = AMSI_RESULT_CLEAN;
        status = AmsiScanBuffer(context, const_cast<char*>(marker), sizeof(marker)-1, L"inert demo marker", nullptr, &result);
        bool detected = SUCCEEDED(status) && AmsiResultIsMalware(result);
        AmsiUninitialize(context);
        std::cout << "{\"hresult\":" << static_cast<long>(status) << ",\"result\":" << static_cast<int>(result) << "}\n";
        return benign && detected ? 0 : 45;
    }
    return 92;
}
