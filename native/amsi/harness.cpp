// Inert local harness. No COM/AMSI registration, script execution or registry writes.
#include "provider.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

void Require(bool ok, const char* name) { if (!ok) throw std::runtime_error(name); }

class Stream final : public IAmsiStream {
    ULONG refs = 1;
public:
    std::string data;
    ULONGLONG size;
    bool truncated = false, badCount = false, changing = false, badAttribute = false, readError = false;
    ULONG chunk = 65536, attributes = 0;
    explicit Stream(std::string value) : data(std::move(value)), size(data.size()) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IAmsiStream)) return E_NOINTERFACE;
        *value = this; AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { return --refs; } // Harness owns stack lifetime.
    HRESULT STDMETHODCALLTYPE GetAttribute(AMSI_ATTRIBUTE attr, ULONG count, BYTE* bytes, ULONG* returned) override {
        if (attr != AMSI_ATTRIBUTE_CONTENT_SIZE) return E_NOTIMPL;
        if (count < sizeof(size) || !bytes || !returned) return E_INVALIDARG;
        auto value = size + (changing && attributes++ > 0 ? 1 : 0);
        memcpy(bytes, &value, sizeof(value)); *returned = badAttribute ? 4 : sizeof(value); return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Read(ULONGLONG position, ULONG count, BYTE* bytes, ULONG* returned) override {
        if (readError) return E_ABORT;
        if (truncated || position >= data.size()) { *returned = 0; return S_OK; }
        ULONG take = (std::min)({count, chunk, static_cast<ULONG>(data.size() - position)});
        memcpy(bytes, data.data() + position, take); *returned = badCount ? count + 1 : take; return S_OK;
    }
};

IAntimalwareProvider* NewProvider() {
    IClassFactory* factory = nullptr;
    Require(SUCCEEDED(DllGetClassObject(CLSID_SentinelAmsi, __uuidof(IClassFactory), reinterpret_cast<void**>(&factory))), "factory");
    IAntimalwareProvider* provider = nullptr;
    auto status = factory->CreateInstance(nullptr, __uuidof(IAntimalwareProvider), reinterpret_cast<void**>(&provider));
    factory->Release(); Require(SUCCEEDED(status), "provider"); return provider;
}

int wmain(int argc, wchar_t** argv) {
    try {
        Require(DllCanUnloadNow() == S_OK, "initial unload state");
        auto provider = NewProvider();
        Require(DllCanUnloadNow() == S_FALSE, "active object tracked");
        LPWSTR name = nullptr; Require(SUCCEEDED(provider->DisplayName(&name)) && name, "display name"); CoTaskMemFree(name);
        Require(provider->DisplayName(nullptr) == E_POINTER, "null display output");
        AMSI_RESULT result = AMSI_RESULT_DETECTED;
        Require(provider->Scan(nullptr, &result) == E_INVALIDARG && result == AMSI_RESULT_NOT_DETECTED, "null stream");
        Stream clean("ordinary harmless text");
        Require(provider->Scan(&clean, nullptr) == E_POINTER, "null verdict");
        Stream huge(""); huge.size = static_cast<ULONGLONG>(kMaxContent) + 1;
        Require(provider->Scan(&huge, &result) == HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE), "oversized stream");
        Stream truncated("fixture"); truncated.truncated = true;
        Require(FAILED(provider->Scan(&truncated, &result)), "truncated stream");
        Stream badCount("fixture"); badCount.badCount = true;
        Require(FAILED(provider->Scan(&badCount, &result)), "oversized read count");
        Stream changing("fixture"); changing.changing = true;
        Require(FAILED(provider->Scan(&changing, &result)), "changing size");
        Stream attribute("fixture"); attribute.badAttribute = true;
        Require(FAILED(provider->Scan(&attribute, &result)), "malformed size attribute");
        Stream broken("fixture"); broken.readError = true;
        Require(provider->Scan(&broken, &result) == E_ABORT, "read error propagated");
        if (argc == 4 && std::wstring(argv[1]) == L"--broker") {
            DWORD pid = wcstoul(argv[3], nullptr, 10); SetTestBroker(argv[2], pid);
            Require(SUCCEEDED(provider->Scan(&clean, &result)) && result == AMSI_RESULT_NOT_DETECTED, "clean buffer no match");
            Stream marker("SENTINELAV_DEMO_THREAT_7C23A"); marker.chunk = 3;
            Require(SUCCEEDED(provider->Scan(&marker, &result)) && result == AMSI_RESULT_DETECTED, "real YARA marker through broker");
            Stream hash("SentinelAV native broker exact hash fixture");
            Require(SUCCEEDED(provider->Scan(&hash, &result)) && result == AMSI_RESULT_DETECTED, "real exact hash through broker");
            Stream empty("");
            Require(SUCCEEDED(provider->Scan(&empty, &result)) && result == AMSI_RESULT_NOT_DETECTED, "empty buffer");
            SetTestBroker(argv[2], pid + 1);
            Require(provider->Scan(&clean, &result) == E_ACCESSDENIED, "server PID mismatch rejected");
            SetTestBroker(L"\\\\.\\pipe\\SentinelAV.Test.Amsi.00000000000000000000000000000000", pid);
            Require(FAILED(provider->Scan(&clean, &result)) && result == AMSI_RESULT_NOT_DETECTED, "missing broker remains an error");
        }
        if (argc == 4 && (std::wstring(argv[1]) == L"--unavailable" || std::wstring(argv[1]) == L"--timeout")) {
            SetTestBroker(argv[2], wcstoul(argv[3], nullptr, 10));
            auto began = GetTickCount64();
            auto status = provider->Scan(&clean, &result);
            HRESULT expected = HRESULT_FROM_WIN32(std::wstring(argv[1]) == L"--timeout" ? ERROR_TIMEOUT : ERROR_NOT_READY);
            Require(status == expected && result == AMSI_RESULT_NOT_DETECTED, "unavailable scan remains an error");
            Require(GetTickCount64() - began < 4500, "transport timeout bound");
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--dll") {
            HMODULE module = LoadLibraryExW(argv[2], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            Require(module != nullptr, "load unregistered production DLL");
            auto factory = reinterpret_cast<HRESULT(__stdcall*)(REFCLSID,REFIID,void**)>(GetProcAddress(module,"DllGetClassObject"));
            Require(factory != nullptr && GetProcAddress(module,"DllCanUnloadNow"), "COM exports");
            Require(!GetProcAddress(module,"SetTestBroker") && !GetProcAddress(module,"DllRegisterServer"), "no test endpoint or auto-registration export");
            IAntimalwareProvider* production = nullptr;
            IClassFactory* productionFactory = nullptr;
            Require(SUCCEEDED(factory(CLSID_SentinelAmsi,__uuidof(IClassFactory),reinterpret_cast<void**>(&productionFactory))), "DLL factory");
            Require(SUCCEEDED(productionFactory->CreateInstance(nullptr,__uuidof(IAntimalwareProvider),reinterpret_cast<void**>(&production))), "DLL provider");
            Require(production->Scan(nullptr,&result)==E_INVALIDARG, "DLL stream guard");
            production->Release(); productionFactory->Release(); FreeLibrary(module);
        }
        provider->CloseSession(0); provider->Release();
        Require(DllCanUnloadNow() == S_OK, "released objects unload");
        std::cout << "PASS: native COM/stream bounds, lifetime and requested integration checks\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
