#include "provider.h"
#include <algorithm>
#include <atomic>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {
std::atomic<long> objects{0}, locks{0}, scans{0};
constexpr DWORD magic = 0x31414d53;
constexpr DWORD timeoutMs = 3000;
constexpr wchar_t pipeName[] = L"\\\\.\\pipe\\SentinelAV.Amsi.v1";

struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
    Handle(const Handle&) = delete;
};
struct ServiceHandle {
    SC_HANDLE value;
    explicit ServiceHandle(SC_HANDLE h) : value(h) {}
    ~ServiceHandle() { if (value) CloseServiceHandle(value); }
};
#ifdef SENTINEL_AMSI_TESTING
std::wstring testPipe;
DWORD testPid = 0;
#endif

HRESULT ExpectedServer(DWORD* pid) {
#ifdef SENTINEL_AMSI_TESTING
    if (!testPipe.empty()) { *pid = testPid; return S_OK; }
#endif
    ServiceHandle manager(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!manager.value) return HRESULT_FROM_WIN32(GetLastError());
    ServiceHandle service(OpenServiceW(manager.value, L"SentinelAVProtection", SERVICE_QUERY_STATUS));
    if (!service.value) return HRESULT_FROM_WIN32(GetLastError());
    SERVICE_STATUS_PROCESS state{};
    DWORD needed = 0;
    if (!QueryServiceStatusEx(service.value, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&state), sizeof(state), &needed)) return HRESULT_FROM_WIN32(GetLastError());
    if (state.dwCurrentState != SERVICE_RUNNING || !state.dwProcessId)
        return HRESULT_FROM_WIN32(ERROR_SERVICE_NOT_ACTIVE);
    *pid = state.dwProcessId;
    return S_OK;
}

HRESULT Transfer(HANDLE pipe, bool write, void* bytes, DWORD length, ULONGLONG deadline) {
    DWORD offset = 0;
    while (offset < length) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event.value) return HRESULT_FROM_WIN32(GetLastError());
        OVERLAPPED operation{};
        operation.hEvent = event.value;
        DWORD count = 0;
        BOOL ok = write ? WriteFile(pipe, static_cast<BYTE*>(bytes) + offset, length - offset, &count, &operation)
                        : ReadFile(pipe, static_cast<BYTE*>(bytes) + offset, length - offset, &count, &operation);
        if (!ok) {
            DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) return HRESULT_FROM_WIN32(error);
            auto now = GetTickCount64();
            DWORD wait = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
            DWORD state = WaitForSingleObject(event.value, wait);
            if (state != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &count, TRUE);
                return HRESULT_FROM_WIN32(state == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_GEN_FAILURE);
            }
            if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) return HRESULT_FROM_WIN32(GetLastError());
        }
        if (!count || count > length - offset) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        offset += count;
    }
    return S_OK;
}

HRESULT Inspect(std::vector<BYTE>& content, AMSI_RESULT* result, ULONGLONG deadline) {
    DWORD expected = 0;
    HRESULT status = ExpectedServer(&expected);
    if (FAILED(status)) return status;
    const wchar_t* name = pipeName;
#ifdef SENTINEL_AMSI_TESTING
    if (!testPipe.empty()) name = testPipe.c_str();
#endif
    // Write-data only; clients cannot create another server instance with this ACL.
    HANDLE opened = INVALID_HANDLE_VALUE;
    do {
        opened = CreateFileW(name, FILE_GENERIC_READ | FILE_WRITE_DATA, 0, nullptr, OPEN_EXISTING,
                            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (opened != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY) break;
        auto now = GetTickCount64();
        if (now >= deadline || !WaitNamedPipeW(name, static_cast<DWORD>(deadline - now)))
            return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    } while (GetTickCount64() < deadline);
    Handle pipe(opened);
    if (pipe.value == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    ULONG actual = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &actual)) return HRESULT_FROM_WIN32(GetLastError());
    if (actual != expected) return E_ACCESSDENIED;
    DWORD request[3] = {magic, 1, static_cast<DWORD>(content.size())};
    status = Transfer(pipe.value, true, request, sizeof(request), deadline);
    if (SUCCEEDED(status) && !content.empty())
        status = Transfer(pipe.value, true, content.data(), static_cast<DWORD>(content.size()), deadline);
    DWORD reply[3]{};
    if (SUCCEEDED(status)) status = Transfer(pipe.value, false, reply, sizeof(reply), deadline);
    if (FAILED(status)) return status;
    if (reply[0] != magic || reply[1] != 1 || reply[2] > 2) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (reply[2] == 2) return HRESULT_FROM_WIN32(ERROR_NOT_READY);
    *result = reply[2] == 1 ? AMSI_RESULT_DETECTED : AMSI_RESULT_NOT_DETECTED;
    return S_OK;
}

class Provider final : public IAntimalwareProvider {
    std::atomic<ULONG> refs{1};
public:
    Provider() { ++objects; }
    ~Provider() { --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IAntimalwareProvider)) return E_NOINTERFACE;
        *value = static_cast<IAntimalwareProvider*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --refs; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE Scan(IAmsiStream* stream, AMSI_RESULT* result) override {
        if (!result) return E_POINTER;
        *result = AMSI_RESULT_NOT_DETECTED;
        if (!stream) return E_INVALIDARG;
        if (++scans > 4) { --scans; return HRESULT_FROM_WIN32(ERROR_BUSY); }
        struct Active { ~Active() { --scans; } } active;
        try {
            ULONGLONG deadline = GetTickCount64() + timeoutMs;
            ULONGLONG size = 0;
            ULONG returned = 0;
            HRESULT status = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(size),
                                                 reinterpret_cast<BYTE*>(&size), &returned);
            if (FAILED(status)) return status;
            if (returned != sizeof(size)) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            if (size > kMaxContent) return HRESULT_FROM_WIN32(ERROR_FILE_TOO_LARGE);
            std::vector<BYTE> bytes(static_cast<size_t>(size));
            ULONG offset = 0;
            while (offset < bytes.size()) {
                if (GetTickCount64() >= deadline) return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                ULONG count = 0, requested = (std::min)(65536UL, static_cast<ULONG>(bytes.size()) - offset);
                status = stream->Read(offset, requested, bytes.data() + offset, &count);
                if (FAILED(status)) return status;
                if (!count || count > requested) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                offset += count;
            }
            // Reject growing streams instead of silently scanning only a prefix.
            ULONGLONG finalSize = 0;
            status = stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE, sizeof(finalSize),
                                         reinterpret_cast<BYTE*>(&finalSize), &returned);
            if (FAILED(status)) return status;
            if (returned != sizeof(finalSize) || finalSize != size) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            return Inspect(bytes, result, deadline);
        } catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
          catch (...) { return E_UNEXPECTED; }
    }
    void STDMETHODCALLTYPE CloseSession(ULONGLONG) override {} // Session correlation is not yet implemented.
    HRESULT STDMETHODCALLTYPE DisplayName(LPWSTR* name) override {
        if (!name) return E_POINTER;
        constexpr wchar_t text[] = L"SentinelAV AMSI (prototype)";
        *name = static_cast<LPWSTR>(CoTaskMemAlloc(sizeof(text)));
        if (!*name) return E_OUTOFMEMORY;
        memcpy(*name, text, sizeof(text)); return S_OK;
    }
};

class Factory final : public IClassFactory {
    std::atomic<ULONG> refs{1};
public:
    Factory() { ++objects; }
    ~Factory() { --objects; }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (iid != __uuidof(IUnknown) && iid != __uuidof(IClassFactory)) return E_NOINTERFACE;
        *value = static_cast<IClassFactory*>(this); AddRef(); return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { ULONG count = --refs; if (!count) delete this; return count; }
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* outer, REFIID iid, void** value) override {
        if (!value) return E_POINTER;
        *value = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto provider = new(std::nothrow) Provider();
        if (!provider) return E_OUTOFMEMORY;
        HRESULT status = provider->QueryInterface(iid, value); provider->Release(); return status;
    }
    HRESULT STDMETHODCALLTYPE LockServer(BOOL lock) override {
        if (lock) ++locks;
        else {
            long count = locks.load();
            while (count > 0 && !locks.compare_exchange_weak(count, count - 1)) {}
        }
        return S_OK;
    }
};
} // namespace

#ifdef SENTINEL_AMSI_TESTING
void SetTestBroker(const wchar_t* name, DWORD expectedPid) { testPipe = name; testPid = expectedPid; }
#endif

STDAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void** value) {
    if (!value) return E_POINTER;
    *value = nullptr;
    if (clsid != CLSID_SentinelAmsi) return CLASS_E_CLASSNOTAVAILABLE;
    auto factory = new(std::nothrow) Factory();
    if (!factory) return E_OUTOFMEMORY;
    HRESULT status = factory->QueryInterface(iid, value); factory->Release(); return status;
}
STDAPI DllCanUnloadNow() {
    return objects == 0 && locks == 0 ? S_OK : S_FALSE;
}
