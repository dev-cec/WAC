/*! \file
 *  \brief HTTP download through WinHTTP loaded at run time (see http_client.h).
 */
#include "http_client.h"
#include <windows.h>
#include <winhttp.h>
#include <algorithm>

/*! The WinHTTP functions used, resolved by GetProcAddress. The declarations of
 *  winhttp.h only give their types: decltype takes no address, hence imports
 *  nothing. */
struct HttpClient::Api {
	HMODULE module = nullptr;
	HINTERNET session = nullptr;
	decltype(&WinHttpOpen) open = nullptr;
	decltype(&WinHttpSetTimeouts) setTimeouts = nullptr;
	decltype(&WinHttpCrackUrl) crackUrl = nullptr;
	decltype(&WinHttpConnect) connect = nullptr;
	decltype(&WinHttpOpenRequest) openRequest = nullptr;
	decltype(&WinHttpSendRequest) sendRequest = nullptr;
	decltype(&WinHttpReceiveResponse) receiveResponse = nullptr;
	decltype(&WinHttpQueryHeaders) queryHeaders = nullptr;
	decltype(&WinHttpReadData) readData = nullptr;
	decltype(&WinHttpCloseHandle) closeHandle = nullptr;
};

namespace {

//! Resolves one export into `target`. @return false if absent
template <typename F>
bool resolve(HMODULE module, const char* name, F& target) {
	target = reinterpret_cast<F>(reinterpret_cast<void*>(GetProcAddress(module, name)));
	return target != nullptr;
}

//! "text: error N", the last Win32 error appended.
std::string failure(const char* text) {
	return std::string(text) + ": error " + std::to_string(GetLastError());
}

// Timeouts, in milliseconds: name resolution, connection, sending, receiving.
const int RESOLVE_TIMEOUT = 15000, CONNECT_TIMEOUT = 15000, SEND_TIMEOUT = 30000, RECEIVE_TIMEOUT = 60000;
const DWORD READ_BLOCK = 64 * 1024;

} // namespace

HttpClient::HttpClient() : api_(new Api) {
	// From System32 only: a winhttp.dll planted next to WAC.exe is not loaded.
	api_->module = LoadLibraryExW(L"winhttp.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!api_->module) { reason_ = failure("winhttp.dll not loaded"); return; }
	Api& a = *api_;
	if (!resolve(a.module, "WinHttpOpen", a.open) || !resolve(a.module, "WinHttpSetTimeouts", a.setTimeouts)
	    || !resolve(a.module, "WinHttpCrackUrl", a.crackUrl) || !resolve(a.module, "WinHttpConnect", a.connect)
	    || !resolve(a.module, "WinHttpOpenRequest", a.openRequest)
	    || !resolve(a.module, "WinHttpSendRequest", a.sendRequest)
	    || !resolve(a.module, "WinHttpReceiveResponse", a.receiveResponse)
	    || !resolve(a.module, "WinHttpQueryHeaders", a.queryHeaders)
	    || !resolve(a.module, "WinHttpReadData", a.readData)
	    || !resolve(a.module, "WinHttpCloseHandle", a.closeHandle)) {
		reason_ = "winhttp.dll without an expected function";
		return;
	}
	// The system's proxy settings: an analysis workstation often has one.
	a.session = a.open(L"WAC-update-trust", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
	                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!a.session)          // before Windows 8.1, and under some wine versions
		a.session = a.open(L"WAC-update-trust", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (!a.session) { reason_ = failure("WinHTTP session not opened"); return; }
	if (!a.setTimeouts(a.session, RESOLVE_TIMEOUT, CONNECT_TIMEOUT, SEND_TIMEOUT, RECEIVE_TIMEOUT)) {
		reason_ = failure("WinHTTP timeouts not set");
		a.closeHandle(a.session);
		a.session = nullptr;
	}
}

HttpClient::~HttpClient() {
	if (api_->session) api_->closeHandle(api_->session);
	if (api_->module) FreeLibrary(api_->module);
}

bool HttpClient::ready() const {
	return api_->session != nullptr;
}

bool HttpClient::get(const std::wstring& url, std::vector<uint8_t>& body, size_t maxSize, std::string& reason) const {
	body.clear();
	if (!ready()) { reason = reason_; return false; }
	const Api& a = *api_;
	URL_COMPONENTS parts = {};
	parts.dwStructSize = sizeof(parts);
	parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = (DWORD)-1;
	if (!a.crackUrl(url.c_str(), (DWORD)url.size(), 0, &parts)) { reason = failure("address not understood"); return false; }
	if (parts.nScheme != INTERNET_SCHEME_HTTP && parts.nScheme != INTERNET_SCHEME_HTTPS) {
		reason = "neither http nor https";
		return false;
	}
	const std::wstring host(parts.lpszHostName, parts.dwHostNameLength);
	const std::wstring path = std::wstring(parts.lpszUrlPath, parts.dwUrlPathLength)
	                        + std::wstring(parts.lpszExtraInfo, parts.dwExtraInfoLength);

	// The three handles, closed in reverse order whatever the way out.
	struct Handles {
		const Api& api;
		HINTERNET connection = nullptr, request = nullptr;
		~Handles() {
			if (request) api.closeHandle(request);
			if (connection) api.closeHandle(connection);
		}
	} h{ a };
	h.connection = a.connect(a.session, host.c_str(), parts.nPort, 0);
	if (!h.connection) { reason = failure("connection failed"); return false; }
	h.request = a.openRequest(h.connection, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
	                          WINHTTP_DEFAULT_ACCEPT_TYPES,
	                          parts.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0);
	if (!h.request) { reason = failure("request not opened"); return false; }
	if (!a.sendRequest(h.request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
		reason = failure("request not sent");
		return false;
	}
	if (!a.receiveResponse(h.request, nullptr)) { reason = failure("no response"); return false; }
	DWORD status = 0, statusSize = sizeof(status);
	if (!a.queryHeaders(h.request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
	                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
		reason = failure("status not read");
		return false;
	}
	if (status != 200) { reason = "HTTP status " + std::to_string(status); return false; }
	for (;;) {
		const size_t at = body.size();
		if (at >= maxSize) {       // one byte more than allowed would be refused: probe for it
			uint8_t probe;
			DWORD read = 0;
			if (!a.readData(h.request, &probe, 1, &read)) { reason = failure("read failed"); return false; }
			if (read) { reason = "larger than " + std::to_string(maxSize) + " bytes"; body.clear(); return false; }
			return true;
		}
		const DWORD block = (DWORD)std::min<size_t>(READ_BLOCK, maxSize - at);
		body.resize(at + block);
		DWORD read = 0;
		if (!a.readData(h.request, body.data() + at, block, &read)) {
			reason = failure("read failed");
			body.clear();
			return false;
		}
		body.resize(at + read);
		if (read == 0) return true;                        // end of the response
	}
}
