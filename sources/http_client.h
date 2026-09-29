/*! \file
 *  \brief HTTP DOWNLOAD for --update-trust, through WinHTTP loaded at run time.
 *
 *  WHY LOADED AT RUN TIME. WAC.exe runs on the examined machine, where it must
 *  not be able to reach the network, and where every library loaded is a
 *  trace and a surface. A static import of winhttp.dll would load it at every
 *  start, in every mode; loaded by LoadLibraryExW, from System32 only, it is
 *  loaded by --update-trust alone, on the analysis workstation. The build
 *  refuses a WAC.exe that imports a network library (build-windows.sh).
 *
 *  WHY PLAIN HTTP IS ENOUGH. What --update-trust downloads is checked by what
 *  it is, not by where it comes from: Microsoft's trust lists carry their own
 *  signature, verified up to a Microsoft root embedded in WAC, and each root
 *  certificate must have the SHA-1 the signed list gives. A download altered
 *  on the way is refused, whatever the transport.
 */
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

/*! A WinHTTP session. Loads the library and opens the session on
 *  construction, closes both on destruction. */
class HttpClient {
public:
	HttpClient();
	~HttpClient();
	HttpClient(const HttpClient&) = delete;
	HttpClient& operator=(const HttpClient&) = delete;

	//! @return true if the library is loaded and the session open
	bool ready() const;
	//! @return why the session could not be opened, when ready() is false
	const std::string& reason() const { return reason_; }

	/*! Downloads a resource.
	 *  @param url the address, http:// or https://
	 *  @param body receives the content
	 *  @param maxSize limit of the content: beyond it, the download is refused
	 *  @param reason why it failed
	 *  @return true on a complete response of status 200 */
	bool get(const std::wstring& url, std::vector<uint8_t>& body, size_t maxSize, std::string& reason) const;

private:
	struct Api;
	std::unique_ptr<Api> api_;
	std::string reason_;
};
