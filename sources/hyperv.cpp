/*! \file
 *  \brief The Hyper-V role (see hyperv.h).
 */
#include "hyperv.h"
#include "registry_common.h"
#include "whole_file.h"
#include <cwctype>
#include <filesystem>
#include <set>

namespace {

const uintmax_t CONFIGURATION_MAX = 64ULL * 1024 * 1024;   //!< a measured .vmcx is 70 KiB: a forged one is refused
const size_t KEY_MAX = 64, VALUE_BYTES_MAX = 8192;

//! @return true for a character of the keys measured: letters, digits, _ ' - .
bool isKeyCharacter(uint8_t c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '\'' || c == '-' || c == '.';
}

//! @return true if the bytes read as UTF-16 text: no control character, surrogates in pairs
bool isUtf16Text(const uint8_t* bytes, size_t size) {
	for (size_t i = 0; i + 1 < size; i += 2) {
		const uint16_t c = (uint16_t)(bytes[i] | bytes[i + 1] << 8);
		if (c < 0x20) return false;
		if (c >= 0xD800 && c < 0xDC00) {
			if (i + 3 >= size) return false;
			const uint16_t low = (uint16_t)(bytes[i + 2] | bytes[i + 3] << 8);
			if (low < 0xDC00 || low > 0xDFFF) return false;
			i += 2;
		}
		else if (c >= 0xDC00 && c <= 0xDFFF) return false;
	}
	return true;
}

//! A disk or a state file of a machine: the extensions of a value worth a field of its own.
bool isDiskPath(const std::wstring& value) {
	const std::wstring lower = toLower(value);
	for (const wchar_t* extension : { L".vhd", L".vhdx", L".avhd", L".avhdx", L".iso", L".vfd" }) {
		const size_t size = wcslen(extension);
		if (lower.size() > size && lower.compare(lower.size() - size, size, extension) == 0) return true;
	}
	return false;
}

/*! Reads a configuration file into one object.
 *  @param path its working copy
 *  @param original its path on the examined machine
 *  @param registered receives the configurations a data.vmcx names
 *  @return the object; its identifier and file alone when unreadable */
Json readConfiguration(const std::filesystem::path& path, const std::wstring& original, std::set<std::wstring>* registered) {
	// The identifier and the file first: an unreadable configuration still says it exists.
	Json o = Json::obj();
	o.add(L"Id", Json::str(path.stem().wstring()));
	o.add(L"File", Json::str(original));
	std::string bytes;
	if (!readWholeFile(path, CONFIGURATION_MAX, bytes)) {
		log(2, L"🔥Hyper-V configuration not read: " + path.wstring());
		return o;
	}
	const auto pairsRead = readVmcxStrings((const uint8_t*)bytes.data(), bytes.size());
	Json disks = Json::arr(), strings = Json::arr();
	for (const auto& [key, value] : pairsRead) {
		// data.vmcx also names its Resource Types, 25 on a Server 2022: Windows' own definitions, no machine.
		if (registered && toLower(std::filesystem::path(value).extension().wstring()) == L".vmcx"
		    && toLower(std::filesystem::path(value).parent_path().filename().wstring()) != L"resource types") registered->insert(value);
		if (isDiskPath(value)) disks.push(Json::str(value));
		Json s = Json::obj();
		s.add(L"Key", Json::str(key));
		s.add(L"Value", Json::str(value));
		strings.push(std::move(s));
	}
	o.add(L"DiskFiles", std::move(disks));
	o.add(L"Strings", std::move(strings));
	return o;
}

} // namespace

std::vector<std::pair<std::wstring, std::wstring>> readVmcxStrings(const uint8_t* bytes, size_t size) {
	std::vector<std::pair<std::wstring, std::wstring>> out;
	std::set<std::pair<std::wstring, std::wstring>> seen;
	for (size_t at = 0; at + 2 < size; ++at) {
		const size_t keySize = bytes[at];   // its final zero included
		if (keySize < 2 || keySize > KEY_MAX || keySize > size - at - 1) continue;
		const uint8_t* key = bytes + at + 1;
		if (key[keySize - 1] != 0) continue;
		bool wellFormed = true;
		for (size_t i = 0; i + 1 < keySize && wellFormed; ++i) wellFormed = isKeyCharacter(key[i]);
		if (!wellFormed) continue;
		const size_t lengthAt = at + 1 + keySize;
		if (size < 4 || lengthAt > size - 4) continue;
		const uint32_t length = (uint32_t)bytes[lengthAt] | (uint32_t)bytes[lengthAt + 1] << 8
		                        | (uint32_t)bytes[lengthAt + 2] << 16 | (uint32_t)bytes[lengthAt + 3] << 24;
		if (length < 2 || length % 2 || length > VALUE_BYTES_MAX || length > size - lengthAt - 4) continue;
		const uint8_t* value = bytes + lengthAt + 4;
		if (!isUtf16Text(value, length)) continue;
		std::wstring text(length / 2, L'\0');
		for (size_t i = 0; i < text.size(); ++i) text[i] = (wchar_t)(value[2 * i] | value[2 * i + 1] << 8);
		std::wstring name((const char*)key, (const char*)key + keySize - 1);
		if (seen.insert({ name, text }).second) out.emplace_back(std::move(name), std::move(text));
		at = lengthAt + 3 + length;
	}
	return out;
}

std::wstring hyperVFolder() {
	return conf.systemDrive.substr(0, 2) + L"\\ProgramData\\Microsoft\\Windows\\Hyper-V";
}

HRESULT HyperV::getData() {
	const std::wstring folder = hyperVFolder();
	std::set<std::wstring> registered, read;
	std::error_code ec;
	const std::filesystem::path data = extractedPath(folder + L"\\data.vmcx");
	if (std::filesystem::is_regular_file(data, ec)) readConfiguration(data, folder + L"\\data.vmcx", &registered);
	/* A machine kept on another folder or volume, a real host's usual case, has its
	   configuration cached in "Virtual Machines Cache": named and read without leaving
	   the host's own folder. */
	for (const wchar_t* kind : { L"Virtual Machines", L"Snapshots", L"Virtual Machines Cache" }) {
		const std::wstring sub = folder + L"\\" + kind;
		for (std::filesystem::directory_iterator it(extractedPath(sub), ec), end; !ec && it != end; it.increment(ec)) {
			if (!it->is_regular_file(ec) || toLower(it->path().extension().wstring()) != L".vmcx") continue;
			const std::wstring original = sub + L"\\" + it->path().filename().wstring();
			Json o = readConfiguration(it->path(), original, nullptr);
			o.add(L"Kind", Json::str(wcscmp(kind, L"Snapshots") == 0 ? L"Snapshot" : wcscmp(kind, L"Virtual Machines") == 0 ? L"Machine" : L"CachedMachine"));
			const std::wstring id = toLower(it->path().stem().wstring());
			// The cache's copy says where the machine really is.
			if (wcscmp(kind, L"Virtual Machines Cache") == 0)
				for (const std::wstring& path : registered)
					if (toLower(std::filesystem::path(path).stem().wstring()) == id && toLower(path).find(L"\\virtual machines cache\\") == std::wstring::npos)
						o.add(L"RegisteredFile", Json::str(path));
			machines_.push(std::move(o));
			read.insert(id);
		}
	}
	// A machine named by the host, of which no configuration was read here: its file is not taken.
	for (const std::wstring& path : registered) {
		if (read.count(toLower(std::filesystem::path(path).stem().wstring()))) continue;
		Json o = Json::obj();
		o.add(L"Kind", Json::str(L"RegisteredElsewhere"));
		o.add(L"File", Json::str(path));
		machines_.push(std::move(o));
	}
	return ERROR_SUCCESS;
}

HRESULT HyperV::toJson() { return writeJsonFile("hyperv_machines.json", machines_); }
void HyperV::clear() { machines_ = Json::arr(); }
