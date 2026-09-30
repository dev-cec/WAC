/*! \file
 *  \brief Registry artefacts of the second lot (see registry_lot2.h).
 */
#include "registry_lot2.h"
#include "authenticode.h"
#include "sha.h"

namespace {

//! The key's last write, or zero.
FILETIME lastWrite(ORHKEY key) {
	FILETIME f = { 0, 0 };
	ORQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &f);
	return f;
}

//! The names of the subkeys of `path` under `root`.
std::vector<std::wstring> subkeys(ORHKEY root, const std::wstring& path) {
	std::vector<std::wstring> names;
	ORHKEY key = NULL;
	if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) return names;
	wchar_t name[512];
	for (DWORD i = 0;; ++i) {
		DWORD length = (DWORD)(sizeof(name) / sizeof(name[0]));
		if (OREnumKey(key, i, name, &length, NULL, NULL, NULL) != ERROR_SUCCESS) break;
		names.emplace_back(name, length);
	}
	ORCloseKey(key);
	return names;
}

//! A value as text: a string as written, a DWORD as its number.
std::wstring valueText(DWORD type, const std::vector<BYTE>& data) {
	if (type == REG_SZ || type == REG_EXPAND_SZ) return readWideZ(data.data(), data.size(), 0);
	if (type == REG_DWORD && data.size() >= sizeof(DWORD)) {
		DWORD v = 0;
		memcpy(&v, data.data(), sizeof(DWORD));
		return std::to_wstring(v);
	}
	return L"";
}

//! Name/Value pairs as a JSON array.
Json pairs(const NameValues& values) {
	Json list = Json::arr();
	for (const auto& [name, value] : values) {
		Json p = Json::obj();
		p.add(L"Name", Json::str(name));
		p.add(L"Value", Json::str(value));
		list.push(std::move(p));
	}
	return list;
}

//! Writes an array of elements that have toJson().
template <class Element>
HRESULT writeList(const char* file, const std::vector<Element>& elements) {
	Json list = Json::arr();
	for (const Element& e : elements) list.push(e.toJson());
	return writeJsonFile(file, list);
}

//! What the Explorer inputs and the settings add about their user.
void addUser(Json& o, const std::wstring& sid) {
	o.add(L"SID", Json::str(sid));
	o.add(L"SIDName", Json::str(getNameFromSid(sid)));
}

const DWORD MACROS_ENABLED = 0x7FFFFFFF;   //!< last DWORD of a TrustRecords value: "Enable macros"
const DWORD CERT_CERT_PROP_ID = 0x20;      //!< the property holding the certificate, DER

} // namespace

// ------------------------------------------------------------ Office TrustRecords

bool parseTrustRecord(const std::vector<BYTE>& data, FILETIME& trustedUtc, bool& macrosEnabled) {
	if (data.size() < sizeof(FILETIME) + sizeof(DWORD)) return false;
	memcpy(&trustedUtc, data.data(), sizeof(FILETIME));
	DWORD flag = 0;
	memcpy(&flag, data.data() + data.size() - sizeof(DWORD), sizeof(DWORD));
	macrosEnabled = flag == MACROS_ENABLED;
	return true;
}

Json TrustRecord::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"Application", Json::str(application));
	o.add(L"OfficeVersion", Json::str(version));
	o.add(L"Document", Json::str(document));
	addDate(o, L"Trusted", trustedUtc);
	o.add(L"MacrosEnabled", Json::boolean(macrosEnabled));
	o.add(L"Data", Json::str(data));
	return o;
}

HRESULT OfficeTrustRecords::getData() {
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		const std::wstring office = L"Software\\Microsoft\\Office";
		for (const std::wstring& version : subkeys(root, office))
			for (const std::wstring& application : subkeys(root, office + L"\\" + version)) {
				ORHKEY key = NULL;
				const std::wstring path = office + L"\\" + version + L"\\" + application
				                        + L"\\Security\\Trusted Documents\\TrustRecords";
				if (OROpenKey(root, path.c_str(), &key) != ERROR_SUCCESS) continue;
				for (DWORD i = 0;; ++i) {
					TrustRecord r;
					DWORD type = 0;
					std::vector<BYTE> data;
					if (enumRegistryValue(key, i, r.document, type, data) != ERROR_SUCCESS) break;
					if (!parseTrustRecord(data, r.trustedUtc, r.macrosEnabled)) continue;
					r.sid = sid;
					r.version = version;
					r.application = application;
					r.data = toHexadecimal(data.data(), data.size());
					records_.push_back(std::move(r));
				}
				ORCloseKey(key);
			}
	});
	return ERROR_SUCCESS;
}

HRESULT OfficeTrustRecords::toJson() { return writeList("office_trust_records.json", records_); }
void OfficeTrustRecords::clear() { records_.clear(); }

// ------------------------------------------------------------ Explorer input

Json ExplorerInput::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	o.add(L"MruPosition", Json::num(mruPosition));
	o.add(L"Text", Json::str(text));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT TypedPaths::getData() {
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		ORHKEY key = NULL;
		if (OROpenKey(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths", &key) != ERROR_SUCCESS) return;
		const FILETIME written = lastWrite(key);
		for (DWORD i = 0;; ++i) {
			std::wstring name;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
			// url1 is the most recent: position 0.
			if (name.size() < 4 || _wcsnicmp(name.c_str(), L"url", 3) != 0
			    || name.find_first_not_of(L"0123456789", 3) != std::wstring::npos) continue;
			const unsigned number = (unsigned)std::stoul(name.substr(3).substr(0, 9));
			if (number == 0) continue;
			ExplorerInput e;
			e.sid = sid;
			e.mruPosition = number - 1;
			e.text = valueText(type, data);
			e.keyLastWriteUtc = written;
			entries_.push_back(std::move(e));
		}
		ORCloseKey(key);
	});
	return ERROR_SUCCESS;
}

HRESULT TypedPaths::toJson() { return writeList("typed_paths.json", entries_); }
void TypedPaths::clear() { entries_.clear(); }

HRESULT WordWheelQueries::getData() {
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		ORHKEY key = NULL;
		if (OROpenKey(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery", &key) != ERROR_SUCCESS) return;
		const FILETIME written = lastWrite(key);
		// The values "0", "1"… in the order of MRUListEx: the first is the most recent.
		std::vector<unsigned int> order;
		readMruListEx(key, order);
		unsigned position = 0;
		for (unsigned int id : order) {
			std::vector<BYTE> data;
			if (getRegBinaryValue(key, nullptr, std::to_wstring(id).c_str(), data) != ERROR_SUCCESS) continue;
			ExplorerInput e;
			e.sid = sid;
			e.mruPosition = position++;
			e.text = readWideZ(data.data(), data.size(), 0);   // UTF-16, bounded by the value
			e.keyLastWriteUtc = written;
			entries_.push_back(std::move(e));
		}
		ORCloseKey(key);
	});
	return ERROR_SUCCESS;
}

HRESULT WordWheelQueries::toJson() { return writeList("word_wheel_query.json", entries_); }
void WordWheelQueries::clear() { entries_.clear(); }

// ------------------------------------------------------------ Root certificates

bool certificateInBlob(const std::vector<BYTE>& blob, size_t& der, size_t& size) {
	const size_t HEADER = 3 * sizeof(DWORD);
	for (size_t at = 0; at + HEADER <= blob.size();) {
		DWORD id = 0, length = 0;
		memcpy(&id, blob.data() + at, sizeof(DWORD));
		memcpy(&length, blob.data() + at + 2 * sizeof(DWORD), sizeof(DWORD));
		if (length > blob.size() - at - HEADER) return false;   // a length that lies
		if (id == CERT_CERT_PROP_ID) { der = at + HEADER; size = length; return length > 0; }
		at += HEADER + length;
	}
	return false;
}

Json RootCertificate::toJson() const {
	Json o = Json::obj();
	o.add(L"Store", Json::str(store));
	if (!sid.empty()) addUser(o, sid);
	o.add(L"Thumbprint", Json::str(thumbprint));
	if (!readable) o.add(L"CertificateUnreadable", Json::boolean(true));
	if (!thumbprintMatches) o.add(L"ThumbprintMismatch", Json::boolean(true));
	o.add(L"Subject", Json::str(subject));
	o.add(L"Organization", Json::str(organization));
	o.add(L"Issuer", Json::str(issuer));
	o.add(L"SerialNumber", Json::str(serialNumber));
	addDate(o, L"NotBefore", notBeforeUtc);
	addDate(o, L"NotAfter", notAfterUtc);
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

namespace {

//! Reads every certificate of a store: `path` holds one subkey per thumbprint.
void readStore(ORHKEY root, const std::wstring& path, const std::wstring& store, const std::wstring& sid,
               std::vector<RootCertificate>& out) {
	for (const std::wstring& thumbprint : subkeys(root, path)) {
		ORHKEY key = NULL;
		if (OROpenKey(root, (path + L"\\" + thumbprint).c_str(), &key) != ERROR_SUCCESS) continue;
		RootCertificate c;
		c.store = store;
		c.sid = sid;
		c.thumbprint = thumbprint;
		c.keyLastWriteUtc = lastWrite(key);
		std::vector<BYTE> blob;
		size_t der = 0, size = 0;
		CertificateSummary summary;
		c.readable = getRegBinaryValue(key, nullptr, L"Blob", blob) == ERROR_SUCCESS && certificateInBlob(blob, der, size)
		          && SummarizeCertificate(blob.data() + der, size, summary);
		if (c.readable) {
			uint8_t sha1[20];
			sha1Bytes(blob.data() + der, size, sha1);
			c.thumbprintMatches = _wcsicmp(toHexadecimal(sha1, sizeof(sha1)).c_str(), thumbprint.c_str()) == 0;
			c.subject = summary.subject;
			c.organization = summary.subjectOrganization;
			c.issuer = summary.issuer;
			c.serialNumber = summary.serialNumber;
			c.notBeforeUtc = { (DWORD)summary.notBefore, (DWORD)(summary.notBefore >> 32) };
			c.notAfterUtc = { (DWORD)summary.notAfter, (DWORD)(summary.notAfter >> 32) };
		}
		ORCloseKey(key);
		out.push_back(std::move(c));
	}
}

} // namespace

HRESULT RootCertificates::getData() {
	// The machine's stores (SOFTWARE), then each user's own.
	if (conf.Software) {
		readStore(conf.Software, L"Microsoft\\SystemCertificates\\ROOT\\Certificates", L"LocalMachine\\Root", L"", certificates_);
		readStore(conf.Software, L"Microsoft\\SystemCertificates\\AuthRoot\\Certificates", L"LocalMachine\\AuthRoot", L"", certificates_);
		readStore(conf.Software, L"Microsoft\\EnterpriseCertificates\\Root\\Certificates", L"LocalMachine\\Enterprise\\Root", L"", certificates_);
		readStore(conf.Software, L"Policies\\Microsoft\\SystemCertificates\\Root\\Certificates", L"LocalMachine\\GroupPolicy\\Root", L"", certificates_);
	}
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		readStore(root, L"Software\\Microsoft\\SystemCertificates\\Root\\Certificates", L"CurrentUser\\Root", sid, certificates_);
	});
	return ERROR_SUCCESS;
}

HRESULT RootCertificates::toJson() { return writeList("root_certificates.json", certificates_); }
void RootCertificates::clear() { certificates_.clear(); }

// ------------------------------------------------------------ Internet Settings

Json InternetSettings::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	for (const auto& [name, value] : values) o.add(name, Json::str(value));
	addDate(o, L"KeyLastWrite", keyLastWriteUtc);
	return o;
}

HRESULT InternetSettingsSet::getData() {
	forEachProfileHive(L"\\ntuser.dat", [this](ORHKEY root, const std::wstring& sid) {
		ORHKEY key = NULL;
		if (OROpenKey(root, L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", &key) != ERROR_SUCCESS) return;
		InternetSettings s;
		s.sid = sid;
		s.keyLastWriteUtc = lastWrite(key);
		// The registry's names, and the JSON's (PascalCase, no abbreviation).
		const std::pair<const wchar_t*, const wchar_t*> WANTED[] = {
			{ L"ProxyEnable", L"ProxyEnable" }, { L"ProxyServer", L"ProxyServer" },
			{ L"ProxyOverride", L"ProxyOverride" }, { L"AutoConfigURL", L"AutoConfigUrl" },
			{ L"AutoDetect", L"AutoDetect" } };
		for (DWORD i = 0;; ++i) {
			std::wstring name;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
			for (const auto& [registry, json] : WANTED)
				if (_wcsicmp(name.c_str(), registry) == 0) {
					const std::wstring text = valueText(type, data);
					if (!text.empty()) s.values.emplace_back(json, text);
				}
		}
		ORCloseKey(key);
		settings_.push_back(std::move(s));
	});
	return ERROR_SUCCESS;
}

HRESULT InternetSettingsSet::toJson() { return writeList("internet_settings.json", settings_); }
void InternetSettingsSet::clear() { settings_.clear(); }

// ------------------------------------------------------------ Firewall

NameValues parseFirewallRule(const std::wstring& rule, std::wstring& version) {
	NameValues fields;
	size_t start = 0;
	bool first = true;
	while (start < rule.size()) {
		size_t bar = rule.find(L'|', start);
		if (bar == std::wstring::npos) bar = rule.size();
		const std::wstring field = rule.substr(start, bar - start);
		start = bar + 1;
		if (field.empty()) continue;
		const size_t equal = field.find(L'=');
		if (first && equal == std::wstring::npos) { version = field; first = false; continue; }
		first = false;
		if (equal == std::wstring::npos || equal == 0) continue;
		fields.emplace_back(field.substr(0, equal), field.substr(equal + 1));
	}
	return fields;
}

Json FirewallRule::toJson() const {
	Json o = Json::obj();
	o.add(L"Id", Json::str(id));
	o.add(L"Version", Json::str(version));
	/* The fields most read, under a JSON name without abbreviation, when
	   present once; every field as written stays in Fields. */
	const std::pair<const wchar_t*, const wchar_t*> NAMED[] = {
		{ L"Name", L"Name" }, { L"Action", L"Action" }, { L"Active", L"Active" }, { L"Dir", L"Direction" },
		{ L"Protocol", L"Protocol" }, { L"LPort", L"LocalPort" }, { L"RPort", L"RemotePort" },
		{ L"App", L"Application" }, { L"Svc", L"Service" } };
	for (const auto& [field, json] : NAMED) {
		unsigned count = 0;
		std::wstring value;
		for (const auto& [k, v] : fields) if (k == field) { ++count; value = v; }
		if (count == 1) o.add(json, Json::str(value));
	}
	o.add(L"Fields", pairs(fields));
	return o;
}

HRESULT Firewall::getData() {
	if (!conf.CurrentControlSet) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const std::wstring policy = L"Services\\SharedAccess\\Parameters\\FirewallPolicy";
	ORHKEY key = NULL;
	if (OROpenKey(conf.CurrentControlSet, (policy + L"\\FirewallRules").c_str(), &key) == ERROR_SUCCESS) {
		rulesLastWriteUtc_ = lastWrite(key);
		for (DWORD i = 0;; ++i) {
			FirewallRule r;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(key, i, r.id, type, data) != ERROR_SUCCESS) break;
			if (type != REG_SZ) continue;
			r.fields = parseFirewallRule(readWideZ(data.data(), data.size(), 0), r.version);
			rules_.push_back(std::move(r));
		}
		ORCloseKey(key);
	}
	for (const wchar_t* profile : { L"DomainProfile", L"StandardProfile", L"PublicProfile" }) {
		if (OROpenKey(conf.CurrentControlSet, (policy + L"\\" + profile).c_str(), &key) != ERROR_SUCCESS) continue;
		NameValues values;
		for (DWORD i = 0;; ++i) {
			std::wstring name;
			DWORD type = 0;
			std::vector<BYTE> data;
			if (enumRegistryValue(key, i, name, type, data) != ERROR_SUCCESS) break;
			const std::wstring text = valueText(type, data);
			if (!text.empty()) values.emplace_back(name, text);
		}
		ORCloseKey(key);
		profiles_.emplace_back(profile, std::move(values));
	}
	return ERROR_SUCCESS;
}

HRESULT Firewall::toJson() {
	Json o = Json::obj();
	Json profiles = Json::arr();
	for (const auto& [name, values] : profiles_) {
		Json p = Json::obj();
		p.add(L"Profile", Json::str(name));
		p.add(L"Values", pairs(values));
		profiles.push(std::move(p));
	}
	o.add(L"Profiles", std::move(profiles));
	o.add(L"RuleCount", Json::num((unsigned long long)rules_.size()));
	addDate(o, L"RulesKeyLastWrite", rulesLastWriteUtc_);
	Json list = Json::arr();
	for (const FirewallRule& r : rules_) list.push(r.toJson());
	o.add(L"Rules", std::move(list));
	return writeJsonFile("firewall.json", o);
}

void Firewall::clear() { rules_.clear(); profiles_.clear(); }
