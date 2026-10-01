/*! \file
 *  \brief Registry artefacts of the second lot: Office trusted documents,
 *         Explorer's typed paths and searches, root certificates, Internet
 *         proxy settings, firewall rules.
 *
 *  Each is a small artefact of its own file, read in the copied hives; they
 *  share this header because each is a few dozen lines, and share its
 *  structure: one struct per element with toJson(), one class with getData(),
 *  toJson(), clear().
 *
 *  WHAT THEY PROVE.
 *   - Office TrustRecords: a document whose user clicked "Enable content" —
 *     with 0x7FFFFFFF at its end, "Enable macros" —, and when. The door of
 *     most macro infections.
 *   - TypedPaths: the paths typed in Explorer's address bar (a share, a USB
 *     key's folder).
 *   - WordWheelQuery: the terms searched in Explorer.
 *   - Root certificates: a root added to a store makes Windows trust whatever
 *     it signs — interception of TLS, signed malware. The SHA-1 of each
 *     certificate is checked against its key's name, the thumbprint Windows
 *     looks it up by.
 *   - Internet Settings: a proxy set for a user (traffic diverted), an
 *     automatic configuration script (a PAC served by an intruder).
 *   - Firewall rules: a port opened, a program allowed, by whom — every rule
 *     of the policy, Windows' own included.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "registry_common.h"


// ------------------------------------------------------------ Office TrustRecords

/*! Reads a TrustRecords value: when the document was trusted, and whether
 *  its macros were enabled (the value ends with 0x7FFFFFFF).
 *  @param data the value's bytes
 *  @param trustedUtc receives the instant (the first 8 bytes, a FILETIME)
 *  @param macrosEnabled receives the macro flag
 *  @return false if the value is shorter than a FILETIME and a flag */
bool parseTrustRecord(const std::vector<BYTE>& data, FILETIME& trustedUtc, bool& macrosEnabled);

/*! A document trusted by a user in an Office application. */
struct TrustRecord {
	std::wstring sid, version, application, document;
	FILETIME trustedUtc = { 0 };
	bool macrosEnabled = false;
	std::wstring data;          //!< the value, hexadecimal
	Json toJson() const;        //!< @return the record as a JSON object
};

//! Office trusted documents of every profile (office_trust_records.json).
class OfficeTrustRecords {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any record
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the records
private:
	std::vector<TrustRecord> records_;
};

// ------------------------------------------------------------ Explorer input

/*! A path typed, or a term searched, in Explorer. */
struct ExplorerInput {
	std::wstring sid;
	/*! Position in the list, 0 for the most recent: the same name and origin
	 *  as the shellbags' (it was a "Rank" from 1, a second name for one concept). */
	unsigned mruPosition = 0;
	std::wstring text;
	FILETIME keyLastWriteUtc = { 0 };   //!< the key's last write: the date of position 0
	Json toJson() const;        //!< @return the entry as a JSON object
};

//! Paths typed in Explorer's address bar (typed_paths.json).
class TypedPaths {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	std::vector<ExplorerInput> entries_;
};

//! Terms searched in Explorer (word_wheel_query.json).
class WordWheelQueries {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	std::vector<ExplorerInput> entries_;
};

// ------------------------------------------------------------ Root certificates

/*! Finds the certificate in a certificate store's Blob value: a sequence of
 *  properties (identifier, 1, length, data), the certificate being property
 *  0x20. Every length is bounded by the value.
 *  @param blob the value's bytes
 *  @param der receives the certificate's offset in `blob`
 *  @param size receives its length
 *  @return false if the Blob holds no certificate */
bool certificateInBlob(const std::vector<BYTE>& blob, size_t& der, size_t& size);

/*! A certificate of a root store. */
struct RootCertificate {
	std::wstring store, sid, thumbprint;
	std::wstring subject, organization, issuer, serialNumber;
	FILETIME notBeforeUtc = { 0 }, notAfterUtc = { 0 }, keyLastWriteUtc = { 0 };
	bool thumbprintMatches = true;   //!< the SHA-1 of the certificate is its key's name
	bool readable = true;            //!< the Blob held a certificate
	Json toJson() const;             //!< @return the certificate as a JSON object
};

//! Certificates of the machine's and users' root stores (root_certificates.json).
class RootCertificates {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	std::vector<RootCertificate> certificates_;
};

// ------------------------------------------------------------ Internet Settings

//! A user's proxy settings.
struct InternetSettings {
	std::wstring sid;
	NameValues values;               //!< ProxyEnable, ProxyServer, ProxyOverride, AutoConfigURL, AutoDetect
	FILETIME keyLastWriteUtc = { 0 };
	Json toJson() const;             //!< @return the settings as a JSON object
};

//! Proxy settings of every profile (internet_settings.json).
class InternetSettingsSet {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	std::vector<InternetSettings> settings_;
};

// ------------------------------------------------------------ Firewall

/*! Splits a firewall rule, "v2.33|Action=Allow|Active=TRUE|Dir=In|…|", into
 *  its fields; a field may repeat (several remote addresses).
 *  @param rule the value
 *  @param version receives the leading "v2.33"
 *  @return the Name/Value pairs, in order */
NameValues parseFirewallRule(const std::wstring& rule, std::wstring& version);

//! One firewall rule.
struct FirewallRule {
	std::wstring id, version;
	NameValues fields;
	Json toJson() const;             //!< @return the rule as a JSON object
};

//! Firewall rules and profile settings (firewall.json).
class Firewall {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	std::vector<FirewallRule> rules_;
	FILETIME rulesLastWriteUtc_ = { 0 };
	std::vector<std::pair<std::wstring, NameValues>> profiles_;   //!< Domain, Standard (private), Public
};
