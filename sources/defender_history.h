/*! \file
 *  \brief Microsoft Defender's detection history and quarantine:
 *         `\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory`
 *         and `…\Windows Defender\Quarantine`.
 *
 *  WHAT THEY PROVE. One DetectionHistory file per detection: the threat, the
 *  file or key it was found in, the process that touched it, the account, and
 *  when. It outlives the event log: a detection whose events were cleared is
 *  still there. The quarantine keeps what Defender removed — the file's
 *  original path, its dates and attributes, and its content.
 *
 *  THE DETECTIONHISTORY FORMAT, undocumented, established on Defender
 *  4.18.26080 (Magic.Version 1.2) against MSFT_MpThreatDetection on two
 *  detections that differ: a sequence of fields, each "size (4 bytes), type
 *  (4 bytes), value", aligned on 8 bytes. Types 0x06 a 32-bit number, 0x08 a
 *  64-bit one, 0x0A a FILETIME, 0x15 a UTF-16 string, 0x1E a GUID, 0x28 a
 *  bag of NAMED properties (ThreatTrackingSha1, …ThreatTrackingStartTime…).
 *  Only the fields whose position the reference confirmed are named; every
 *  other one is given as read — offset, type, value — without a meaning
 *  made up. Two fields that both follow DetectionSourceTypeID, two dates that
 *  both equal RemediationTime, stay unnamed for that reason.
 *  Defender of Windows 8.1 writes the same fields without any Magic.Version
 *  marker — the threat's name comes right after the detection's GUID, a
 *  resource is its type and path alone —, established the same way against
 *  MSFT_MpThreat and MSFT_MpThreatDetection on two detections.
 *
 *  THE QUARANTINE, established the same way against a file of known dates.
 *  Entries\{GUID} describes a quarantine: three parts, each encrypted with
 *  RC4 under a fixed key found in mpengine.dll (published: ERNW,
 *  "quarantine-formats"; N. Knežević, "defender-dump"). ResourceData\xx\<SHA-1>
 *  holds the removed file, encrypted the same way. The exhibits are copied
 *  AS THEY ARE, encrypted: nothing malicious is written in clear, on the
 *  collection medium or on the analysis workstation (user decision
 *  2026-09-30). The content is decrypted in memory only, for its size and
 *  fingerprints.
 */
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "tools.h"

/*! Decrypts a part of a quarantine file: RC4 under Defender's fixed key,
 *  each part from the start of the key stream.
 *  @param data the encrypted bytes
 *  @param size their number
 *  @return the bytes in clear */
std::vector<uint8_t> defenderDecrypt(const uint8_t* data, size_t size);

// ------------------------------------------------------------ DetectionHistory

/*! A field of a DetectionHistory file, as read. */
struct DetectionField {
	size_t offset = 0;        //!< in the file
	uint32_t type = 0;        //!< 0x06, 0x08, 0x0A, 0x15, 0x1E, 0x28, or other
	std::vector<uint8_t> value;
	//! @return the value as JSON: number, date, string, GUID, or hexadecimal
	Json valueToJson() const;
};

/*! A property of a named bag (type 0x28), such as ThreatTrackingSha256. */
struct DetectionProperty {
	std::wstring name;
	Json value = Json::null();
};

/*! A resource of a detection: its type ("file", "regkey", "process"…) and path. */
struct DetectionResource {
	std::wstring type, path;
};

/*! A detection of Microsoft Defender. */
struct DefenderDetection {
	std::wstring file;                    //!< the DetectionHistory file on the examined machine
	std::wstring magicVersion;            //!< "1.2": the version the named fields were established on; none on Windows 8.1
	std::wstring detectionId, threatName, quarantineEntryId, domainUser, processName;
	uint64_t threatId = 0;
	bool severityKnown = false, categoryKnown = false, executionStatusKnown = false;
	uint32_t severityId = 0, categoryId = 0, executionStatusId = 0;
	FILETIME initialDetectionUtc = { 0 };
	std::vector<DetectionResource> resources;
	std::vector<DetectionProperty> threatTracking;
	std::vector<DetectionField> unnamed;  //!< every other field, as read
	Json toJson() const;                  //!< @return the detection as a JSON object
};

/*! Reads a DetectionHistory file. Every read is bounded by the file.
 *  @param bytes the file
 *  @param detection receives what was read
 *  @return false if the file is not a DetectionHistory file */
bool parseDetectionHistory(const std::vector<uint8_t>& bytes, DefenderDetection& detection);

//! Defender's detections (defender_detections.json).
class DefenderDetections {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any detection
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the detections
private:
	std::vector<DefenderDetection> detections_;
};

// ------------------------------------------------------------ Quarantine

/*! A field of a quarantined resource: tag (type in the high 4 bits, identifier
 *  in the low 12) and value. */
struct QuarantineField {
	uint16_t tag = 0;
	std::vector<uint8_t> value;
};

/*! A resource of a quarantine entry: the file, or the key, removed. */
struct QuarantineResource {
	std::wstring type, path;
	std::vector<QuarantineField> fields;
	// The content, decrypted in memory from its ResourceData exhibit.
	bool contentRead = false;
	uint64_t contentSize = 0;
	std::wstring contentSha1, contentSha256;
	/*! @return the SHA-1 naming its ResourceData file, upper case; empty without one */
	std::wstring resourceDataSha1() const;
	Json toJson() const;        //!< @return the resource as a JSON object
};

/*! A quarantine entry (Entries\{GUID}). */
struct QuarantineEntry {
	std::wstring file;          //!< the entry on the examined machine
	std::wstring entryId;       //!< the file's name, the GUID DetectionHistory cites
	uint64_t threatId = 0;
	std::wstring threatName;
	FILETIME quarantinedUtc = { 0 };
	std::vector<QuarantineResource> resources;
	Json toJson() const;        //!< @return the entry as a JSON object
};

/*! Reads a quarantine entry. Every length it announces is bounded by the file.
 *  @param bytes the file, encrypted
 *  @param entry receives what was read
 *  @return false if the file is shorter than its header says */
bool parseQuarantineEntry(const std::vector<uint8_t>& bytes, QuarantineEntry& entry);

/*! Finds the removed file in a decrypted ResourceData: after a header and the
 *  file's security descriptor, its length (8 bytes) then its bytes.
 *  @param head the start of the ResourceData, decrypted: at least up to the length
 *  @param total the ResourceData's size
 *  @param offset receives the content's offset
 *  @param size receives its length
 *  @return false if a length does not fit in `head`, or the content in `total` */
bool quarantinedContent(const std::vector<uint8_t>& head, uint64_t total, size_t& offset, uint64_t& size);

//! Defender's quarantine (defender_quarantine.json).
class DefenderQuarantine {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any entry
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<QuarantineEntry> entries_;
};
