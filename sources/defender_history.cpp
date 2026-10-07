/*! \file
 *  \brief Microsoft Defender's detection history and quarantine (see defender_history.h).
 */
#include "conversions.h"
#include "defender_history.h"
#include "consigne.h"
#include "idList.h"
#include "sha.h"
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

//! Folders, relative to the system volume, in lower case as the manifest index is.
const wchar_t DETECTION_FOLDER[] = L"\\programdata\\microsoft\\windows defender\\scans\\history\\service\\detectionhistory\\";
const wchar_t QUARANTINE_FOLDER[] = L"\\programdata\\microsoft\\windows defender\\quarantine\\";

//! A DetectionHistory file is a few kilobytes; an entry a few hundred bytes.
const uintmax_t DESCRIPTION_MAX = 4 * 1024 * 1024;

/*! RC4 key of the quarantine, hard-coded in mpengine.dll. Published by ERNW
 *  (github.com/ernw/quarantine-formats) and N. Knežević (defender-dump);
 *  checked here by decrypting the entries Defender wrote in the test VM. */
const uint8_t QUARANTINE_KEY[256] = {
	0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86,
	0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA,
	0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18,
	0x27, 0x96, 0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53,
	0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
	0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE,
	0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8,
	0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E,
	0x3E, 0x19, 0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2, 0x57,
	0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
	0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A,
	0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC,
	0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
	0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26, 0x2E, 0x42, 0x9B,
	0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
	0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53,
};

/*! RC4 under the quarantine key, as a stream: a ResourceData of hundreds of
 *  megabytes is decrypted and fingerprinted block by block. */
class Rc4 {
public:
	Rc4() {
		for (int n = 0; n < 256; ++n) state_[n] = (uint8_t)n;
		uint8_t j = 0;
		for (int n = 0; n < 256; ++n) {
			j = (uint8_t)(j + state_[n] + QUARANTINE_KEY[n]);
			std::swap(state_[n], state_[j]);
		}
	}
	//! Decrypts `size` bytes in place, continuing the key stream.
	void apply(uint8_t* data, size_t size) {
		for (size_t n = 0; n < size; ++n) {
			i_ = (uint8_t)(i_ + 1);
			j_ = (uint8_t)(j_ + state_[i_]);
			std::swap(state_[i_], state_[j_]);
			data[n] ^= state_[(uint8_t)(state_[i_] + state_[j_])];
		}
	}
private:
	uint8_t state_[256];
	uint8_t i_ = 0, j_ = 0;
};

//! A GUID stored as Windows lays it out in memory (16 bytes).
std::wstring guidAt(const uint8_t* p) {
	GUID g;
	memcpy(&g, p, sizeof g);
	return guid_to_wstring(g);
}

//! Reads a whole exhibit, up to a bound; empty if larger or unreadable.
std::vector<uint8_t> readExhibit(const std::wstring& file, uintmax_t maximum) {
	std::error_code ec;
	const uintmax_t size = std::filesystem::file_size(file, ec);
	if (ec || size > maximum) return {};
	std::vector<uint8_t> bytes((size_t)size);
	std::ifstream in(std::filesystem::path(file), std::ios::binary);
	in.read(reinterpret_cast<char*>(bytes.data()), (std::streamsize)bytes.size());
	if (in.gcount() != (std::streamsize)bytes.size()) return {};
	return bytes;
}

// DetectionHistory field types.
const uint32_t FIELD_NUMBER32 = 0x06, FIELD_NUMBER64 = 0x08, FIELD_FILETIME = 0x0A,
               FIELD_STRING = 0x15, FIELD_GUID = 0x1E, FIELD_BAG = 0x28;
const wchar_t MAGIC_PREFIX[] = L"Magic.Version:";

//! The string of a field of type 0x15; empty for another type.
std::wstring fieldString(const DetectionField& f) {
	return f.type == FIELD_STRING ? readWideZ(f.value.data(), f.value.size(), 0) : std::wstring();
}

bool isMagic(const DetectionField& f) {
	return f.type == FIELD_STRING && fieldString(f).compare(0, wcslen(MAGIC_PREFIX), MAGIC_PREFIX) == 0;
}

/*! Reads a bag of named properties (field type 0x28): a 24-byte header, then
 *  "name length (4), name (UTF-16), type (4), value". Types 3 a 32-bit number,
 *  4 a 64-bit one — a FILETIME when the name ends with "Time" —, 5 a byte,
 *  6 a string preceded by its length. An unknown type ends the reading: its
 *  size is not known. */
void parseBag(const std::vector<uint8_t>& bag, std::vector<DetectionProperty>& out) {
	const size_t size = bag.size();
	const uint8_t* b = bag.data();
	for (size_t p = 24; fits(size, p, 4);) {
		const uint32_t nameBytes = readLittleEndian<uint32_t>(b + p);
		p += 4;
		if (nameBytes == 0 || !fits(size, p, nameBytes) || !fits(size, p + nameBytes, 4)) return;
		DetectionProperty property;
		property.name = readWideZ(b, p + nameBytes, p);
		p += nameBytes;
		const uint32_t type = readLittleEndian<uint32_t>(b + p);
		p += 4;
		if (type == 3 && fits(size, p, 4)) { property.value = Json::num(readLittleEndian<uint32_t>(b + p)); p += 4; }
		else if (type == 4 && fits(size, p, 8)) {
			const uint64_t v = readLittleEndian<uint64_t>(b + p);
			const bool time = property.name.size() > 4 && property.name.compare(property.name.size() - 4, 4, L"Time") == 0;
			property.value = time ? Json::str(timeToIso8601Utc(filetimeFromTicks(v))) : Json::num(v);
			p += 8;
		}
		else if (type == 5 && fits(size, p, 1)) { property.value = Json::num((unsigned)b[p]); p += 1; }
		else if (type == 6 && fits(size, p, 4) && fits(size, p + 4, readLittleEndian<uint32_t>(b + p))) {
			const uint32_t bytes = readLittleEndian<uint32_t>(b + p);
			property.value = Json::str(readWideZ(b, p + 4 + bytes, p + 4));
			p += 4 + bytes;
		}
		else return;
		out.push_back(std::move(property));
	}
}

/*! Names the fields of a Magic.Version 1.2 file whose position the reference
 *  confirmed; marks them in `named`.
 *  Position 3 the threat's name, 5 and 6 its severity and category (as
 *  MSFT_MpThreat gives them); each resource a Magic.Version marker then its
 *  type and path; after the resources, the quarantine entry's GUID, then at
 *  +1 CurrentThreatExecutionStatusID, +3 the account, +5 the process, +9
 *  InitialDetectionTime. A field of an unexpected type is left unnamed. */
void nameFields(const std::vector<DetectionField>& f, DefenderDetection& d, std::vector<bool>& named) {
	auto at = [&](size_t i, uint32_t type) { return i < f.size() && f[i].type == type; };
	if (at(3, FIELD_STRING)) { d.threatName = fieldString(f[3]); named[3] = true; }
	if (at(5, FIELD_NUMBER32) && f[5].value.size() == 4) { d.severityId = readLittleEndian<uint32_t>(f[5].value.data()); d.severityKnown = named[5] = true; }
	if (at(6, FIELD_NUMBER32) && f[6].value.size() == 4) { d.categoryId = readLittleEndian<uint32_t>(f[6].value.data()); d.categoryKnown = named[6] = true; }
	size_t last = 3;
	for (size_t i = 4; i + 2 < f.size(); ++i) {
		if (!isMagic(f[i]) || !at(i + 1, FIELD_STRING) || !at(i + 2, FIELD_STRING)) continue;
		d.resources.push_back({ fieldString(f[i + 1]), fieldString(f[i + 2]) });
		named[i + 1] = named[i + 2] = true;
		last = i + 2;
	}
	size_t q = last + 1;
	while (q < f.size() && !(f[q].type == FIELD_GUID && f[q].value.size() == 16)) ++q;
	if (q >= f.size()) return;
	static const uint8_t ZERO[16] = {};
	if (memcmp(f[q].value.data(), ZERO, 16) != 0) d.quarantineEntryId = guidAt(f[q].value.data());
	named[q] = true;
	if (at(q + 1, FIELD_NUMBER32) && f[q + 1].value.size() == 4) {
		d.executionStatusId = readLittleEndian<uint32_t>(f[q + 1].value.data());
		d.executionStatusKnown = named[q + 1] = true;
	}
	if (at(q + 3, FIELD_STRING)) { d.domainUser = fieldString(f[q + 3]); named[q + 3] = true; }
	if (at(q + 5, FIELD_STRING)) { d.processName = fieldString(f[q + 5]); named[q + 5] = true; }
	if (at(q + 9, FIELD_FILETIME) && f[q + 9].value.size() == 8) {
		d.initialDetectionUtc = filetimeFromTicks(readLittleEndian<uint64_t>(f[q + 9].value.data()));
		named[q + 9] = true;
	}
}

//! Upper-case hexadecimal of a value.
std::wstring hexOf(const std::vector<uint8_t>& v) {
	return toHexadecimal(v.data(), v.size());
}

//! A tag, "0x6010".
std::wstring tagText(uint32_t tag, int digits) {
	wchar_t text[16];
	swprintf(text, 16, L"0x%0*X", digits, tag);
	return text;
}

// Quarantine: identifiers (low 12 bits of the tag) confirmed against a file of known dates.
const uint16_t TAG_RESOURCE_DATA = 0x002, TAG_ATTRIBUTES = 0x00A, TAG_CREATED = 0x00F,
               TAG_MODIFIED = 0x011, TAG_SIZE = 0x012;
const size_t ENTRY_HEADER = 0x3C;

//! The field of a resource with this identifier; nullptr without one.
const QuarantineField* fieldOf(const std::vector<QuarantineField>& fields, uint16_t id) {
	for (const QuarantineField& f : fields) if ((f.tag & 0x0FFF) == id) return &f;
	return nullptr;
}

//! A 64-bit field, or false.
bool field64(const std::vector<QuarantineField>& fields, uint16_t id, uint64_t& v) {
	const QuarantineField* f = fieldOf(fields, id);
	if (!f || f->value.size() != 8) return false;
	v = readLittleEndian<uint64_t>(f->value.data());
	return true;
}

/*! Reads one resource of an entry's third part, at `start`: its path
 *  (UTF-16), the number of its fields (2 bytes), its type (ASCII), then each
 *  field "size (2), tag (2), value", aligned on 4 bytes from the resource. */
bool parseResource(const uint8_t* d, size_t size, size_t start, QuarantineResource& r) {
	std::wstring path = readWideZ(d, size, start);
	size_t p = start + (path.size() + 1) * 2;
	if (!fits(size, p, 2)) return false;
	if (path.compare(0, 4, L"\\\\?\\") == 0) path.erase(0, 4);
	r.path = std::move(path);
	const uint16_t count = readLittleEndian<uint16_t>(d + p);
	p += 2;
	const std::string type = readNarrowZ(d, size, p);
	r.type = decodeText(type, CP_UTF8);
	p += type.size() + 1;
	p += (4 - (p - start) % 4) % 4;
	for (uint16_t n = 0; n < count; ++n) {
		if (!fits(size, p, 4)) return false;
		QuarantineField f;
		const uint16_t length = readLittleEndian<uint16_t>(d + p);
		f.tag = readLittleEndian<uint16_t>(d + p + 2);
		p += 4;
		if (!fits(size, p, length)) return false;
		f.value.assign(d + p, d + p + length);
		p += length;
		p += (4 - (p - start) % 4) % 4;
		r.fields.push_back(std::move(f));
	}
	return true;
}

/*! Decrypts a ResourceData exhibit block by block and fingerprints the file
 *  it holds, never writing it: its offset is known once the header and the
 *  security descriptor are decrypted.
 *  @return false if unreadable or if its lengths do not fit in it */
bool fingerprintContent(const std::wstring& file, QuarantineResource& r) {
	std::error_code ec;
	const uintmax_t total = std::filesystem::file_size(file, ec);
	if (ec) return false;
	std::ifstream in(std::filesystem::path(file), std::ios::binary);
	Rc4 rc4;
	std::vector<uint8_t> head;                   // the decrypted start, until the content's offset is known
	size_t offset = 0;
	uint64_t length = 0;
	bool located = false;
	uint64_t position = 0, hashed = 0;
	Sha1Stream sha1;
	Sha256Stream sha256;
	std::vector<uint8_t> block(1 << 20);
	while (position < total) {
		in.read(reinterpret_cast<char*>(block.data()), (std::streamsize)block.size());
		const size_t got = (size_t)in.gcount();
		if (got == 0) return false;
		rc4.apply(block.data(), got);
		if (!located) {
			head.insert(head.end(), block.begin(), block.begin() + got);
			// The security descriptor's length is at 8; the content's length follows it.
			if (head.size() >= 12 && head.size() >= (size_t)readLittleEndian<uint32_t>(head.data() + 8) + 0x24) {
				if (!quarantinedContent(head, total, offset, length)) return false;
				located = true;
				const size_t available = head.size() > offset ? (size_t)std::min<uint64_t>(head.size() - offset, length) : 0;
				sha1.update(head.data() + offset, available);
				sha256.update(head.data() + offset, available);
				hashed = available;
				head.clear();
			}
		}
		else {
			const uint64_t blockStart = position;
			const uint64_t from = std::max<uint64_t>(blockStart, offset + hashed);
			const uint64_t to = std::min<uint64_t>(blockStart + got, (uint64_t)offset + length);
			if (to > from) {
				sha1.update(block.data() + (from - blockStart), (size_t)(to - from));
				sha256.update(block.data() + (from - blockStart), (size_t)(to - from));
				hashed += to - from;
			}
		}
		position += got;
		if (located && hashed == length) break;
	}
	if (!located || hashed != length) return false;
	r.contentRead = true;
	r.contentSize = length;
	r.contentSha1 = sha1.hexDigest();
	r.contentSha256 = sha256.hexDigest();
	return true;
}

} // namespace

std::vector<uint8_t> defenderDecrypt(const uint8_t* data, size_t size) {
	std::vector<uint8_t> clear(data, data + size);
	Rc4().apply(clear.data(), clear.size());
	return clear;
}

// ------------------------------------------------------------ DetectionHistory

Json DetectionField::valueToJson() const {
	const uint8_t* v = value.data();
	if (type == FIELD_NUMBER32 && value.size() == 4) return Json::num(readLittleEndian<uint32_t>(v));
	if (type == FIELD_NUMBER64 && value.size() == 8) return Json::num(readLittleEndian<uint64_t>(v));
	if (type == FIELD_FILETIME && value.size() == 8) return Json::str(timeToIso8601Utc(filetimeFromTicks(readLittleEndian<uint64_t>(v))));
	if (type == FIELD_STRING) return Json::str(fieldString(*this));
	if (type == FIELD_GUID && value.size() == 16) return Json::str(guidAt(v));
	return Json::str(hexOf(value));
}

bool parseDetectionHistory(const std::vector<uint8_t>& bytes, DefenderDetection& d) {
	std::vector<DetectionField> fields;
	const size_t size = bytes.size();
	for (size_t p = 0; fits(size, p, 8);) {
		DetectionField f;
		const uint32_t length = readLittleEndian<uint32_t>(bytes.data() + p);
		f.type = readLittleEndian<uint32_t>(bytes.data() + p + 4);
		f.offset = p;
		if (!fits(size, p + 8, length)) break;          // truncated: what precedes is kept
		f.value.assign(bytes.begin() + p + 8, bytes.begin() + p + 8 + length);
		fields.push_back(std::move(f));
		p += 8 + (size_t)length;
		p += (8 - p % 8) % 8;
	}
	// The header: the threat's identifier, then the detection's.
	if (fields.size() < 3 || fields[0].type != FIELD_NUMBER64 || fields[0].value.size() != 8
	    || fields[1].type != FIELD_GUID || fields[1].value.size() != 16 || !isMagic(fields[2]))
		return false;
	d.threatId = readLittleEndian<uint64_t>(fields[0].value.data());
	d.detectionId = guidAt(fields[1].value.data());
	d.magicVersion = fieldString(fields[2]).substr(wcslen(MAGIC_PREFIX));
	std::vector<bool> named(fields.size(), false);
	named[0] = named[1] = true;
	if (d.magicVersion == L"1.2") nameFields(fields, d, named);
	for (size_t i = 0; i < fields.size(); ++i) {
		if (fields[i].type == FIELD_BAG) parseBag(fields[i].value, d.threatTracking);
		else if (!named[i] && !isMagic(fields[i])) d.unnamed.push_back(fields[i]);
	}
	return true;
}

Json DefenderDetection::toJson() const {
	Json o = Json::obj();
	o.add(L"File", Json::str(file));
	o.add(L"MagicVersion", Json::str(magicVersion));
	o.add(L"DetectionId", Json::str(detectionId));
	o.add(L"ThreatId", Json::num(threatId));
	o.add(L"ThreatName", Json::str(threatName));
	if (severityKnown) o.add(L"SeverityId", Json::num(severityId));
	if (categoryKnown) o.add(L"CategoryId", Json::num(categoryId));
	if (!resources.empty()) {
		Json list = Json::arr();
		for (const DetectionResource& r : resources) {
			Json item = Json::obj();
			item.add(L"Type", Json::str(r.type));
			item.add(L"Path", Json::str(r.path));
			list.push(std::move(item));
		}
		o.add(L"Resources", std::move(list));
	}
	addDate(o, L"InitialDetection", initialDetectionUtc);
	o.add(L"DomainUser", Json::str(domainUser));
	o.add(L"ProcessName", Json::str(processName));
	if (executionStatusKnown) o.add(L"CurrentThreatExecutionStatusId", Json::num(executionStatusId));
	o.add(L"QuarantineEntryId", Json::str(quarantineEntryId));
	if (!threatTracking.empty()) {
		Json list = Json::arr();
		for (const DetectionProperty& p : threatTracking) {
			Json item = Json::obj();
			item.add(L"Name", Json::str(p.name));
			item.add(L"Value", Json(p.value));
			list.push(std::move(item));
		}
		o.add(L"ThreatTracking", std::move(list));
	}
	if (!unnamed.empty()) {
		Json list = Json::arr();
		for (const DetectionField& f : unnamed) {
			Json item = Json::obj();
			item.add(L"Offset", Json::num((unsigned long long)f.offset));
			item.add(L"Type", Json::str(tagText(f.type, 2)));
			item.add(L"Value", f.valueToJson());
			list.push(std::move(item));
		}
		o.add(L"UnnamedFields", std::move(list));
	}
	return o;
}

HRESULT DefenderDetections::getData() {
	log(0, L"ℹ️Defender detection history :");
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (exhibit.workingFile.empty() || key.size() < 3 || key.compare(2, wcslen(DETECTION_FOLDER), DETECTION_FOLDER) != 0) continue;
		const std::vector<uint8_t> bytes = readExhibit(exhibit.workingFile, DESCRIPTION_MAX);
		DefenderDetection d;
		d.file = exhibit.sourcePath;
		if (bytes.empty() || !parseDetectionHistory(bytes, d)) {
			log(2, L"🔥Not a DetectionHistory file: " + exhibit.sourcePath);
			continue;
		}
		detections_.push_back(std::move(d));
	}
	return ERROR_SUCCESS;
}

HRESULT DefenderDetections::toJson() {
	Json list = Json::arr();
	for (const DefenderDetection& d : detections_) list.push(d.toJson());
	return writeJsonFile("defender_detections.json", list);
}

void DefenderDetections::clear() {
	detections_.clear();
}

// ------------------------------------------------------------ Quarantine

bool quarantinedContent(const std::vector<uint8_t>& head, uint64_t total, size_t& offset, uint64_t& size) {
	if (!fits(head.size(), 8, 4)) return false;
	const size_t descriptor = readLittleEndian<uint32_t>(head.data() + 8);
	if (!fits(head.size(), descriptor + 0x1C, 8)) return false;
	size = readLittleEndian<uint64_t>(head.data() + descriptor + 0x1C);
	offset = 0x28 + descriptor;
	return offset <= total && size <= total - offset;
}

std::wstring QuarantineResource::resourceDataSha1() const {
	const QuarantineField* f = fieldOf(fields, TAG_RESOURCE_DATA);
	return f && f->value.size() == 20 ? hexOf(f->value) : std::wstring();
}

Json QuarantineResource::toJson() const {
	Json o = Json::obj();
	o.add(L"Type", Json::str(type));
	o.add(L"Path", Json::str(path));
	o.add(L"ResourceDataSha1", Json::str(resourceDataSha1()));
	uint64_t v = 0;
	if (field64(fields, TAG_SIZE, v)) o.add(L"Size", Json::num(v));
	if (field64(fields, TAG_CREATED, v)) addDate(o, L"Created", filetimeFromTicks(v));
	if (field64(fields, TAG_MODIFIED, v)) addDate(o, L"Modified", filetimeFromTicks(v));
	const QuarantineField* attributes = fieldOf(fields, TAG_ATTRIBUTES);
	if (attributes && attributes->value.size() == 4)
		o.add(L"Attributes", Json::str(FileAttributes(readLittleEndian<uint32_t>(attributes->value.data())).to_wstring()));
	Json others = Json::arr();
	for (const QuarantineField& f : fields) {
		const uint16_t id = f.tag & 0x0FFF;
		if (id == TAG_RESOURCE_DATA || id == TAG_SIZE || id == TAG_CREATED || id == TAG_MODIFIED || id == TAG_ATTRIBUTES) continue;
		Json item = Json::obj();
		item.add(L"Tag", Json::str(tagText(f.tag, 4)));
		// Type 2 a UTF-16 string, 3 a 32-bit number, 5 and 6 a 64-bit one (6 also holds the dates).
		const unsigned kind = f.tag >> 12;
		if (kind == 2) item.add(L"Value", Json::str(readWideZ(f.value.data(), f.value.size(), 0)));
		else if (kind == 3 && f.value.size() == 4) item.add(L"Value", Json::num(readLittleEndian<uint32_t>(f.value.data())));
		else if ((kind == 5 || kind == 6) && f.value.size() == 8) item.add(L"Value", Json::num(readLittleEndian<uint64_t>(f.value.data())));
		else item.add(L"Value", Json::str(hexOf(f.value)));
		others.push(std::move(item));
	}
	if (!others.empty()) o.add(L"OtherFields", std::move(others));
	if (contentRead) {
		o.add(L"ContentSize", Json::num(contentSize));
		o.add(L"ContentSha1", Json::str(contentSha1));
		o.add(L"ContentSha256", Json::str(contentSha256));
	}
	return o;
}

Json QuarantineEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"File", Json::str(file));
	o.add(L"EntryId", Json::str(entryId));
	o.add(L"ThreatId", Json::num(threatId));
	o.add(L"ThreatName", Json::str(threatName));
	addDate(o, L"Quarantined", quarantinedUtc);
	Json list = Json::arr();
	for (const QuarantineResource& r : resources) list.push(r.toJson());
	o.add(L"Resources", std::move(list));
	return o;
}

bool parseQuarantineEntry(const std::vector<uint8_t>& bytes, QuarantineEntry& entry) {
	if (bytes.size() < ENTRY_HEADER) return false;
	const std::vector<uint8_t> header = defenderDecrypt(bytes.data(), ENTRY_HEADER);
	const size_t first = readLittleEndian<uint32_t>(header.data() + 0x28), second = readLittleEndian<uint32_t>(header.data() + 0x2C);
	if (!fits(bytes.size(), ENTRY_HEADER, first) || !fits(bytes.size(), ENTRY_HEADER + first, second)) return false;
	// The threat: its identifier, the instant of the quarantine, its name.
	const std::vector<uint8_t> threat = defenderDecrypt(bytes.data() + ENTRY_HEADER, first);
	if (threat.size() < 0x34) return false;
	entry.threatId = readLittleEndian<uint64_t>(threat.data());
	entry.quarantinedUtc = filetimeFromTicks(readLittleEndian<uint64_t>(threat.data() + 0x20));
	entry.threatName = decodeText(readNarrowZ(threat.data(), threat.size(), 0x34), CP_UTF8);
	// The resources: their number, their offsets, each one.
	const std::vector<uint8_t> list = defenderDecrypt(bytes.data() + ENTRY_HEADER + first, second);
	if (list.size() < 4) return false;
	const size_t count = readLittleEndian<uint32_t>(list.data());
	if (count > (list.size() - 4) / 4) return false;
	for (size_t n = 0; n < count; ++n) {
		QuarantineResource r;
		if (parseResource(list.data(), list.size(), readLittleEndian<uint32_t>(list.data() + 4 + 4 * n), r)) entry.resources.push_back(std::move(r));
	}
	return true;
}

HRESULT DefenderQuarantine::getData() {
	log(0, L"ℹ️Defender quarantine :");
	const auto& index = ExhibitStoreIndex();
	const std::wstring entries = std::wstring(QUARANTINE_FOLDER) + L"entries\\";
	for (const auto& [key, exhibit] : index) {
		if (exhibit.workingFile.empty() || key.size() < 3 || key.compare(2, entries.size(), entries) != 0) continue;
		const std::vector<uint8_t> bytes = readExhibit(exhibit.workingFile, DESCRIPTION_MAX);
		QuarantineEntry entry;
		entry.file = exhibit.sourcePath;
		entry.entryId = std::filesystem::path(exhibit.sourcePath).filename().wstring();
		if (bytes.empty() || !parseQuarantineEntry(bytes, entry)) {
			log(2, L"🔥Quarantine entry not read: " + exhibit.sourcePath);
			continue;
		}
		// The removed file, by the SHA-1 naming its ResourceData on the same volume.
		for (QuarantineResource& r : entry.resources) {
			const std::wstring sha1 = toLower(r.resourceDataSha1());
			if (sha1.size() != 40) continue;
			const auto data = index.find(key.substr(0, 2) + QUARANTINE_FOLDER + L"resourcedata\\" + sha1.substr(0, 2) + L"\\" + sha1);
			if (data != index.end() && !data->second.workingFile.empty() && !fingerprintContent(data->second.workingFile, r))
				log(2, L"🔥Quarantined content not read: " + data->second.sourcePath);
		}
		entries_.push_back(std::move(entry));
	}
	return ERROR_SUCCESS;
}

HRESULT DefenderQuarantine::toJson() {
	Json list = Json::arr();
	for (const QuarantineEntry& e : entries_) list.push(e.toJson());
	return writeJsonFile("defender_quarantine.json", list);
}

void DefenderQuarantine::clear() {
	entries_.clear();
}
