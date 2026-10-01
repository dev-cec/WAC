/*! \file
 *  \brief The $MFT of the system volume, read from its exhibit (see mft.h).
 */
#include "mft.h"
#include "consigne.h"
#include "idList.h"
#include "raw_hive.h"
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

// Layout of a FILE record (the NTFS documentation of the Linux-NTFS project).
const size_t RECORD_SEQUENCE = 0x10;       //!< uint16 sequence number
const size_t RECORD_ATTRIBUTES = 0x14;     //!< uint16 offset of the first attribute
const size_t RECORD_FLAGS = 0x16;          //!< uint16: 0x01 in use, 0x02 directory
const size_t RECORD_USED_SIZE = 0x18;      //!< uint32 bytes used in the record
const size_t RECORD_ALLOCATED_SIZE = 0x1C; //!< uint32 bytes of the record
const size_t RECORD_BASE = 0x20;           //!< uint64 reference of the base record, 0 for a base record
const uint32_t ATTRIBUTE_END = 0xFFFFFFFF;
const uint32_t STANDARD_INFORMATION = 0x10, FILE_NAME = 0x30, DATA = 0x80;
const size_t SI_SECURITY_ID = 0x34;      //!< uint32 in $STANDARD_INFORMATION: number of the descriptor in $Secure
const uint64_t ROOT_ENTRY = 5;             //!< the root directory's record
const uint64_t REFERENCE_ENTRY_MASK = 0x0000FFFFFFFFFFFFULL;   //!< low 48 bits of a reference: the record
const unsigned MAX_PATH_DEPTH = 255;       //!< a longer parent chain is a loop, or a forged record

uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
uint32_t rd32(const uint8_t* p) { return (uint32_t)rd16(p) | ((uint32_t)rd16(p + 2) << 16); }
uint64_t rd64(const uint8_t* p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }
FILETIME filetime(uint64_t v) { return { (DWORD)(v & 0xFFFFFFFFULL), (DWORD)(v >> 32) }; }

//! A UTC date, not emitted when the record holds none.
void addDate(Json& o, const wchar_t* key, const FILETIME& f) {
	if (f.dwLowDateTime || f.dwHighDateTime) o.add(key, Json::str(timeToIso8601Utc(f)));
}

/*! The $FILE_NAME namespaces, by preference for the name shown: Win32 (1)
 *  and Win32+DOS (3) are the long name, POSIX (0) a case-sensitive one, DOS
 *  (2) the 8.3 alias — used only when nothing else exists. */
int namePreference(uint8_t space) { return space == 1 || space == 3 ? 0 : space == 0 ? 1 : 2; }

} // namespace

bool MftEntry::parse(const uint8_t* record, size_t recordSize, uint64_t number) {
	if (recordSize < 0x30 || std::memcmp(record, "FILE", 4) != 0) return false;
	const size_t used = std::min<size_t>(rd32(record + RECORD_USED_SIZE), recordSize);
	entry = number;
	sequence = rd16(record + RECORD_SEQUENCE);
	const uint16_t flags = rd16(record + RECORD_FLAGS);
	inUse = (flags & 0x01) != 0;
	directory = (flags & 0x02) != 0;
	baseEntry = rd64(record + RECORD_BASE) & REFERENCE_ENTRY_MASK;
	baseSequence = (uint16_t)(rd64(record + RECORD_BASE) >> 48);
	for (size_t p = rd16(record + RECORD_ATTRIBUTES); p + 16 <= used;) {
		const uint32_t type = rd32(record + p);
		const uint32_t length = rd32(record + p + 4);
		if (type == ATTRIBUTE_END || length < 16 || p + length > used) break;
		const uint8_t* a = record + p;
		const bool resident = a[8] == 0;
		const uint8_t nameLength = a[9];
		// The value of a resident attribute, bounded by the attribute.
		const uint8_t* value = nullptr;
		uint32_t valueLength = 0;
		if (resident && length >= 0x18) {
			valueLength = rd32(a + 0x10);
			const uint16_t offset = rd16(a + 0x14);
			if ((uint64_t)offset + valueLength <= length) value = a + offset;
		}
		if (type == STANDARD_INFORMATION && value && valueLength >= 0x24) {
			created = filetime(rd64(value));
			modified = filetime(rd64(value + 0x08));
			mftModified = filetime(rd64(value + 0x10));
			accessed = filetime(rd64(value + 0x18));
			attributes = rd32(value + 0x20);
			// The long form (NTFS 3.0, 0x48 bytes) carries the security descriptor's number.
			if (valueLength >= SI_SECURITY_ID + 4) securityId = rd32(value + SI_SECURITY_ID);
		}
		else if (type == FILE_NAME && value && valueLength >= 0x42
		         && 0x42u + 2u * value[0x40] <= valueLength) {
			const uint8_t space = value[0x41];
			if (space != 2) {
				Link link;
				link.parentEntry = rd64(value) & REFERENCE_ENTRY_MASK;
				link.parentSequence = rd16(value + 6);
				link.name.assign(value[0x40], L'\0');
				for (size_t k = 0; k < link.name.size(); ++k) link.name[k] = (wchar_t)rd16(value + 0x42 + 2 * k);
				links.push_back(std::move(link));
			}
			if (namePreference(space) < nameRank) {
				nameRank = namePreference(space);
				parentEntry = rd64(value) & REFERENCE_ENTRY_MASK;
				parentSequence = rd16(value + 6);
				fileNameCreated = filetime(rd64(value + 0x08));
				fileNameModified = filetime(rd64(value + 0x10));
				fileNameMftModified = filetime(rd64(value + 0x18));
				fileNameAccessed = filetime(rd64(value + 0x20));
				name.assign(value[0x40], L'\0');
				for (size_t k = 0; k < name.size(); ++k) name[k] = (wchar_t)rd16(value + 0x42 + 2 * k);
			}
		}
		else if (type == DATA) {
			const uint16_t nameOffset = rd16(a + 10);
			if (nameLength && (uint64_t)nameOffset + 2u * nameLength <= length) {
				std::wstring stream(nameLength, L'\0');
				for (size_t k = 0; k < stream.size(); ++k) stream[k] = (wchar_t)rd16(a + nameOffset + 2 * k);
				if (toLower(stream) == L"zone.identifier") {
					zoneIdentifier = true;
					if (resident && value) {
						zoneIdentifierResident = true;
						zoneIdentifierSize = valueLength;
						zoneIdentifierContent.assign(reinterpret_cast<const char*>(value), valueLength);
					}
					else if (!resident && length >= 0x40 && rd64(a + 0x10) == 0) zoneIdentifierSize = rd64(a + 0x30);
				}
				streams.push_back(std::move(stream));
			}
			// The content's size: resident, or on the first fragment (starting VCN 0).
			else if (!nameLength && resident && value) { size = valueLength; sizeKnown = true; }
			else if (!nameLength && !resident && length >= 0x40 && rd64(a + 0x10) == 0) { size = rd64(a + 0x30); sizeKnown = true; }
		}
		p += length;
	}
	/* No size from $FILE_NAME: NTFS updates it there only when the name
	   changes, so it can be long out of date. A file whose $DATA is in an
	   extension record gets its size from there (Mft::complete). */
	return true;
}

Json MftEntry::toJson(const std::wstring& path, bool pathComplete,
                      const std::vector<std::wstring>& hardLinkPaths, const std::wstring& volume) const {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(volume));
	o.add(L"Entry", Json::num(entry));
	o.add(L"Sequence", Json::num(sequence));
	o.add(L"Path", Json::str(path));
	if (!pathComplete) o.add(L"PathIncomplete", Json::boolean(true));
	// The parent reference itself: what ties an orphan to a directory of the change journal.
	o.add(L"ParentEntry", Json::num(parentEntry));
	o.add(L"ParentSequence", Json::num(parentSequence));
	if (!inUse) o.add(L"Deleted", Json::boolean(true));
	if (directory) o.add(L"Directory", Json::boolean(true));
	else if (sizeKnown) o.add(L"Size", Json::num(size));
	o.add(L"Attributes", Json::str(FileAttributes(attributes).to_wstring()));
	if (securityId) o.add(L"SecurityId", Json::num((unsigned long long)securityId));
	addDate(o, L"CreatedUtc", created);
	addDate(o, L"ModifiedUtc", modified);
	addDate(o, L"MftModifiedUtc", mftModified);
	addDate(o, L"AccessedUtc", accessed);
	addDate(o, L"FileNameCreatedUtc", fileNameCreated);
	addDate(o, L"FileNameModifiedUtc", fileNameModified);
	addDate(o, L"FileNameMftModifiedUtc", fileNameMftModified);
	addDate(o, L"FileNameAccessedUtc", fileNameAccessed);
	/* A file with hard links is one record under several names: each is a
	   path an analyst may look for (System32\\crypt32.dll, not only its
	   original under WinSxS). */
	if (!hardLinkPaths.empty()) {
		o.add(L"HardLinks", Json::num(hardLinkPaths.size()));
		Json paths = Json::arr();
		for (const std::wstring& other : hardLinkPaths) paths.push(Json::str(other));
		o.add(L"HardLinkPaths", std::move(paths));
	}
	Json list = Json::arr();
	for (const std::wstring& s : streams) list.push(Json::str(s));
	o.add(L"Streams", std::move(list));
	return o;
}

template <typename Visit>
HRESULT Mft::forEachRecord(Visit visit) const {
	std::ifstream in(std::filesystem::path(file_), std::ios::binary);
	if (!in) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	const size_t perBlock = std::max<size_t>(1, (4u << 20) / recordSize_);   // 4 MiB at a time
	std::vector<uint8_t> block(perBlock * recordSize_);
	uint64_t number = 0;
	while (in) {
		in.read(reinterpret_cast<char*>(block.data()), (std::streamsize)block.size());
		const size_t records = (size_t)in.gcount() / recordSize_;
		for (size_t k = 0; k < records; ++k, ++number) {
			uint8_t* record = block.data() + k * recordSize_;
			// A torn record (interrupted write) is left out rather than decoded half old, half new.
			if (std::memcmp(record, "FILE", 4) != 0 || !applyNtfsFixup(record, recordSize_)) continue;
			MftEntry entry;
			if (entry.parse(record, recordSize_, number)) visit(entry);
		}
	}
	return ERROR_SUCCESS;
}

HRESULT Mft::getData(const std::wstring& volume) {
	log(3, L"🔈mft getData " + volume);
	const auto& index = ExhibitStoreIndex();
	const auto found = index.find(toLower(volume.substr(0, 2) + L"\\$MFT"));
	if (found == index.end() || found->second.file.empty()) return HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	file_ = found->second.file;
	volume_ = volume.substr(0, 2);
	// Bytes per record, from record 0 ($MFT itself): 1024 or 4096 on the volumes Windows formats.
	{
		std::ifstream in(std::filesystem::path(file_), std::ios::binary);
		uint8_t header[0x20] = {};
		in.read(reinterpret_cast<char*>(header), sizeof header);
		recordSize_ = in.gcount() == (std::streamsize)sizeof header && std::memcmp(header, "FILE", 4) == 0
		            ? rd32(header + RECORD_ALLOCATED_SIZE) : 0;
		if (recordSize_ != 1024 && recordSize_ != 2048 && recordSize_ != 4096) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
		in.seekg(0, std::ios::end);
		nodes_.resize((size_t)((uint64_t)in.tellg() / recordSize_));
	}
	const HRESULT hresult = forEachRecord([this](const MftEntry& e) {
		if (e.baseEntry) {
			// An extension record: kept only if it carries what a base record may lack.
			if (!e.name.empty() || e.sizeKnown || !e.streams.empty() || !e.links.empty() || e.zoneIdentifier) {
				MftEntry& kept = extensions_[((uint64_t)e.baseSequence << 48) | e.baseEntry];
				if (!e.name.empty() && e.nameRank < kept.nameRank) {
					kept.name = e.name;
					kept.nameRank = e.nameRank;
					kept.parentEntry = e.parentEntry;
					kept.parentSequence = e.parentSequence;
					kept.fileNameCreated = e.fileNameCreated;
					kept.fileNameModified = e.fileNameModified;
					kept.fileNameMftModified = e.fileNameMftModified;
					kept.fileNameAccessed = e.fileNameAccessed;
				}
				if (!kept.sizeKnown && e.sizeKnown) { kept.size = e.size; kept.sizeKnown = true; }
				// A file with many names has some of them here.
				kept.links.insert(kept.links.end(), e.links.begin(), e.links.end());
				kept.streams.insert(kept.streams.end(), e.streams.begin(), e.streams.end());
				if (e.zoneIdentifier && !kept.zoneIdentifier) {
					kept.zoneIdentifier = true;
					kept.zoneIdentifierResident = e.zoneIdentifierResident;
					kept.zoneIdentifierContent = e.zoneIdentifierContent;
					kept.zoneIdentifierSize = e.zoneIdentifierSize;
				}
			}
			return;
		}
		Node& n = nodes_[(size_t)e.entry];
		n.sequence = e.sequence;
		n.inUse = e.inUse;
		if (e.name.empty()) return;
		n.named = true;
		n.nameRank = (uint8_t)e.nameRank;
		n.parentEntry = e.parentEntry;
		n.parentSequence = e.parentSequence;
		n.nameOffset = (uint32_t)names_.size();
		n.nameLength = (uint16_t)e.name.size();
		names_ += e.name;
	});
	if (hresult != ERROR_SUCCESS) return hresult;
	/* A base record whose names were moved to extension records, or that
	   kept only its 8.3 alias there: the better name names the directory.
	   Otherwise the paths under it read "AM3B40~1.945" where Windows shows
	   the long name. */
	for (const auto& [reference, extension] : extensions_) {
		const uint64_t base = reference & REFERENCE_ENTRY_MASK;
		if (base >= nodes_.size() || extension.name.empty()) continue;
		Node& n = nodes_[(size_t)base];
		if (extensionOf(base, n.sequence, n.inUse) != &extension) continue;   // a former file's
		if (n.named && n.nameRank <= extension.nameRank) continue;
		n.named = true;
		n.nameRank = (uint8_t)extension.nameRank;
		n.parentEntry = extension.parentEntry;
		n.parentSequence = extension.parentSequence;
		n.nameOffset = (uint32_t)names_.size();
		n.nameLength = (uint16_t)extension.name.size();
		names_ += extension.name;
	}
	return ERROR_SUCCESS;
}

std::wstring Mft::pathOf(uint64_t entry, uint16_t sequence, bool& complete) const {
	complete = true;
	std::vector<std::wstring> parts;
	uint64_t current = entry;
	uint16_t expected = sequence;
	for (unsigned depth = 0; current != ROOT_ENTRY; ++depth) {
		const bool known = current < nodes_.size() && nodes_[(size_t)current].named;
		const Node* n = known ? &nodes_[(size_t)current] : nullptr;
		/* The record named now must be the one referenced: same sequence
		   number, or one more for a deleted record (NTFS raises it on
		   freeing). Otherwise the directory was reused, and its name would
		   be another's. */
		const bool same = n && (expected == 0 || n->sequence == expected
		                        || (!n->inUse && n->sequence == (uint16_t)(expected + 1)));
		if (!same || depth >= MAX_PATH_DEPTH) {
			complete = false;
			if (parts.empty()) return std::wstring();
			break;
		}
		parts.push_back(names_.substr(n->nameOffset, n->nameLength));
		expected = n->parentSequence;
		current = n->parentEntry;
	}
	/* The root closes the walk, but it is checked like any directory: a
	   reference to entry 5 with another sequence number is a damaged or
	   misread record, whose path is not to be asserted. */
	if (complete && expected != 0 && ROOT_ENTRY < nodes_.size() && nodes_[(size_t)ROOT_ENTRY].named
	    && nodes_[(size_t)ROOT_ENTRY].sequence != expected) {
		complete = false;
		if (parts.empty()) return std::wstring();
	}
	std::wstring path = complete ? volume_ : std::wstring(L"?");
	for (auto it = parts.rbegin(); it != parts.rend(); ++it) path += L"\\" + *it;
	return path;
}

const MftEntry* Mft::extensionOf(uint64_t entry, uint16_t sequence, bool inUse) const {
	auto found = extensions_.find(((uint64_t)sequence << 48) | entry);
	if (found == extensions_.end() && !inUse)
		found = extensions_.find(((uint64_t)(uint16_t)(sequence - 1) << 48) | entry);
	return found == extensions_.end() ? nullptr : &found->second;
}

void Mft::complete(MftEntry& entry) const {
	const MftEntry* found = extensionOf(entry.entry, entry.sequence, entry.inUse);
	if (!found) return;
	const MftEntry& extension = *found;
	if (!extension.name.empty() && extension.nameRank < entry.nameRank) {
		entry.name = extension.name;
		entry.nameRank = extension.nameRank;
		entry.parentEntry = extension.parentEntry;
		entry.parentSequence = extension.parentSequence;
		entry.fileNameCreated = extension.fileNameCreated;
		entry.fileNameModified = extension.fileNameModified;
		entry.fileNameMftModified = extension.fileNameMftModified;
		entry.fileNameAccessed = extension.fileNameAccessed;
	}
	if (extension.sizeKnown) { entry.size = extension.size; entry.sizeKnown = true; }
	entry.streams.insert(entry.streams.end(), extension.streams.begin(), extension.streams.end());
	if (extension.zoneIdentifier && !entry.zoneIdentifier) {
		entry.zoneIdentifier = true;
		entry.zoneIdentifierResident = extension.zoneIdentifierResident;
		entry.zoneIdentifierContent = extension.zoneIdentifierContent;
		entry.zoneIdentifierSize = extension.zoneIdentifierSize;
	}
	entry.links.insert(entry.links.end(), extension.links.begin(), extension.links.end());
}

HRESULT Mft::toJson(JsonArrayWriter& out) const {
	log(3, L"🔈mft toJson " + volume_);
	return forEachRecord([this, &out](MftEntry& e) {
		if (e.baseEntry) return;               // merged into its base record
		complete(e);
		bool pathComplete = true;
		std::wstring path = pathOf(e.entry, e.sequence, pathComplete);
		// The root itself, and a record of which nothing names the place.
		if (e.entry == ROOT_ENTRY) path = volume_ + L"\\";
		// The other names of the file, each through its own directory.
		std::vector<std::wstring> others;
		for (const MftEntry::Link& link : e.links) {
			if (e.isShownName(link) || e.entry == ROOT_ENTRY) continue;
			bool complete = true;
			const std::wstring folder = pathOf(link.parentEntry, link.parentSequence, complete);
			others.push_back((folder.empty() ? std::wstring(L"?") : folder) + L"\\" + link.name);
		}
		out.add(e.toJson(path, pathComplete || e.entry == ROOT_ENTRY, others, volume_));
	});
}

HRESULT Mft::forEachFile(const std::function<void(const MftEntry&, const std::wstring&, bool)>& visit) const {
	return forEachRecord([this, &visit](MftEntry& e) {
		if (e.baseEntry) return;               // merged into its base record
		complete(e);
		bool pathComplete = true;
		const std::wstring path = pathOf(e.entry, e.sequence, pathComplete);
		visit(e, path, pathComplete);
	});
}

void Mft::clear() {
	log(3, L"🔈mft clear");
	nodes_.clear();
	nodes_.shrink_to_fit();
	names_.clear();
	names_.shrink_to_fit();
	extensions_.clear();
}
