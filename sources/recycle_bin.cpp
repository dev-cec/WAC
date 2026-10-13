/*! \file
 *  \brief Recycle bin (see recycle_bin.h).
 */
#include "conversions.h"
#include "recycle_bin.h"
#include "consigne.h"
#include <filesystem>
#include <fstream>

namespace {

const size_t HEADER_SIZE = 24;          //!< version, size, deletion date
const uint64_t V1 = 1, V2 = 2;          //!< the two layouts read below; which versions are decoded is the artefact table's word
const size_t V1_PATH_BYTES = 520;       //!< version 1: the path, 260 UTF-16 characters
const size_t V2_LENGTH_OFFSET = 24;     //!< version 2: length of the path, in characters
const size_t V2_PATH_OFFSET = 28;       //!< version 2: the path
//! Largest `$I`: version 2 with a path of 32,767 characters (28 + 65,534 bytes), rounded up.
const uint64_t INDEX_MAX = 64 * 1024 + 64;



/*! The version as a signature for the artefact table: the format's field is
 *  64 bits wide, the table's signatures 32 — a larger value is no version
 *  the table could hold, and must not be mistaken for its low half. */
unsigned formatSignature(uint64_t version) {
	return version > 0xFFFFFFFFull ? 0xFFFFFFFFu : (unsigned)version;
}

} // namespace

bool parseRecycleBinIndex(const std::vector<uint8_t>& bytes, RecycledFile& recycled) {
	if (bytes.size() < HEADER_SIZE) return false;
	recycled.version = readLittleEndian<uint64_t>(bytes.data());
	/* The version decides, and the table holds which ones are decoded
	   (pieceFormat). Another one used to be dropped with a line in the log;
	   it is listed as "unsupported format", and nothing is read under a
	   layout that is not known to be its own. */
	if (!pieceFormat("recycle_bin", formatSignature(recycled.version)).decoded) {
		recycled.unsupportedFormat = true;
		return true;
	}
	recycled.size = readLittleEndian<uint64_t>(bytes.data() + 8);
	const uint64_t deleted = readLittleEndian<uint64_t>(bytes.data() + 16);
	recycled.deletedUtc = filetimeFromTicks(deleted);
	if (recycled.version == V1) {
		if (bytes.size() < HEADER_SIZE + V1_PATH_BYTES) return false;
		recycled.originalPath = readWideZ(bytes.data(), HEADER_SIZE + V1_PATH_BYTES, HEADER_SIZE);
		return true;
	}
	if (recycled.version == V2) {
		if (bytes.size() < V2_PATH_OFFSET) return false;
		const uint32_t announced = readLittleEndian<uint32_t>(bytes, V2_LENGTH_OFFSET);
		// The length is the file's word: bounded by what the file really holds.
		const size_t available = (bytes.size() - V2_PATH_OFFSET) / 2;
		const size_t characters = announced < available ? announced : available;
		recycled.originalPath = readWideZ(bytes.data(), V2_PATH_OFFSET + 2 * characters, V2_PATH_OFFSET);
		return true;
	}
	return false;
}

Json RecycledFile::toJson() const {
	Json o = Json::obj();
	addUser(o, sid);
	if (unsupportedFormat) {
		o.add(L"IndexFile", Json::str(indexFile));
		o.add(L"FormatVersion", Json::num(version));
		addUnsupportedFormat(o, "recycle_bin", formatSignature(version));
		return o;
	}
	o.add(L"OriginalPath", Json::str(originalPath));
	o.add(L"Size", Json::num(size));
	addDate(o, L"Deleted", deletedUtc);
	o.add(L"IndexFile", Json::str(indexFile));
	o.add(L"FormatVersion", Json::num(version));
	return o;
}

HRESULT RecycleBin::getData() {
	log(0, L"ℹ️Recycle bin :");
	/* Through the manifest, like the change journal: the `$I` are found by
	   their path on the examined machine, "X:\$Recycle.Bin\<SID>\$I…", on
	   whichever volume. */
	for (const auto& [key, exhibit] : ExhibitStoreIndex()) {
		if (key.size() < 3 || key.compare(2, 14, L"\\$recycle.bin\\") != 0 || exhibit.workingFile.empty()) continue;
		const std::filesystem::path source(exhibit.sourcePath);
		const std::wstring name = source.filename().wstring();
		if (name.size() < 3 || (name.compare(0, 2, L"$I") != 0 && name.compare(0, 2, L"$i") != 0)) continue;
		std::vector<uint8_t> bytes;
		if (!readWholeFile(std::filesystem::path(exhibit.workingFile), INDEX_MAX, bytes)) {
			log(2, L"🔥Recycle bin index not read (unreadable or too large): " + exhibit.sourcePath);
			continue;
		}
		RecycledFile recycled;
		recycled.indexFile = exhibit.sourcePath;
		recycled.sid = source.parent_path().filename().wstring();
		if (!parseRecycleBinIndex(bytes, recycled)) {
			log(2, L"🔥Recycle bin index truncated: " + exhibit.sourcePath);
			continue;
		}
		files_.push_back(std::move(recycled));
	}
	return ERROR_SUCCESS;
}

HRESULT RecycleBin::toJson() {
	Json list = Json::arr();
	for (const RecycledFile& f : files_) list.push(f.toJson());
	return writeJsonFile("recycle_bin.json", list);
}

void RecycleBin::clear() {
	files_.clear();
}
