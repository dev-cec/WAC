/*! \file
 *  \brief Reading of the custom jump lists (see jumplist_custom.h).
 */
#include "jumplist_custom.h"
#include "consigne.h"
#include <algorithm>

//! The largest jump list read: a series of shortcuts, a few hundred KiB at most.
const uintmax_t JUMPLIST_MAX = 256ull * 1024 * 1024;

namespace {
const uint32_t CUSTOM_DESTINATIONS_VERSION = 2;
const uint32_t CATEGORY_CUSTOM = 0, CATEGORY_KNOWN = 1, CATEGORY_TASKS = 2;
const uint32_t CATEGORIES_MAX = 1000;                  //!< far beyond a real list: a forged count
} // namespace

std::vector<CustomCategoryHeader> customDestinationCategories(const uint8_t* data, size_t size) {
	std::vector<CustomCategoryHeader> categories;
	// Header: version, category count, a reserved word.
	if (!fits(size, 0, 12) || readLittleEndian<uint32_t>(data) != CUSTOM_DESTINATIONS_VERSION) return categories;
	const uint32_t count = readLittleEndian<uint32_t>(data + 4);
	const uint8_t footer[4] = { 0xAB, 0xFB, 0xBF, 0xBA };   // 0xBABFFBAB little-endian: closes every category, and the file
	size_t at = 12;
	for (uint32_t i = 0; i < count && i < CATEGORIES_MAX && fits(size, at, 4); ++i) {
		CustomCategoryHeader c;
		c.kind = readLittleEndian<uint32_t>(data + at);
		at += 4;
		if (c.kind == CATEGORY_CUSTOM) {
			// Its name: a count of UTF-16 characters, the characters; then its entry count.
			if (!fits(size, at, 2)) break;
			const size_t bytes = 2ULL * readLittleEndian<uint16_t>(data + at);
			if (!fits(size, at + 2, bytes + 4)) break;
			c.name = std::wstring(reinterpret_cast<const wchar_t*>(data + at + 2), bytes / 2);
			c.entries = readLittleEndian<uint32_t>(data + at + 2 + bytes);
			at += 2 + bytes + 4;
		}
		else if (c.kind == CATEGORY_KNOWN || c.kind == CATEGORY_TASKS) {
			if (!fits(size, at, 4)) break;
			(c.kind == CATEGORY_KNOWN ? c.knownId : c.entries) = readLittleEndian<uint32_t>(data + at);
			at += 4;
		}
		else break;   // no such kind: the walk lost its place
		categories.push_back(std::move(c));
		// Its shortcuts are not measured here: the category ends at its footer.
		const uint8_t* end = std::search(data + at, data + size, footer, footer + 4);
		if (end == data + size) break;
		at = (size_t)(end - data) + 4;
	}
	return categories;
}

Json CustomCategoryHeader::toJson() const {
	Json o = Json::obj();
	if (kind == CATEGORY_CUSTOM) {
		o.add(L"Kind", Json::str(L"Custom"));
		o.add(L"Name", Json::str(name));
	}
	else if (kind == CATEGORY_KNOWN) {
		o.add(L"Kind", Json::str(L"Known"));
		o.add(L"KnownCategory", knownId == 1 ? Json::str(L"Frequent") : knownId == 2 ? Json::str(L"Recent") : Json::num(knownId));
	}
	else o.add(L"Kind", Json::str(L"Tasks"));
	if (kind != CATEGORY_KNOWN) o.add(L"Entries", Json::num(entries));
	return o;
}

CustomDestinationCategory::CustomDestinationCategory(LPBYTE buffer, size_t buffersize, std::wstring _path, std::wstring _sid) {
	/* The shortcuts are found by their header: the size 0x4C then the
	   ShellLink CLSID, 20 bytes in all. The walk used to run while
	   `x < buffersize - pos - 23`, an UNSIGNED difference: on a file of 25 or
	   26 bytes it wrapped around and the scan went on far past the buffer. */
	const size_t pos = 4;
	const size_t LNK_HEADER = 4 + 16;   // HeaderSize, then LinkCLSID
	for (size_t x = pos; fits(buffersize, x, LNK_HEADER); x++) {
		const unsigned int s = *reinterpret_cast<unsigned int*>(buffer + x); // = 0x4C = 76 for a LNK
		if (s == 76) {
			GUID guid = *reinterpret_cast<GUID*>(buffer + x + 4);
			log(3, L"🔈guid_to_wstring guid");
			std::wstring wguid = guid_to_wstring(guid);

			if (wguid.compare(L"{00021401-0000-0000-C000-000000000046}") == 0) {
				log(3, L"🔈RecentDoc");
				recentDocs.push_back(RecentDoc(buffer + x, buffersize - x, _path, _sid));
			}
		}
	}
};

Json CustomDestinationCategory::toJson() {
	log(3, L"🔈CustomDestinationCategory toJson");
	Json arr = Json::arr();
	for (RecentDoc& r : recentDocs) arr.push(r.toJson());
	Json o = Json::obj();
	o.add(L"RecentDocs", std::move(arr));
	return o;
}

void CustomDestinationCategory::clear() {
	log(3, L"🔈CustomDestinationCategory clear");
}

CustomDestination::CustomDestination(std::filesystem::path _path, std::wstring _sid) {
	Sid = _sid;
	// the path in UTF-16, as Windows holds it
	path = _path.wstring();
	log(3, L"🔈replaceAll pathOriginal");
	// RAW path: the escaping is centralised in json.h.
	pathOriginal = originalPath(path);
	log(2, L"❇️CustomDestination Path : " + pathOriginal);
	// Ownership carried by the type: every exit of the function releases the buffer.
	std::vector<BYTE> content;
	if (readWholeFile(std::filesystem::path(path), JUMPLIST_MAX, content))
	{
		const size_t size = content.size();
		LPBYTE buffer = content.data();

		// The dates of the file ON THE EXAMINED MACHINE, as the raw reading recorded
		// them: the working copy's own are those of the collection (ExhibitSourceTimes).
		if (!ExhibitSourceTimes(path, createdUtc, modifiedUtc, accessedUtc))
			log(2, L"🔥Source timestamps not recorded: " + path);

		// turn the AppID held in the file name into an application name
		std::wstring baseName = _path.stem(); // file name without its extension
		log(3, L"🔈from_appId application");
		application = from_appId(baseName);
		/* The word at 0 is the format's version (2), not a category's kind: read
		   as one, every file was "User tasks". The kinds are those of the
		   categories, walked from the header. */
		categories = customDestinationCategories(buffer, size);
		if (categories.empty()) log(2, L"🔥" + pathOriginal + L" : no category read", ERROR_UNSUPPORTED_TYPE);

		// The shortcuts, found by their header whatever their category.
		if (size > 24) {
			log(3, L"🔈CustomDestinationCategory");
			category = std::make_unique<CustomDestinationCategory>(buffer, size, path, _sid);
		}
		else {
			log(2, L"🔥" + pathOriginal + L" : no LNK to parse",ERROR_EMPTY );
		}
		// The buffer is released by its unique_ptr.
	}
};

Json CustomDestination::toJson() {
	log(3, L"🔈CustomDestination toJson");
	Json o = Json::obj();
	addUser(o, Sid);
	o.add(L"Application", Json::str(application));
	o.add(L"Path",        Json::str(pathOriginal));
	Json list = Json::arr();
	for (const CustomCategoryHeader& c : categories) list.push(c.toJson());
	o.add(L"Categories",  std::move(list));
	o.add(L"Created",     Json::str(utcTimeToIso8601Local(createdUtc)));
	o.add(L"CreatedUtc",  Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"Modified",    Json::str(utcTimeToIso8601Local(modifiedUtc)));
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Accessed",    Json::str(utcTimeToIso8601Local(accessedUtc)));
	o.add(L"AccessedUtc", Json::str(timeToIso8601Utc(accessedUtc)));
	if (category) o.merge(category->toJson());   // fields flattened (the original schema)
	return o;
}

void CustomDestination::clear() {
	log(3, L"🔈CustomDestination clear");
	/* The guard was missing: `category` is null as soon as a Custom Destination
	   carries no lnk — a case that `toJson()` tests explicitly just above. The
	   call was therefore made on a null pointer. The release, for its part, is
	   now ensured by the `unique_ptr`. */
	if (category) category->clear();
	category.reset();
}

HRESULT JumplistCustoms::getData() {
	
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️JumplistCustoms : ");
	log(0, L"*******************************************************************************************************************");


	const std::wstring rep = L"\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations";
	for (const std::tuple<std::wstring, std::wstring>& profileEntry : conf.profiles) {
		// extractedPath() handles the case of a profile on another volume than
		// Windows, which replaceAll(conf.systemDrive) left absolute.
		const std::filesystem::path directory =
			extractedPath(std::get<1>(profileEntry) + rep);
		const std::vector<std::filesystem::path> files =
			listFilesByExtension(directory, { L".customDestinations-ms" });
		size_t iFile = 0;
		for (const std::filesystem::path& file : files) {
			log(1, L"➕CustomDestination");
			printProgress(L"Jumplist " + file.filename().wstring(),
			              ++iFile, files.size(), L"files");
			customDestinations.push_back(CustomDestination(file, std::get<0>(profileEntry)));
		}
	}
	return ERROR_SUCCESS;
}

HRESULT JumplistCustoms::toJson() {
	log(3, L"🔈JumplistCustoms toJson");
	Json arr = Json::arr();
	for (CustomDestination& c : customDestinations) arr.push(c.toJson());
	return writeJsonFile("jumplistCustomDestinations.json", arr);
};

void JumplistCustoms::clear() {
	log(3, L"🔈CustomDestinations clear");
	customDestinations.clear();   // destroys the elements -> really releases them
}
