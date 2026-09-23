/*! \file
 *  \brief Decoding of shell items, ID lists, property stores and extension blocks (see idList.h).
 */
#include "idList.h"
#include <exception>
#include <map>


/********************************************************************************************************************
* FLAGS
*********************************************************************************************************************/

FileAttributes::FileAttributes(unsigned int attr) {
	ReadOnly = (attr & FILE_ATTRIBUTE_READONLY) ? true : false;
	Hidden = (attr & FILE_ATTRIBUTE_HIDDEN) ? true : false;
	System = (attr & FILE_ATTRIBUTE_SYSTEM) ? true : false;
	Directory = (attr & FILE_ATTRIBUTE_DIRECTORY) ? true : false;
	Archive = (attr & FILE_ATTRIBUTE_ARCHIVE) ? true : false;
	Normal = (attr & FILE_ATTRIBUTE_NORMAL) ? true : false;
	Temporary = (attr & FILE_ATTRIBUTE_TEMPORARY) ? true : false;
	SparseFile = (attr & FILE_ATTRIBUTE_SPARSE_FILE) ? true : false;
	ReparsePoint = (attr & FILE_ATTRIBUTE_REPARSE_POINT) ? true : false;
	Compressed = (attr & FILE_ATTRIBUTE_COMPRESSED) ? true : false;
	Offline = (attr & FILE_ATTRIBUTE_OFFLINE) ? true : false;
	NotContentIndexed = (attr & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) ? true : false;
	Encrypted = (attr & FILE_ATTRIBUTE_ENCRYPTED) ? true : false;
}

std::wstring FileAttributes::to_wstring() {
	log(3, L"🔈FileAttributes to_wstring");
	std::wstring result = L"";
	if (ReadOnly == true) result += L"READONLY, ";
	if (Hidden == true) result += L"HIDDEN, ";
	if (System == true) result += L"SYSTEM, ";
	if (Directory == true) result += L"DIRECTORY, ";
	if (Archive == true) result += L"ARCHIVE, ";
	if (Normal == true) result += L"NORMAL, ";
	if (Temporary == true) result += L"TEMPORARY, ";
	if (SparseFile == true) result += L"SPARSE_FILE, ";
	if (ReparsePoint == true) result += L"REPARSE_POINT, ";
	if (Compressed == true) result += L"COMPRESSED, ";
	if (Offline == true) result += L"OFFLINE, ";
	if (NotContentIndexed == true) result += L"NOT_CONTENT_INDEXED, ";
	if (Encrypted == true) result += L"ENCRYPTED, ";
	if (result.size() > 0)
		return std::wstring(&result[0], &result[0] + result.size() - 2);// remove the last comma and space
	else
		return result;
}

LinkFlags::LinkFlags(unsigned int _flags) {
	HasLinkTargetIDList = (_flags & 0x1) ? true : false;
	HasLinkInfo = (_flags & 0x2) ? true : false;
	HasName = (_flags & 0x4) ? true : false;
	HasRelativePath = (_flags & 0x8) ? true : false;
	HasWorkingDir = (_flags & 0x10) ? true : false;
	HasArguments = (_flags & 0x20) ? true : false;
	HasIconLocation = (_flags & 0x40) ? true : false;
	IsUnicode = (_flags & 0x80) ? true : false;
	ForceNoLinkInfo = (_flags & 0x100) ? true : false;
	HasExpString = (_flags & 0x200) ? true : false;
	RunInSeparateProcess = (_flags & 0x400) ? true : false;
	Unused1 = (_flags & 0x800) ? true : false;
	HasDarwinID = (_flags & 0x1000) ? true : false;
	RunAsUser = (_flags & 0x2000) ? true : false;
	HasExpIcon = (_flags & 0x4000) ? true : false;
	NoPidlAlias = (_flags & 0x8000) ? true : false;
	Unused2 = (_flags & 0x10000) ? true : false;
	RunWithShimLayer = (_flags & 0x20000) ? true : false;
	ForceNoLinkTrack = (_flags & 0x40000) ? true : false;
	EnableTargetMetadata = (_flags & 0x8000) ? true : false;
	DisableLinkPathTracking = (_flags & 0x100000) ? true : false;
	DisableKnownFolderTracking = (_flags & 0x200000) ? true : false;
	DisableKnownFolderAlias = (_flags & 0x400000) ? true : false;
	AllowLinkToLink = (_flags & 0x800000) ? true : false;
	UnaliasOnSave = (_flags & 0x1000000) ? true : false;
	PreferEnvironmentPath = (_flags & 0x2000000) ? true : false;
	KeepLocalIDListForUNCTarget = (_flags & 0x4000000) ? true : false;
}

std::wstring LinkFlags::to_wstring() {
	log(3, L"🔈LinkFlags to_wstring");
	std::wstring result = L"";
	if (HasLinkTargetIDList == true) result += L"HAS_LINK_TARGET_ID_LIST, ";
	if (HasLinkInfo == true) result += L"HAS_LINK_INFO, ";
	if (HasName == true) result += L"HAS_NAME, ";
	if (HasRelativePath == true) result += L"HAS_RELATIVE_PATH, ";
	if (HasWorkingDir == true) result += L"HAS_WORKING_DIR, ";
	if (HasArguments == true) result += L"HAS_ARGUMENTS, ";
	if (HasIconLocation == true) result += L"HAS_ICON_LOCATION, ";
	if (IsUnicode == true) result += L"IS_UNICODE, ";
	if (ForceNoLinkInfo == true) result += L"FORCE_NO_LINK_INFO, ";
	if (HasExpString == true) result += L"HAS_EXP_STRING, ";
	if (RunInSeparateProcess == true) result += L"RUN_IN_SEPARATE_PROCESS, ";
	if (Unused1 == true) result += L"UNUSED1, ";
	if (HasDarwinID == true) result += L"HAS_DARWIN_ID, ";
	if (RunAsUser == true) result += L"RUN_AS_USER, ";
	if (HasExpIcon == true) result += L"HAS_EXP_ICON, ";
	if (NoPidlAlias == true) result += L"NO_PIDL_ALIAS, ";
	if (Unused2 == true) result += L"UNUSED2, ";
	if (RunWithShimLayer == true) result += L"RUN_WITH_SHIM_LAYER, ";
	if (ForceNoLinkTrack == true) result += L"FORCE_NO_LINK_TRACK, ";
	if (EnableTargetMetadata == true) result += L"ENABLE_TARGET_METADATA, ";
	if (DisableLinkPathTracking == true) result += L"DISABLE_LINK_PATH_TRACKING, ";
	if (DisableKnownFolderTracking == true) result += L"DISABLE_KNOWN_FOLDER_TRACKING, ";
	if (DisableKnownFolderAlias == true) result += L"DISABLE_KNOWN_FOLDER_ALIAS, ";
	if (AllowLinkToLink == true) result += L"ALLOW_LINK_TO_LINK, ";
	if (UnaliasOnSave == true) result += L"UNALIAS_ON_SAVE, ";
	if (PreferEnvironmentPath == true) result += L"PREFER_ENVIRONMENT_PATH, ";
	if (KeepLocalIDListForUNCTarget == true) result += L"KEEP_LOCAL_IDLIST_FOR_UNC_TARGET, ";
	if (result.size() > 0)
		return std::wstring(&result[0], &result[0] + result.size() - 2);// remove the last comma and space
	else
		return result;
}

/********************************************************************************************************************
* SPS (Property STORE)
*********************************************************************************************************************/

IdList::IdList(LPBYTE buffer, int _level, bool Parentiszip) {
	type_char = NULL;
	level = _level;
	shellItem = NULL;
	item_size = *reinterpret_cast<unsigned short int*>(buffer);

	if (conf._dump == true) {
		log(3, L"🔈dump_wstring idlist");
		data = dump_wstring(buffer, 0, item_size);
	}
	else
		data = L"";
	if (item_size != 0) {
		type_char = *reinterpret_cast<unsigned char*>(buffer + 2);
		log(3, L"🔈to_hex type_char");
		type_hex = to_hex((int)type_char);
		if (Parentiszip)
			type = L"ARCHIVE_FILE_CONTENT";
		else {
			log(3, L"🔈shell_item_class type_char");
			type = shell_item_class(type_char);
		}
		log(3, L"🔈makeShellItem idlist");
		shellItem = makeShellItem(buffer, level + 1, Parentiszip);
	}
}

Json IdList::toJson() {
	log(3, L"🔈IdList toJson");
	Json o = Json::obj();
	o.add(L"TypeHex", Json::str(L"0x" + type_hex));
	o.add(L"Type",    Json::str(type));
	if (conf._dump) o.add(L"Dump", Json::str(data));
	// The shell item's fields are flattened into this object (the original schema).
	// Guard: shellItem may be null (an item of null size, or a type not recognised).
	if (shellItem) o.merge(shellItem->toJson());
	return o;
}

/*
 * VARENUM usage key,
 *
 * * [V] - may appear in a VARIANT
 * * [T] - may appear in a TYPEDESC
 * * [P] - may appear in an OLE property set
 * * [S] - may appear in a Safe Array
 *
 *
 *  VT_EMPTY            [V]   [P]     nothing
 *  VT_NULL             [V]   [P]     SQL style Null
 *  VT_I2               [V][T][P][S]  2 byte signed int
 *  VT_I4               [V][T][P][S]  4 byte signed int
 *  VT_R4               [V][T][P][S]  4 byte real
 *  VT_R8               [V][T][P][S]  8 byte real
 *  VT_CY               [V][T][P][S]  currency
 *  VT_DATE             [V][T][P][S]  date
 *  VT_BSTR             [V][T][P][S]  OLE Automation std::string
 *  VT_DISPATCH         [V][T]   [S]  IDispatch *
 *  VT_ERROR            [V][T][P][S]  SCODE
 *  VT_BOOL             [V][T][P][S]  True=-1, False=0
 *  VT_VARIANT          [V][T][P][S]  VARIANT *
 *  VT_UNKNOWN          [V][T]   [S]  IUnknown *
 *  VT_DECIMAL          [V][T]   [S]  16 byte fixed point
 *  VT_RECORD           [V]   [P][S]  user defined type
 *  VT_I1               [V][T][P][s]  signed char
 *  VT_UI1              [V][T][P][S]  unsigned char
 *  VT_UI2              [V][T][P][S]  unsigned short
 *  VT_UI4              [V][T][P][S]  ULONG
 *  VT_I8                  [T][P]     signed 64-bit int
 *  VT_UI8                 [T][P]     unsigned 64-bit int
 *  VT_INT              [V][T][P][S]  signed machine int
 *  VT_UINT             [V][T]   [S]  unsigned machine int
 *  VT_INT_PTR             [T]        signed machine register size width
 *  VT_UINT_PTR            [T]        unsigned machine register size width
 *  VT_VOID                [T]        C style void
 *  VT_HRESULT             [T]        Standard return type
 *  VT_PTR                 [T]        pointer type
 *  VT_SAFEARRAY           [T]        (use VT_ARRAY in VARIANT)
 *  VT_CARRAY              [T]        C style array
 *  VT_USERDEFINED         [T]        user defined type
 *  VT_LPSTR               [T][P]     null terminated std::string
 *  VT_LPWSTR              [T][P]     wide null terminated std::string
 *  VT_FILETIME               [P]     FILETIME
 *  VT_BLOB                   [P]     Length prefixed bytes
 *  VT_STREAM                 [P]     Name of the stream follows
 *  VT_STORAGE                [P]     Name of the storage follows
 *  VT_STREAMED_OBJECT        [P]     Stream contains an object
 *  VT_STORED_OBJECT          [P]     Storage contains an object
 *  VT_VERSIONED_STREAM       [P]     Stream with a GUID version
 *  VT_BLOB_OBJECT            [P]     Blob contains an object
 *  VT_CF                     [P]     Clipboard format
 *  VT_CLSID                  [P]     A Class ID
 *  VT_VECTOR                 [P]     simple counted array
 *  VT_ARRAY            [V]           SAFEARRAY*
 *  VT_BYREF            [V]           void* for local use
 *  VT_BSTR_BLOB                      Reserved for system use
 *

enum VARENUM
{
	VT_EMPTY = 0,
	VT_NULL = 1,
	VT_I2 = 2,
	VT_I4 = 3,
	VT_R4 = 4,
	VT_R8 = 5,
	VT_CY = 6,
	VT_DATE = 7,
	VT_BSTR = 8,
	VT_DISPATCH = 9,
	VT_ERROR = 10,
	VT_BOOL = 11,
	VT_VARIANT = 12,
	VT_UNKNOWN = 13,
	VT_DECIMAL = 14,
	VT_I1 = 16,
	VT_UI1 = 17,
	VT_UI2 = 18,
	VT_UI4 = 19,
	VT_I8 = 20,
	VT_UI8 = 21,
	VT_INT = 22,
	VT_UINT = 23,
	VT_VOID = 24,
	VT_HRESULT = 25,
	VT_PTR = 26,
	VT_SAFEARRAY = 27,
	VT_CARRAY = 28,
	VT_USERDEFINED = 29,
	VT_LPSTR = 30,
	VT_LPWSTR = 31,
	VT_RECORD = 36,
	VT_INT_PTR = 37,
	VT_UINT_PTR = 38,
	VT_FILETIME = 64,
	VT_BLOB = 65,
	VT_STREAM = 66,
	VT_STORAGE = 67,
	VT_STREAMED_OBJECT = 68,
	VT_STORED_OBJECT = 69,
	VT_BLOB_OBJECT = 70,
	VT_CF = 71,
	VT_CLSID = 72,
	VT_VERSIONED_STREAM = 73,
	VT_BSTR_BLOB = 0xfff,
	VT_VECTOR = 0x1000,
	VT_ARRAY = 0x2000,
	VT_BYREF = 0x4000,
	VT_RESERVED = 0x8000,
	VT_ILLEGAL = 0xffff,
	VT_ILLEGALMASKED = 0xfff,
	VT_TYPEMASK = 0xfff
};*/
std::wstring getType(unsigned int type) {
	if (type == 0) return L"VT_EMPTY";
	else if (type == 1) return L"VT_NULL";
	else if (type == 2) return L"VT_I2";
	else if (type == 3) return L"VT_I4";
	else if (type == 4) return L"VT_R4";
	else if (type == 5) return L"VT_R8";
	else if (type == 6) return L"VT_CY";
	else if (type == 7) return L"VT_DATE";
	else if (type == 8) return L"VT_BSTR";
	else if (type == 9) return L"VT_DISPATCH";
	else if (type == 10) return L"VT_ERROR";
	else if (type == 11) return L"VT_BOOL";
	else if (type == 12) return L"VT_VARIANT";
	else if (type == 13) return L"VT_UNKNOWN";
	else if (type == 14) return L"VT_DECIMAL";
	else if (type == 16) return L"VT_I1";
	else if (type == 17) return L"VT_UI1";
	else if (type == 18) return L"VT_UI2";
	else if (type == 19) return L"VT_UI4";
	else if (type == 20) return L"VT_I8";
	else if (type == 21) return L"VT_UI8";
	else if (type == 22) return L"VT_INT";
	else if (type == 23) return L"VT_UINT";
	else if (type == 24) return L"VT_VOID";
	else if (type == 25) return L"VT_HRESULT";
	else if (type == 26) return L"VT_PTR";
	else if (type == 27) return L"VT_SAFEARRAY";
	else if (type == 28) return L"VT_CARRAY";
	else if (type == 29) return L"VT_USERDEFINED";
	else if (type == 30) return L"VT_LPSTR";
	else if (type == 31) return L"VT_LPWSTR";
	else if (type == 36) return L"VT_RECORD";
	else if (type == 37) return L"VT_INT_PTR";
	else if (type == 38) return L"VT_UINT_PTR";
	else if (type == 64) return L"VT_FILETIME";
	else if (type == 65) return L"VT_BLOB";
	else if (type == 66) return L"VT_STREAM";
	else if (type == 67) return L"VT_STORAGE";
	else if (type == 68) return L"VT_STREAMED_OBJECT";
	else if (type == 69) return L"VT_STORED_OBJECT";
	else if (type == 70) return L"VT_BLOB_OBJECT";
	else if (type == 71) return L"VT_CF";
	else if (type == 72) return L"VT_CLSID";
	else if (type == 73) return L"VT_VERSIONED_STREAM";
	else if (type == 0xfff) return L"VT_BSTR_BLOB";
	else if (type == 0x1000) return L"VT_VECTOR";
	else if (type == 0x2000) return L"VT_ARRAY";
	else if (type == 0x4000) return L"VT_BYREF";
	else if (type == 0x8000) return L"VT_RESERVED";
	else if (type == 0xffff) return L"VT_ILLEGAL";
	else if (type == 0xfff) return L"VT_ILLEGALMASKED";
	else if (type == 0xfff) return L"VT_TYPEMASK";
	else if (type == 0x101F) return L"Vector<VT_LPWSTR>";
	else if (type == 0x1011) return L"Vector<VT_UI1>";
	else return L"0x" + to_hex(type);
}

Json getValue(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int level,
              unsigned int inputSize, bool* typeNotDecoded);

/*! Size a shell item or an extension block declares in its first two bytes.
 *  The caller has checked that this size fits in the real buffer: it is then
 *  the bound of every read inside the structure. */
static size_t declaredSize(LPBYTE buffer) {
	return *reinterpret_cast<unsigned short*>(buffer);
}

/*! True if `length` bytes starting at `offset` lie inside a structure of `size`
 *  bytes. Written so that no addition can wrap around. */
static bool fits(size_t size, size_t offset, size_t length) {
	return offset <= size && length <= size - offset;
}

/*! Reads ONE scalar value. See `getValue`, which also handles the vectors. */
static Json readScalar(LPBYTE buffer, unsigned int* pos, unsigned short valueType,
                         unsigned int level, unsigned int inputSize, bool* typeNotDecoded) {
	// Now returns a typed Json value (and no longer a pre-serialised string):
	// the escaping is done by the writer, once, at serialisation time.
	// NB: the backslashes are NO LONGER doubled here, which also fixes the
	// advance of *pos that was computed on the escaped string (hence wrong for
	// any value holding a backslash, that is any path).
	/* EVERY READ STAYS INSIDE THE ENTRY, of `inputSize` bytes from `buffer`.
	   The offsets and lengths below come from the file; a truncated or forged
	   entry used to be read beyond its end. A value that does not fit is not
	   decoded: its remaining bytes are returned, and the walk stops, as for a
	   type not decoded. Both callers pass the real size of the entry. */
	auto room = [&](size_t length) { return fits(inputSize, *pos, length); };
	auto truncated = [&]() {
		if (typeNotDecoded) *typeNotDecoded = true;
		log(2, L"🔥getValue: value of type 0x" + to_hex(valueType) + L" overruns its entry",
		    ERROR_INVALID_DATA);
		Json o = Json::obj();
		o.add(L"TruncatedValueType", Json::str(L"0x" + to_hex(valueType)));
		if (inputSize > *pos)
			o.add(L"Data", Json::str(dump_wstring(buffer, (int)*pos, (int)(inputSize - *pos))));
		return o;
	};
	static const std::map<unsigned short, size_t> FIXED_SIZE = {
		{ VT_I2, 2 }, { VT_I4, 4 }, { VT_INT, 4 }, { VT_DATE, 8 }, { VT_BOOL, 2 },
		{ VT_R8, 8 }, { VT_I1, 1 }, { VT_UI1, 1 }, { VT_UI2, 2 }, { VT_UI4, 4 },
		{ VT_UINT, 4 }, { VT_I8, 8 }, { VT_UI8, 8 }, { VT_FILETIME, 8 }, { VT_R4, 4 },
		{ VT_CY, 8 }, { VT_ERROR, 4 }, { VT_DECIMAL, 16 }, { VT_CLSID, 16 },
		// variable types: only their leading size field is fixed
		{ VT_BSTR, 4 }, { VT_LPWSTR, 4 }, { VT_LPSTR, 4 }, { VT_BLOB, 4 },
		{ VT_STREAM, 4 }, { 0x101F, 4 }, { 0x1011, 2 },
	};
	const auto fixedSize = FIXED_SIZE.find(valueType);
	if (fixedSize != FIXED_SIZE.end() && !room(fixedSize->second)) return truncated();

	if (valueType == VT_EMPTY) return Json::str(L"");
	if (valueType == VT_NULL)  return Json::null();
	if (valueType == VT_I2) {
		short v = *reinterpret_cast<short*>(buffer + *pos); *pos += 2; return Json::num((long long)v);
	}
	if (valueType == VT_I4 || valueType == VT_INT) {
		int v = *reinterpret_cast<int*>(buffer + *pos); *pos += 4; return Json::num((long long)v);
	}
	if (valueType == VT_BSTR) {
		std::wstring v = readWideZ(buffer, inputSize, (size_t)*pos + 4);
		*pos += 4 + (unsigned int)v.size() * 2 + 2;
		return Json::str(v);
	}
	if (valueType == VT_DATE) {
		double t = *reinterpret_cast<double*>(buffer + *pos);
		SYSTEMTIME st = { 0 };
		if (!VariantTimeToSystemTime(t, &st)) { *pos += 8; return Json::null(); }
		*pos += 8;
		// A VARIANT date (VT_DATE) is expressed in LOCAL time, by OLE convention.
		return Json::str(timeToIso8601(st, false));
	}
	if (valueType == VT_BOOL) {
		unsigned short v = *reinterpret_cast<unsigned short*>(buffer + *pos); *pos += 2;
		if (v == 0xFFFF) return Json::boolean(true);
		if (v == 0x0000) return Json::boolean(false);
		/* VARIANT_BOOL outside the two canonical values: the raw value is returned
		   rather than an empty string, which lost the data. */
		log(2, L"🔥VT_BOOL not canonical 0x" + to_hex(v));
		return Json::str(L"0x" + to_hex(v));
	}
	if (valueType == VT_R8) {
		double v = *reinterpret_cast<double*>(buffer + *pos); *pos += 8;
		return Json::str(std::to_wstring(v));
	}
	if (valueType == VT_I1) {
		char v = *reinterpret_cast<char*>(buffer + *pos); *pos += 1; return Json::num((long long)v);
	}
	if (valueType == VT_UI1) {
		unsigned char v = *reinterpret_cast<unsigned char*>(buffer + *pos); *pos += 1; return Json::num((long long)v);
	}
	if (valueType == VT_UI2) {
		unsigned short v = *reinterpret_cast<unsigned short*>(buffer + *pos); *pos += 2; return Json::num((long long)v);
	}
	if (valueType == VT_UI4 || valueType == VT_UINT) {
		unsigned int v = *reinterpret_cast<unsigned int*>(buffer + *pos); *pos += 4; return Json::num((unsigned long long)v);
	}
	if (valueType == VT_I8) {
		long long v = *reinterpret_cast<long long*>(buffer + *pos); *pos += 8; return Json::num(v);
	}
	if (valueType == VT_UI8) {
		unsigned long long v = *reinterpret_cast<unsigned long long*>(buffer + *pos); *pos += 8; return Json::num(v);
	}
	if (valueType == VT_LPWSTR) {
		std::wstring v = readWideZ(buffer, inputSize, (size_t)*pos + 4);
		*pos += 4 + (unsigned int)v.size() * 2;
		while (*pos < inputSize && buffer[*pos] == 0x00) *pos += 1;   // padding
		return Json::str(v);
	}
	if (valueType == 0x101F) {                     // Vector<VT_LPWSTR>
		Json arr = Json::arr();
		unsigned int nb = *reinterpret_cast<unsigned int*>(buffer + *pos);
		for (unsigned int x = 0; x < nb && fits(inputSize, (size_t)*pos + 4, 4); x++) {
			unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos + 4);
			arr.push(Json::str(readWideZ(buffer, inputSize, (size_t)*pos + 8)));
			*pos += 4 + size * 2;
		}
		return arr;
	}
	if (valueType == 0x1011) {                     // Vector<VT_UI1>
		unsigned short size = *reinterpret_cast<unsigned short*>(buffer + *pos);
		Json r = Json::str(L"Not implemented");    // unknown content (system.delegateidlist)
		// The vector holds `size` bytes; a nested store must fit in them (and in
		// the entry, when its size is known).
		const size_t space = std::min<size_t>(size, inputSize - *pos);   // room(2) checked above
		if (space >= 0x8 + 4 && *reinterpret_cast<unsigned int*>(buffer + *pos + 0x8) == 0x53505331)
			r = SPS(buffer + *pos + 0x4, level + 2, space - 4).toJson();
		else if (space >= 0x1c + 4 && *reinterpret_cast<unsigned int*>(buffer + *pos + 0x1c) == 0x53505331)
			r = SPS(buffer + *pos + 0x8, level + 2, space - 8).toJson();
		*pos += size;
		return r;
	}
	if (valueType == VT_FILETIME) {
		// A FILETIME is UTC by definition: the "Z" label, not the local time zone.
		Json r = Json::str(timeToIso8601Utc(*reinterpret_cast<FILETIME*>(buffer + *pos)));
		*pos += 8; return r;
	}
	if (valueType == VT_BLOB) {
		/* THE OLD VERSION ALWAYS ASSUMED THREE PROPERTY STORES at offset 17,
		   hard-coded and without checking anything. On a BLOB of another shape —
		   and nothing guarantees that one — the three readings went into
		   arbitrary bytes and published invented properties. The raw content,
		   for its part, was never returned.

		   Now: the declared size bounds the reading, the "SPS1" signature is
		   checked before decoding, and as many stores are chained as the BLOB
		   really holds. Failing that, the bytes. */
		const unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos);
		const unsigned int start = *pos + 4;
		Json o = Json::obj();
		o.add(L"DataSize", Json::num(size));
		const bool boundsOk = size > 0 && fits(inputSize, start, size);
		if (!boundsOk) {
			log(2, L"🔥VT_BLOB: size outside the entry (" + std::to_wstring(size) + L")");
		}
		/* The 13-byte offset between the start of the BLOB and the first store was
		   found empirically; it is applied only if the signature is actually
		   there. */
		else if (size >= 13 + 8 && *reinterpret_cast<const unsigned int*>(buffer + start + 13 + 4) == 0x53505331) {
			Json arr = Json::arr();
			unsigned int p = start + 13;
			const unsigned int end = start + size;
			while (p + 8 < end) {
				if (*reinterpret_cast<const unsigned int*>(buffer + p + 4) != 0x53505331) break;
				SPS sps(buffer + p, level + 2, end - p);
				if (sps.size == 0) break;
				arr.push(sps.toJson());
				p += sps.size;
			}
			o.add(L"PropertyStores", std::move(arr));
		}
		else {
			log(3, L"🔈dump_wstring VT_BLOB");
			o.add(L"Data", Json::str(dump_wstring(buffer, (int)start, (int)size)));
		}
		*pos += 4 + size;
		return o;
	}
	if (valueType == VT_STREAM) {
		/* THE STREAM'S CONTENT WAS THROWN AWAY. The code read the stream's name,
		   read the size of the data, advanced by as much… and returned only the
		   name. But that name is a mere indirection identifier: on a real
		   collection, the fifteen VT_STREAM values all returned
		   "prop4294967295". In other words the artefact carried nothing usable,
		   while the data was there.

		   The content is now returned. When it starts with the "SPS1" signature,
		   it is a nested property store: it is decoded as such — the same case as
		   Vector<VT_UI1>. Otherwise, the bytes are returned in hexadecimal. */
		const unsigned int nameSize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		*pos += 4;
		const std::wstring name = readWideZ(buffer, inputSize, *pos);
		if (!fits(inputSize, (size_t)*pos, (size_t)nameSize + 2 + 4)) return truncated();
		*pos += nameSize + 2;
		const unsigned int dataSize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		const unsigned int dataStart = *pos + 4;

		Json o = Json::obj();
		o.add(L"StreamName", Json::str(name));
		o.add(L"DataSize",   Json::num(dataSize));
		const bool boundsOk = dataSize > 0 && fits(inputSize, dataStart, dataSize);
		if (!boundsOk) {
			if (dataSize > 0)
				log(2, L"🔥VT_STREAM: data size outside the entry ("
				     + std::to_wstring(dataSize) + L")");
		}
		else if (dataSize >= 8 && *reinterpret_cast<const unsigned int*>(buffer + dataStart + 4) == 0x53505331) {
			// Nested property store: the "SPS1" signature follows the size.
			log(3, L"🔈VT_STREAM: nested property store");
			o.add(L"PropertyStore", SPS(buffer + dataStart, level + 2, dataSize).toJson());
		}
		else {
			log(3, L"🔈dump_wstring VT_STREAM");
			o.add(L"Data", Json::str(dump_wstring(buffer, (int)dataStart,
			                                      (int)dataSize)));
		}
		*pos += dataSize;
		return o;
	}
	/* TYPES ADDED to align the coverage on libfwps (libyal), the reference for
	   the property store format. All five were missing, and therefore came out
	   without a value. Sizes and semantics after MS-OLEPS. */
	if (valueType == VT_R4) {                      // 0x0004: 32-bit float
		float v = *reinterpret_cast<float*>(buffer + *pos); *pos += 4;
		return Json::str(std::to_wstring(v));
	}
	if (valueType == VT_CY) {                      // 0x0006: currency
		/* A signed 64-bit integer holding the amount multiplied by 10,000. The raw
		   value is kept: dividing it here would impose a decimal format and lose
		   precision. */
		long long v = *reinterpret_cast<long long*>(buffer + *pos); *pos += 8;
		Json o = Json::obj();
		o.add(L"ScaledBy10000", Json::num(v));
		return o;
	}
	if (valueType == VT_ERROR) {                   // 0x000A: HRESULT
		unsigned int v = *reinterpret_cast<unsigned int*>(buffer + *pos); *pos += 4;
		return Json::str(L"0x" + to_hex(v));
	}
	if (valueType == VT_DECIMAL) {                 // 0x000E: 128-bit decimal
		/* Windows DECIMAL structure: 16 bytes. Returned as raw bytes rather than
		   converted — a conversion to double would lose precisely the precision
		   that makes this type worth having. */
		Json o = Json::obj();
		o.add(L"Decimal128", Json::str(dump_wstring(buffer, (int)*pos, 16)));
		*pos += 16;
		return o;
	}
	if (valueType == VT_LPSTR) {                   // 0x001E: ASCII string
		/* Size in BYTES, terminator included — unlike VT_LPWSTR, whose size is in
		   characters. */
		unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos);
		std::wstring v = string_to_wstring(readNarrowZ(buffer, inputSize, (size_t)*pos + 4));
		*pos += 4 + size;
		return Json::str(v);
	}
	if (valueType == VT_CLSID) {
		std::wstring guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + *pos));
		*pos += 16;
		Json o = Json::obj();
		o.add(L"GUID",         Json::str(guid));
		o.add(L"FriendlyName", Json::str(trans_guid_to_wstring(guid)));
		return o;
	}

	/* A TYPE NOT DECODED: ITS BYTES ARE RETURNED.
	 *
	 * The previous version returned an empty string. The property therefore
	 * appeared with its name and its type, but WITHOUT a value —
	 * indistinguishable from a really empty property, and the data was lost
	 * while it is present in the file. A type we cannot read must not make its
	 * content disappear: the remaining bytes of the entry are returned, in
	 * hexadecimal, so that an analyst can decode them — the same reason for being
	 * as the dump of `UnknownShellItem` and of `BeefUnknown`.
	 *
	 * The position is not advanced: it only serves inside the entry, whose walk
	 * is bounded by its own size at the caller's. */
	if (typeNotDecoded) *typeNotDecoded = true;
	Json o = Json::obj();
	o.add(L"UnsupportedValueType", Json::str(L"0x" + to_hex(valueType)));
	if (inputSize > *pos) {
		log(3, L"🔈dump_wstring: value type not supported");
		// "inputSize - pos" is indeed a LENGTH: the remaining bytes.
		o.add(L"Data", Json::str(dump_wstring(buffer, (int)*pos, (int)(inputSize - *pos))));
	}
	log(2, L"🔥getValue: value type not supported 0x" + to_hex(valueType));
	return o;
}

/*! Reads a property store value, scalar or VECTOR.
*
*  THE VECTORS ARE NOW HANDLED GENERICALLY. The `VT_VECTOR` bit (0x1000) signals
*  an array: a 32-bit element count, then the elements of the matching scalar
*  type (MS-OLEPS). Only two vectors were recognised — `Vector<VT_UI1>` and
*  `Vector<VT_LPWSTR>` — and all the others (`Vector<VT_FILETIME>`,
*  `Vector<VT_CLSID>`, `Vector<VT_I4>`, `Vector<VT_LPSTR>`…) fell into the "type
*  not supported" case. Decoding the count then delegating each element to the
*  scalar reader covers them all at once, and any scalar type added later
*  automatically gets its vector form.
*
*  The two historical vectors keep their own handling: `Vector<VT_UI1>` is not a
*  plain byte array but may hold a nested property store ("SPS1" signature),
*  which no generic rule would guess.
*/
Json getValue(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int level,
              unsigned int inputSize, bool* typeNotDecoded) {
	const unsigned short VT_VECTOR_BIT = 0x1000;

	// Special cases kept: heuristics specific to these two vectors.
	if (valueType == 0x1011 || valueType == 0x101F)
		return readScalar(buffer, pos, valueType, level, inputSize, typeNotDecoded);

	if ((valueType & VT_VECTOR_BIT) == 0)
		return readScalar(buffer, pos, valueType, level, inputSize, typeNotDecoded);

	const unsigned short typeElement = (unsigned short)(valueType & 0x0FFF);
	if (!fits(inputSize, *pos, 4)) {                // no room for the element count
		if (typeNotDecoded) *typeNotDecoded = true;
		log(2, L"🔥vector: no room for the element count", ERROR_INVALID_DATA);
		Json o = Json::obj();
		o.add(L"TruncatedValueType", Json::str(L"0x" + to_hex(valueType)));
		return o;
	}
	const unsigned int nb = *reinterpret_cast<unsigned int*>(buffer + *pos);
	*pos += 4;
	log(3, L"🔈vector of " + std::to_wstring(nb) + L" element(s) de type 0x"
	     + to_hex(typeElement));

	/* A nonsensical count comes from corrupted data or a misidentified type: the
	   bytes are returned instead of iterating millions of times. */
	const unsigned int MAX_ELEMENTS = 65536;
	if (nb > MAX_ELEMENTS) {
		log(2, L"🔥vector: nonsensical count " + std::to_wstring(nb));
		if (typeNotDecoded) *typeNotDecoded = true;
		Json o = Json::obj();
		o.add(L"UnsupportedValueType", Json::str(L"0x" + to_hex(valueType)));
		o.add(L"ElementCount",         Json::num(nb));
		if (inputSize > *pos)
			o.add(L"Data", Json::str(dump_wstring(buffer, (int)*pos,
			                                      (int)(inputSize - *pos))));
		return o;
	}

	Json arr = Json::arr();
	for (unsigned int x = 0; x < nb; ++x) {
		bool elementNonDecode = false;
		Json v = readScalar(buffer, pos, typeElement, level, inputSize,
		                      &elementNonDecode);
		arr.push(std::move(v));
		if (elementNonDecode) {
			/* Without knowing an element's size, the position does not advance:
			   going on would re-read the same byte. We stop and report it. */
			if (typeNotDecoded) *typeNotDecoded = true;
			log(2, L"🔥vector: element of a type not decoded 0x" + to_hex(typeElement)
			     + L", stopped after " + std::to_wstring(x + 1) + L"/" + std::to_wstring(nb));
			break;
		}
	}
	return arr;
}

SPSValue::SPSValue(LPBYTE buffer, std::wstring _guid, int _level) {
	log(3, L"🔈SPSValue");
	level = _level;
	guid = _guid;
	size = *reinterpret_cast<unsigned int*>(buffer);
	valueType = 0;
	/* The caller checked that the entry fits in its store. Its header — size,
	   identifier, reserved byte, type and padding — takes 13 bytes; a shorter
	   entry is malformed and ends the store's walk (size 0). */
	if (size > 0 && size < 13) {
		log(2, L"🔥SPSValue: entry of " + std::to_wstring(size) + L" bytes, shorter than its header",
		    ERROR_INVALID_DATA);
		size = 0;
	}
	if (size > 0) {
		unsigned int id_int = *reinterpret_cast<unsigned int*>(buffer + 4);
		id = std::to_wstring(id_int);
		//recherche value
		unsigned int pos = 13;
		if (guid == L"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}") {
			// Named entry: `id_int` is the name's size, then the type.
			if (!fits(size, 9 + (size_t)id_int, 4)) {
				log(2, L"🔥SPSValue: name of " + std::to_wstring(id_int)
				     + L" bytes overruns its entry", ERROR_INVALID_DATA);
				size = 0;
				return;
			}
			id = readWideZ(buffer, size, 9);
			log(3, L"🔈trans_guid_to_wstring name");
			name = trans_guid_to_wstring(guid);
			valueType = *reinterpret_cast<unsigned short int*>(buffer + 9 + id_int); // id_int holds the size of the std::string
			pos = 9 + id_int + 2 + 2; // 2 bytes of padding?
		}
		else {
			valueType = *reinterpret_cast<unsigned short int*>(buffer + 9);
			log(3, L"🔈to_FriendlyName name");
			// The unknown name is now the RAW KEY, logged by to_FriendlyName itself: the
			// test on "(Undefined)" has no purpose any more and was redundant.
			name = to_FriendlyName(guid, id_int);
			id = std::to_wstring(id_int);

		}
		log(3, L"🔈getValue");
		value = getValue(buffer, &pos, valueType, level, size);
	}
}

Json SPSValue::toJson() {
	log(3, L"🔈SPSValue toJson");
	Json o = Json::obj();
	o.add(L"ID",    Json::str(guid + L"/" + id));
	o.add(L"Name",  Json::str(name));
	o.add(L"Type",  Json::str(getType(valueType)));
	o.add(L"Value", value);          // value already typed (string, number, object, array)
	return o;
}

SPS::SPS(LPBYTE buffer, int _level, size_t limit) {
	level = _level;
	size = 0;
	/* The store declares its own size; it must fit in the enclosing structure,
	   and every value must fit in the store. Without those checks, a store
	   declaring more than its container had its values read beyond it. */
	if (limit < 24) return;                        // no room for the header
	const unsigned int declared = *reinterpret_cast<unsigned int*>(buffer);
	if (declared < 24 || declared > limit) {
		log(2, L"🔥SPS: declared size " + std::to_wstring(declared) + L" does not fit in "
		     + std::to_wstring(limit) + L" bytes, store ignored", ERROR_INVALID_DATA);
		return;
	}
	size = declared;
	version = *reinterpret_cast<unsigned int*>(buffer + 4);
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guid);
	unsigned int pos = 24;
	while (pos + 4 <= size) {
		const unsigned int valueSize = *reinterpret_cast<unsigned int*>(buffer + pos);
		if (valueSize == 0 || valueSize > size - pos) break;  // end, or a value overrunning the store
		log(3, L"🔈SPSValue");
		SPSValue block(buffer + pos, guid, level + 2); // consistent with toJson
		if (block.size == 0) { // empty
			break;
		}
		else
			values.push_back(block);
		pos += block.size;
	}
}

Json SPS::toJson() {
	log(3, L"🔈SPS toJson");
	Json arr = Json::arr();
	for (SPSValue& v : values) arr.push(v.toJson());
	Json o = Json::obj();
	/* GUID of the property store (its "format ID") and its label: read by the
	   constructor and never emitted. Each value already carries the GUID in its
	   ID field, but a store WITHOUT a value lost all identification — and the
	   store's label appeared nowhere. */
	if (!guid.empty())         o.add(L"GUID",         Json::str(guid));
	if (!FriendlyName.empty()) o.add(L"FriendlyName", Json::str(FriendlyName));
	o.add(L"Values", std::move(arr));
	return o;
}

/********************************************************************************************************************
* Extension blocks
*********************************************************************************************************************/

Beef0000::Beef0000(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0000";
	log(3, L"🔈guid_to_wstring guid1");
	guid1 = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring identifier1");
	identifier1 = trans_guid_to_wstring(guid1);
	log(3, L"🔈guid_to_wstring guid2");
	guid2 = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 24));
	log(3, L"🔈trans_guid_to_wstring identifier2");
	identifier2 = trans_guid_to_wstring(guid2);
}

Json Beef0000::toJson() {
	log(3, L"🔈Beef0000 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Guid1", Json::str(guid1));
	o.add(L"Identifier1", Json::str(identifier1));
	o.add(L"Guid2", Json::str(guid2));
	o.add(L"Identifier2", Json::str(identifier2));
	return o;
}

Beef0001::Beef0001(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0001";
	message = L"Unsupported Extension block";
}

Json Beef0001::toJson() {
	log(3, L"🔈Beef0001 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0002::Beef0002(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0002";
	message = L"Unsupported Extension block";
}

Json Beef0002::toJson() {
	log(3, L"🔈Beef0002 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0003::Beef0003(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0003";
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring identifier");
	identifier = trans_guid_to_wstring(guid);
}

Json Beef0003::toJson() {
	log(3, L"🔈Beef0003 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Guid", Json::str(guid));
	o.add(L"Identifier", Json::str(identifier));
	return o;
}

Beef0004::Beef0004(LPBYTE buffer, int _level, bool* is_zip, bool is_file) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0004";
	/* VERSION OF THE BLOCK: it was set to zero and never read again, hence neither
	   used nor emitted. Yet it is investigation data: it says which version of
	   Windows WROTE the entry — 0x0003 (XP), 0x0007 (Vista), 0x0008 (Windows 7),
	   0x0009 (Windows 8.1 and later) — and decides which fields the block holds.
	   Offset 2, just before the signature read at 4. */
	ExtensionVersion = *reinterpret_cast<unsigned short int*>(buffer + 2);
	/* FIX (a double shift on the FAT dates).
	   A FAT/DOS date is stored in LOCAL TIME, by the format's specification. The
	   code assigned that local value to `creationDateUtc`, then applied
	   FileTimeToLocalFileTime to it — thus treating local time as UTC.
	   The result: the *Utc key published a local time labelled UTC, and the local
	   key a time shifted a SECOND time (+2 h in Paris in summer).
	   The right way is the reverse: the native value is local, and UTC is
	   derived from it. */
	creationDate = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime creationDate");
	LocalFileTimeToFileTime(&creationDate, &creationDateUtc);

	accessedDate = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 12)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime accessedDate");
	LocalFileTimeToFileTime(&accessedDate, &accessedDateUtc);
	/* IDENTIFIER AND $MFT REFERENCE (versions >= 7), and above all OFFSETS
	 * COMPUTED FROM THE VERSION.
	 *
	 * WHAT WAS WRONG. The offsets of the long name were hard-coded (36 and 46) —
	 * they are right only for VERSION 9 of the block, that of Windows 8.1 and
	 * later. On a block of version 3 (Windows XP), 7 (Vista) or 8 (Windows 7),
	 * the long name was therefore read in the wrong place. It is exactly the kind
	 * of defect that does not show on a recent machine and reveals itself on an
	 * old system, like the $ATTRIBUTE_LIST attribute. The version, now read
	 * (offset 2), serves to compute the real position — the same sequence as Eric
	 * Zimmerman's reference implementation (ExtensionBlocks). */
	identifier = *reinterpret_cast<unsigned short int*>(buffer + 16);
	/* Every field past the fixed part (18 bytes, checked by getExtensionBlock)
	   depends on the version: each read is checked against the block's size. */
	const size_t blockSize = declaredSize(buffer);
	size_t off = 18;                              // end of the fixed part
	if (ExtensionVersion >= 7) {
		off += 2;                                 // two empty bytes
		/* File reference: 6 bytes of entry index, 2 of sequence. */
		if (fits(blockSize, off, 8)) {
			const unsigned long long brut = *reinterpret_cast<unsigned long long*>(buffer + off);
			mftEntryNumber    = brut & 0x0000FFFFFFFFFFFFULL;
			mftSequenceNumber = (unsigned short int)(brut >> 48);
			if (mftEntryNumber != 0 && mftSequenceNumber != 0)      mftNote = L"NTFS";
			else if (mftEntryNumber != 0 && mftSequenceNumber == 0) mftNote = L"FAT";
			else                                                    mftNote = L"Network/special item";
		}
		off += 8;                                 // file reference
		off += 8;                                 // eight unknown bytes
	}
	/* Size of the long name. It was read at the hard-coded offset 36 — right
	   for version 9 only, like the name offsets themselves; it is the 2-byte
	   field of the same sequence. */
	unsigned short int longNameSize = 0;
	if (ExtensionVersion >= 3) {
		if (fits(blockSize, off, 2)) longNameSize = *reinterpret_cast<unsigned short int*>(buffer + off);
		off += 2;
	}
	if (ExtensionVersion >= 9) off += 4;
	if (ExtensionVersion >= 8) off += 4;

	longName = readWideZ(buffer, blockSize, off);
	// the content of ZIP files and other archives has a special format, so the archives must be identified.
	// The ARCHIVE attribute does not mean ZIP but "ready to be archived", in Explorer's sense
	std::wstring extension = L"";
	if (longName.length() > 3)
		extension = longName.substr(longName.length() - 3, 3);
	transform(extension.begin(), extension.end(), extension.begin(), ::toupper);
	if (is_file == true && (extension == L"ZIP" || extension == L"TAR" || extension == L".GZ" || extension == L".7Z" || extension == L"RAR"))
		*is_zip = true;
	if (longNameSize > longName.size())
	{
		localizedName = readWideZ(buffer, blockSize, off + (longName.size() + 1) * 2);
	}
}

Json Beef0004::toJson() {
	log(3, L"🔈Beef0004 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	// Version of the block: says which version of Windows wrote the entry.
	o.add(L"ExtensionVersion", Json::str(L"0x" + to_hex(ExtensionVersion)));
	o.add(L"Identifier",       Json::num(identifier));
	/* $MFT reference: exists only from version 7 of the block on. Emitted only if
	   it is present, so as not to publish misleading zeros. */
	if (!mftNote.empty()) {
		o.add(L"MftEntryNumber",    Json::num(mftEntryNumber));
		o.add(L"MftSequenceNumber", Json::num(mftSequenceNumber));
		o.add(L"MftNote",           Json::str(mftNote));
	}
	// FIX: the Created* keys published accessedDate/accessedDateUtc, while
	// creationDate/creationDateUtc are indeed parsed. The creation date was
	// therefore lost and replaced by the access date.
	o.add(L"CreatedDate",     Json::str(timeToIso8601Local(creationDate)));
	o.add(L"CreatedDateUtc",  Json::str(timeToIso8601Utc(creationDateUtc)));
	o.add(L"AccessedDate",    Json::str(timeToIso8601Local(accessedDate)));
	o.add(L"AccessedDateUtc", Json::str(timeToIso8601Utc(accessedDateUtc)));
	o.add(L"LongName",        Json::str(longName));
	o.add(L"LocalizedName",   Json::str(localizedName));
	return o;
}

Beef0006::Beef0006(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0006";
	// The name follows the first null 16-bit word of the block; both the search
	// and the read stop at the block's end.
	const size_t limit = declaredSize(buffer);
	size_t pos = 0;
	while (pos + 2 <= limit && *reinterpret_cast<short int*>(buffer + pos) != 0x0000)
		pos += 1;
	username = readWideZ(buffer, limit, pos + 2);
}

Json Beef0006::toJson() {
	log(3, L"🔈Beef0006 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Username", Json::str(username));
	return o;
}

Beef0008::Beef0008(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef008";
	message = L"Unsupported Extension block";
}

Json Beef0008::toJson() {
	log(3, L"🔈Beef0008 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0009::Beef0009(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0009";
	message = L"Unsupported Extension block";
}

Json Beef0009::toJson() {
	log(3, L"🔈Beef0009 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef000a::Beef000a(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef000a";
	message = L"Unsupported Extension block";
}

Json Beef000a::toJson() {
	log(3, L"🔈Beef000a toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef000c::Beef000c(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef000c";
	message = L"Unsupported Extension block";
}

Json Beef000c::toJson() {
	log(3, L"🔈Beef000c toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

/* NOT COVERED BY THE TESTS (checked on 2026-09-15).
 * The validation VM produces only 0xbeef0004 blocks: this constructor is never
 * exercised, and its offsets (GUID at +16, 3 SPS from +50, then +11 before 3
 * strings) therefore remain unverified hypotheses.
 * Exercising it needs shellbags holding this block — which requires an
 * INTERACTIVE session in Explorer (the shellbags are not fed by a process started
 * as a service), or a reference set of hives.
 * Until that is done: output to be considered as not validated. */
Beef000e::Beef000e(LPBYTE buffer, int _level) {
	level = _level;
	message = L"";
	isPresent = true;
	signature = L"0xbeef000e";
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 16));
	log(3, L"🔈trans_guid_to_wstring identifier");
	identifier = trans_guid_to_wstring(guid);
	int pos = 50;
	for (int x = 0; x < 3; x++) {
		log(3, L"🔈SPS");
		SPS s = SPS(buffer + pos, level + 1, (size_t)pos < declaredSize(buffer) ? declaredSize(buffer) - pos : 0);
		if (s.size == 0) break;
		SPSs.push_back(s);
		pos += s.size;
	}
	pos += 11;
	for (int x = 0; x < 3; x++) {
		std::string s = readNarrowZ(buffer, declaredSize(buffer), pos);
		pos += s.size() + 1;
	}
	pos += 16;
	std::string s = readNarrowZ(buffer, declaredSize(buffer), pos);
	pos += s.size() + 1;

	pos += 1;

	const size_t limit = declaredSize(buffer);
	for (int x = 0; x < 2; x++) { // 2 extension block
		unsigned short int size = ((size_t)pos + 2 <= limit) ? *reinterpret_cast<unsigned short int*>(buffer + pos) : 0;
		if (size > 0 && size <= limit - (size_t)pos) {
			log(3, L"🔈getExtensionBlock");
			getExtensionBlock(buffer + pos, &extensionblocks, level + 1, NULL, false);
			pos += size;
		}
		else
			break;
	}
	while ((size_t)pos + 2 <= limit) {
		unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos); // look for the idlist
		if (size >= 3 && size <= limit - (size_t)pos) {
			log(3, L"🔈makeShellItem");
			ishellitems.push_back(makeShellItem(buffer + pos, level + 1));
			pos += size;
		}
		else
			break;
	}
}

Json Beef000e::toJson() {
	log(3, L"🔈Beef000e toJson");
	/* MEMBERS COLLECTED AND NEVER EMITTED. The constructor read the GUID, its
	   label, THREE property stores and extension blocks; toJson published only
	   the signature and the shell items. All the rest was read then thrown
	   away — the same defect as UsersPropertyView, found by the same audit. */
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	if (!guid.empty())       o.add(L"GUID",         Json::str(guid));
	if (!identifier.empty()) o.add(L"FriendlyName", Json::str(identifier));

	Json arr = Json::arr();
	for (const auto& it : ishellitems) arr.push(it->toJson());
	o.add(L"IdLists", std::move(arr));

	if (!SPSs.empty()) {
		Json stores = Json::arr();
		for (SPS& sps : SPSs) stores.push(sps.toJson());
		o.add(L"PropertyStores", std::move(stores));
	}
	if (!extensionblocks.empty()) {
		Json blocks = Json::arr();
		for (const auto& b : extensionblocks) blocks.push(b->toJson());
		o.add(L"ExtensionBlocksCount", Json::num((unsigned long long)extensionblocks.size()));
		o.add(L"ExtensionBlocks",      std::move(blocks));
	}
	return o;
}

Beef0010::Beef0010(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0010";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 16, level + 1, declaredSize(buffer) > 16 ? declaredSize(buffer) - 16 : 0);
}

Json Beef0010::toJson() {
	log(3, L"🔈Beef0010 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"SPS",       sps.toJson());
	return o;
}

Beef0013::Beef0013(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0013";
	message = L"The purpose of this extension block is unknown";
}

Json Beef0013::toJson() {
	log(3, L"🔈Beef0013 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0014::Beef0014(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0014";
	message = L"Unsupported Extension block";
}

Json Beef0014::toJson() {
	log(3, L"🔈Beef0014 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0016::Beef0016(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0016";
	value = readWideZ(buffer, declaredSize(buffer), 10);
}

Json Beef0016::toJson() {
	log(3, L"🔈Beef0016 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Value", Json::str(value));
	return o;
}

Beef0017::Beef0017(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0017";
	message = L"Unsupported Extension block";
}

Json Beef0017::toJson() {
	log(3, L"🔈Beef0017 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

Beef0019::Beef0019(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0019";
	log(3, L"🔈guid_to_wstring guid1");
	guid1 = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring identifier1");
	identifier1 = trans_guid_to_wstring(guid1);
	log(3, L"🔈guid_to_wstring guid2");
	guid2 = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 24));
	log(3, L"🔈trans_guid_to_wstring identifier2");
	identifier2 = trans_guid_to_wstring(guid2);
}

Json Beef0019::toJson() {
	log(3, L"🔈Beef0019 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Guid1", Json::str(guid1));
	o.add(L"Identifier1", Json::str(identifier1));
	o.add(L"Guid2", Json::str(guid2));
	o.add(L"Identifier2", Json::str(identifier2));
	return o;
}

Beef001a::Beef001a(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef001a";
	fileDocumentTypeString = readWideZ(buffer, declaredSize(buffer), 10);
}

Json Beef001a::toJson() {
	log(3, L"🔈Beef001a toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"FileDocumentType", Json::str(fileDocumentTypeString));
	return o;
}

Beef001b::Beef001b(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef001b";
	fileDocumentTypeString = readWideZ(buffer, declaredSize(buffer), 10);
}

Json Beef001b::toJson() {
	log(3, L"🔈Beef001b toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"FileDocumentType", Json::str(fileDocumentTypeString));
	return o;
}

Beef001d::Beef001d(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef001d";
	executable = readWideZ(buffer, declaredSize(buffer), 10);
}

Json Beef001d::toJson() {
	log(3, L"🔈Beef001d toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Executable", Json::str(executable));
	return o;
}

Beef001e::Beef001e(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef001e";
	pinType = readWideZ(buffer, declaredSize(buffer), 10);
}

Json Beef001e::toJson() {
	log(3, L"🔈Beef001e toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"PinType", Json::str(pinType));
	return o;
}

Beef0021::Beef0021(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0021";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, level + 1, declaredSize(buffer) > 8 ? declaredSize(buffer) - 8 : 0);
}

Json Beef0021::toJson() {
	log(3, L"🔈Beef0021 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"SPS",       sps.toJson());
	return o;
}

Beef0024::Beef0024(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0024";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, level + 1, declaredSize(buffer) > 8 ? declaredSize(buffer) - 8 : 0);
}

Json Beef0024::toJson() {
	log(3, L"🔈Beef0024 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"SPS",       sps.toJson());
	return o;
}

Beef0025::Beef0025(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0025";
	filetime1 = *reinterpret_cast<FILETIME*>(buffer + 12);
	filetime2 = *reinterpret_cast<FILETIME*>(buffer + 20);
}

Json Beef0025::toJson() {
	log(3, L"🔈Beef0025 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	// Raw FILETIMEs read from the buffer: UTC by definition of the type.
	o.add(L"Filetime1", Json::str(timeToIso8601Utc(filetime1)));
	o.add(L"Filetime2", Json::str(timeToIso8601Utc(filetime2)));
	return o;
}

Beef0026::Beef0026(LPBYTE buffer, int _level) {
	sps = NULL;
	level = _level;
	isPresent = true;
	signature = L"0xbeef0026";
	idlist = NULL;
	shellitem = NULL;
	const bool datedType = buffer[8] == 0x11 || buffer[8] == 0x10 || buffer[8] == 0x12
	                    || buffer[8] == 0x34 || buffer[8] == 0x31;
	if (datedType && !fits(declaredSize(buffer), 12, 24)) {   // three FILETIMEs from 12
		log(2, L"🔥Beef0026: block too short for its dates, not decoded", ERROR_INVALID_DATA);
	}
	else if (datedType) {
		/* Three FILETIMEs, hence UTC. The local times used to be derived with
		   LocalFileTimeToFileTime — the reverse conversion, with the time zone
		   of the machine running WAC — and the access one from the MODIFICATION
		   date. They now go through the suspect's time zone, like every other
		   UTC date. */
		ctimeUtc = *reinterpret_cast<FILETIME*>(buffer + 12);
		mtimeUtc = *reinterpret_cast<FILETIME*>(buffer + 20);
		atimeUtc = *reinterpret_cast<FILETIME*>(buffer + 28);
		log(3, L"🔈utcToSuspectLocal ctime, mtime, atime");
		utcToSuspectLocal(ctimeUtc, &ctime);
		utcToSuspectLocal(mtimeUtc, &mtime);
		utcToSuspectLocal(atimeUtc, &atime);
		// 2 unknown bytes
		// The nested ID list starts at 38 and must fit in the block.
		const size_t blockSize = declaredSize(buffer);
		const unsigned short innerSize = (blockSize >= 40) ? *reinterpret_cast<unsigned short*>(buffer + 38) : 0;
		if (innerSize >= 3 && innerSize <= blockSize - 38) {
			log(3, L"🔈IdList");
			idlist = std::make_unique<IdList>(buffer + 38, level + 2);
		}
	}
	else {
		ctimeUtc = { 0 };
		ctime = { 0 };
		mtimeUtc = { 0 };
		mtime = { 0 };
		atimeUtc = { 0 };
		atime = { 0 };
		log(3, L"🔈SPS");
		sps = std::make_unique<SPS>(buffer + 8, level + 2, declaredSize(buffer) > 8 ? declaredSize(buffer) - 8 : 0);
	}

}

Json Beef0026::toJson() {
	log(3, L"🔈Beef0026 toJson");
	Json o = Json::obj();
	o.add(L"Signature",           Json::str(signature));
	o.add(L"CreationDate",        Json::str(timeToIso8601Local(ctime)));
	o.add(L"CreationDateUtc",     Json::str(timeToIso8601Utc(ctimeUtc)));
	o.add(L"ModificationDate",    Json::str(timeToIso8601Local(mtime)));
	o.add(L"ModificationDateUtc", Json::str(timeToIso8601Utc(mtimeUtc)));
	o.add(L"AccessedDate",        Json::str(timeToIso8601Local(atime)));
	o.add(L"AccessedDateUtc",     Json::str(timeToIso8601Utc(atimeUtc)));
	if (sps)    o.add(L"SPS",    sps->toJson());
	if (idlist) o.add(L"IdList", idlist->toJson());
	return o;
}

Beef0027::Beef0027(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0027";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, level + 1, declaredSize(buffer) > 8 ? declaredSize(buffer) - 8 : 0);
}

Json Beef0027::toJson() {
	log(3, L"🔈Beef0027 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"SPS",       sps.toJson());
	return o;
}

Beef0029::Beef0029(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	signature = L"0xbeef0029";
	message = L"The purpose of this extension block is unknown";
}

Json Beef0029::toJson() {
	log(3, L"🔈Beef0029 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Message", Json::str(message));
	return o;
}

BeefUnknown::BeefUnknown(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	size = *reinterpret_cast<unsigned short*>(buffer);
	signature = L"0x" + to_hex(*reinterpret_cast<unsigned int*>(buffer + 4));
	log(3, L"🔈dump_wstring BeefUnknown");
	data = dump_wstring(buffer, 0, size);
}

Json BeefUnknown::toJson() {
	log(3, L"🔈BeefUnknown toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	o.add(L"Unknown",   Json::boolean(true));
	o.add(L"Size",      Json::num(size));
	// The bytes, so that the block stays decodable later.
	o.add(L"Data",      Json::str(data));
	return o;
}

void getExtensionBlock(LPBYTE buffer, std::vector<std::unique_ptr<IExtensionBlock>>* extensionBlocks, int _level, bool* is_zip, bool is_file) {
	std::unique_ptr<IExtensionBlock> block;
	/*  DECLARED SIZE of the block, read FIRST: the signature lies at offset 4,
	    beyond a block of fewer than 8 bytes. An extension block is at least 8
	    bytes: its size, its version and its signature. Below that, the
	    structure is wrong and parsing it would read fields taken anywhere. */
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	if (size < 8) {
		log(2, L"🔥Extension block of size " + std::to_wstring(size)
		     + L" (minimum 8) ignored", ERROR_INVALID_DATA);
		return;
	}
	unsigned int signature = *reinterpret_cast<unsigned int*>(buffer + 4);
	/*  FIXED PART of each decoded block: the constructors read their fields at
	    fixed offsets, which a block of the right signature but too short does
	    not hold. Such a block is kept raw, as an unknown one — its bytes stay
	    in the output, nothing is read beyond it. */
	static const std::map<unsigned int, size_t> FIXED_PART = {
		{ 0xBeef0000, 40 },   // two GUIDs at 8 and 24
		{ 0xBeef0003, 24 },   // GUID at 8
		{ 0xBeef0004, 18 },   // dates and identifier, up to 18
		{ 0xBeef000e, 32 },   // GUID at 16
		{ 0xBeef0019, 40 },   // two GUIDs at 8 and 24
		{ 0xBeef0025, 28 },   // two FILETIMEs at 12 and 20
		{ 0xBeef0026,  9 },   // type byte at 8
	};
	const auto fixedPart = FIXED_PART.find(signature);
	if (fixedPart != FIXED_PART.end() && size < fixedPart->second) {
		log(2, L"🔥Extension block 0x" + to_hex(signature) + L" of " + std::to_wstring(size)
		     + L" bytes, shorter than its fixed part (" + std::to_wstring(fixedPart->second)
		     + L"): kept raw", ERROR_INVALID_DATA);
		extensionBlocks->push_back(std::make_unique<BeefUnknown>(buffer, _level));
		return;
	}
	if (signature == (unsigned int)0xBeef0000) {
		log(3, L"🔈Beef0000");
		block = std::make_unique<Beef0000>(buffer, _level + 1);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0001) {
		log(3, L"🔈Beef0001");
		block = std::make_unique<Beef0001>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0002) {
		log(3, L"🔈Beef0002");
		block = std::make_unique<Beef0002>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0003) {
		log(3, L"🔈Beef0003");
		block = std::make_unique<Beef0003>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0004) {
		log(3, L"🔈Beef0004");
		block = std::make_unique<Beef0004>(buffer, _level, is_zip, is_file);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0006) {
		log(3, L"🔈Beef0006");
		block = std::make_unique<Beef0006>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0008) {
		log(3, L"🔈Beef0008");
		block = std::make_unique<Beef0008>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0009) {
		log(3, L"🔈Beef0009");
		block = std::make_unique<Beef0009>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef000a) {
		log(3, L"🔈Beef000a");
		block = std::make_unique<Beef000a>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef000c) {
		log(3, L"🔈Beef000c");
		block = std::make_unique<Beef000c>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef000e) {
		log(3, L"🔈Beef000e");
		block = std::make_unique<Beef000e>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0010) {
		log(3, L"🔈Beef0010");
		block = std::make_unique<Beef0010>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0013) {
		log(3, L"🔈Beef0013");
		block = std::make_unique<Beef0013>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0014) {
		log(3, L"🔈Beef0014");
		block = std::make_unique<Beef0014>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0016) {
		log(3, L"🔈Beef0016");
		block = std::make_unique<Beef0016>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0017) {
		log(3, L"🔈Beef0017");
		block = std::make_unique<Beef0017>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0019) {
		log(3, L"🔈Beef0019");
		block = std::make_unique<Beef0019>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef001a) {
		log(3, L"🔈Beef001a");
		block = std::make_unique<Beef001a>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef001b) {
		log(3, L"🔈Beef001b");
		block = std::make_unique<Beef001b>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef001d) {
		log(3, L"🔈Beef001d");
		block = std::make_unique<Beef001d>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef001e) {
		log(3, L"🔈Beef001e");
		block = std::make_unique<Beef001e>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0021) {
		log(3, L"🔈Beef0021");
		block = std::make_unique<Beef0021>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0024) {
		log(3, L"🔈Beef0024");
		block = std::make_unique<Beef0024>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0025) {
		log(3, L"🔈Beef0025");
		block = std::make_unique<Beef0025>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0026) {
		log(3, L"🔈Beef0026");
		block = std::make_unique<Beef0026>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0027) {
		log(3, L"🔈Beef0027");
		block = std::make_unique<Beef0027>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else if (signature == (unsigned int)0xBeef0029) {
		log(3, L"🔈Beef0029");
		block = std::make_unique<Beef0029>(buffer, _level);
		extensionBlocks->push_back(std::move(block));
	}
	else {
		/* The dump went ONLY into the log, and the block was not added to the list:
		   it therefore did not appear in the JSON, and vanished entirely at the
		   default log level. It is now emitted like the others, with its bytes
		   (see BeefUnknown). */
		log(3, L"🔈BeefUnknown");
		block = std::make_unique<BeefUnknown>(buffer, _level);
		log(3, L"🔈to_hex signature");
		log(2, L"🔥Extension block unknown 0x" + to_hex(signature));
		extensionBlocks->push_back(std::move(block));
	}
}

/********************************************************************************************************************
* shell items
*********************************************************************************************************************/

ShellVolumeFlags::ShellVolumeFlags(unsigned char i) {
	None = (i & (unsigned char)0x8f) == (unsigned char)0x00 ? true : false;
	SystemFolder = (i & (unsigned char)0x8f) == (unsigned char)0x0e ? true : false;
	LocalDisk = (i & (unsigned char)0x8f) == (unsigned char)0x0f ? true : false;
}

std::wstring ShellVolumeFlags::to_wstring() {
	std::wstring result = L"";
	if (None == true) result += L"NONE, ";
	if (SystemFolder == true) result += L"SYSTEMFOLDER, ";
	if (LocalDisk == true) result += L"LOCALDISK, ";
	if (result.size() > 0)
		return std::wstring(&result[0], &result[0] + result.size() - 2);
	else
		return result;
}

FsFlags::FsFlags(unsigned char i) {
	IS_DIRECTORY = (i & (unsigned char)0x01) ? true : false;
	IS_FILE = (i & (unsigned char)0x02) ? true : false;
	IS_UNICODE = (i & (unsigned char)0x04) ? true : false;
	UNKNOWN = (i & (unsigned char)0x08) ? true : false;
	HAS_CLSID = (i & (unsigned char)0x80) ? true : false;
}

std::wstring FsFlags::to_wstring() {
	std::wstring result = L"";
	if (IS_DIRECTORY == true) result += L"IS_DIRECTORY, ";
	if (IS_FILE == true) result += L"IS_FILE, ";
	if (IS_UNICODE == true) result += L"IS_UNICODE, ";
	if (HAS_CLSID == true) result += L"HAS_CLSID, ";
	if (UNKNOWN == true) result += L"UNKNOWN, ";

	if (result.size() > 0)
		return std::wstring(&result[0], &result[0] + result.size() - 2);// remove the last comma and space
	else
		return result;
}

VolumeShellItem::VolumeShellItem(LPBYTE buffer, unsigned char type_char, int _level) {

	level = _level;
	isPresent = true;
	name = L"";
	guid = L"";
	identifier = L"";
	log(3, L"🔈ShellVolumeFlags");
	flags = ShellVolumeFlags(type_char);
	std::wstring volumeName = L"";
	if (flags.LocalDisk == true) {
		log(3, L"🔈string_to_wstring name");
		name = string_to_wstring(readNarrowZ(buffer, declaredSize(buffer), 3));
	}
	else if (flags.SystemFolder == true && fits(declaredSize(buffer), 4, 16)) {
		log(3, L"🔈guid_to_wstring guid");
		guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 4));
		log(3, L"🔈trans_guid_to_wstring name");
		name = trans_guid_to_wstring(guid);
		log(3, L"🔈trans_guid_to_wstring identifier");
		identifier = trans_guid_to_wstring(guid);
	}
	else if (flags.None != true) {
		log(2, L"🔥OROpenKey VolumeShellItem flag unknown : " + to_hex(type_char));
	}

}

Json VolumeShellItem::toJson() {
	log(3, L"🔈VolumeShellItem toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"Flags", Json::str(flags.to_wstring()));
	o.add(L"Name",  Json::str(name));
	if (!guid.empty()) {
		o.add(L"GUID",       Json::str(guid));
		o.add(L"Identifier", Json::str(identifier));
	}
	return o;
}

ControlPanel::ControlPanel(LPBYTE buffer, unsigned short int itemSize, int _level) {
	level = _level;
	isPresent = true;
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 14));
	log(3, L"🔈trans_guid_to_wstring identifier");
	identifier = trans_guid_to_wstring(guid);
	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + itemSize - 2);
	if (extensionOffset != 0x00) {
		unsigned short int pos = extensionOffset;
		while (pos < itemSize) {
			// The block declares its size: it must fit in what is left of the item.
			unsigned short int size = ((size_t)pos + 2 <= (size_t)itemSize) ? *reinterpret_cast<unsigned short int*>(buffer + pos) : 0;
			if (size > 0 && pos < itemSize && size <= (size_t)itemSize - (size_t)pos) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, level + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

Json ControlPanel::toJson() {
	log(3, L"🔈ControlPanel toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"GUID",       Json::str(guid));
	o.add(L"Identifier", Json::str(identifier));
	Json blocks = Json::arr();
	for (const auto& b : extensionBlocks) blocks.push(b->toJson());
	o.add(L"ExtensionBlocksCount", Json::num((unsigned long long)extensionBlocks.size()));
	o.add(L"ExtensionBlocks",      std::move(blocks));
	return o;
}

ControlPanelCategory::ControlPanelCategory(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	unsigned short int totalsize = *reinterpret_cast<unsigned short int*>(buffer);
	switch (*reinterpret_cast<unsigned int*>(buffer + 8)) {
	case 0: id = L"All Control Panel Items"; break;
	case 1: id = L"Appearance and Personalization"; break;
	case 2: id = L"Hardware and Sound"; break;
	case 3: id = L"Network and Internet"; break;
	case 4: id = L"Sounds, Speech, and Audio Devices"; break;
	case 5: id = L"System and Security"; break;
	case 6: id = L"Clock, Language, and Region"; break;
	case 7: id = L"Ease of Access"; break;
	case 8: id = L"Programs"; break;
	case 9: id = L"User Accounts"; break;
	case 10:id = L"Security Center (Windows XP [SP2~SP3])"; break;
	case 11:id = L"Mobile PC (Windows Vista Mobile)"; break;
	default: id = L"Unknown"; break;
	}
	if (totalsize > 14) { // extension Block is present
		int pos = 12;
		while (true) {
			// The block declares its size: it must fit in what is left of the item.
			unsigned short int size = ((size_t)pos + 2 <= (size_t)totalsize) ? *reinterpret_cast<unsigned short int*>(buffer + pos) : 0;
			if (size > 0 && pos < totalsize && size <= (size_t)totalsize - (size_t)pos) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, level + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

Json ControlPanelCategory::toJson() {
	log(3, L"🔈ControlPanelCategory toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"ID", Json::str(id));
	Json blocks = Json::arr();
	for (const auto& b : extensionBlocks) blocks.push(b->toJson());
	o.add(L"ExtensionBlocksCount", Json::num((unsigned long long)extensionBlocks.size()));
	o.add(L"ExtensionBlocks",      std::move(blocks));
	return o;
}

Property::Property(LPBYTE buffer, int _level, size_t limit) {
	level = _level;
	id = 0;
	type = 0;
	unsigned int pos = 0;
	// GUID (16), identifier (4) and type (4) must fit before anything is read.
	if (limit < 24) {
		typeNotDecoded = true;
		size = 0;
		return;
	}
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	pos += 16;
	id = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	log(3, L"🔈to_FriendlyName FriendlyName");
	FriendlyName = to_FriendlyName(guid, id);
	type = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	log(3, L"🔈getValue");
	value = getValue(buffer, &pos, type, level, (unsigned int)limit, &typeNotDecoded);
	size = pos;
}

Json Property::toJson() {
	log(3, L"🔈Property toJson");
	const bool hexId = (guid == L"{4D545058-4FCE-4578-95C8-8698A9BC0F49}"
	                 || guid == L"{4D545058-8900-40b3-8F1D-DC246E1E8370}");
	Json o = Json::obj();
	o.add(L"ID",           Json::str(guid + L"/" + (hexId ? to_hex(id) : std::to_wstring(id))));
	o.add(L"Type",         Json::str(getType(type)));
	o.add(L"FriendlyName", Json::str(FriendlyName));
	o.add(L"Value",        value);
	return o;
}

UserPropertyView0xC01::UserPropertyView0xC01(LPBYTE buffer, int _level) {
	level = _level;
	/*  BOTH strings declare their size, in bytes. They were read up to the first
	    zero met: on a damaged structure, the reading went beyond the area. The
	    declared size now bounds each of them, and the possible terminator is
	    removed afterwards. */
	const size_t itemSize = declaredSize(buffer);
	auto boundedString = [&](size_t at, size_t bytes) {
		if (bytes == 0 || !fits(itemSize, at, bytes)) return std::wstring();
		std::wstring s((const wchar_t*)(buffer + at), bytes / sizeof(wchar_t));
		while (!s.empty() && s.back() == L'\0') s.pop_back();
		return s;
	};
	size_t pos = 0x14;//unknown
	if (!fits(itemSize, pos, 4)) return;
	const size_t wstring1Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	folder = boundedString(pos, wstring1Size);
	if (!fits(itemSize, pos, wstring1Size)) return;
	pos += wstring1Size;
	pos += 16;//unknown
	if (!fits(itemSize, pos, 4)) return;
	const size_t wstring2Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	fullurl = boundedString(pos, wstring2Size);
}

Json UserPropertyView0xC01::toJson() {
	log(3, L"🔈UserPropertyView0xC01 toJson");
	Json o = Json::obj();
	o.add(L"Folder",  Json::str(folder));
	o.add(L"FullUrl", Json::str(fullurl));
	return o;
}

UserPropertyView0x23febbee::UserPropertyView0x23febbee(LPBYTE buffer, int _level) {
	level = _level;
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 0xE));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guid);
}

Json UserPropertyView0x23febbee::toJson() {
	log(3, L"🔈UserPropertyView0x23febbee toJson");
	Json o = Json::obj();
	o.add(L"GUID",         Json::str(guid));
	o.add(L"FriendlyName", Json::str(FriendlyName));
	return o;
}

UserPropertyView0x07192006::UserPropertyView0x07192006(LPBYTE buffer, int _level) {
	level = _level;
	const size_t itemSize = declaredSize(buffer);
	if (itemSize < 74) {   // dates and the three name sizes, up to 74
		log(2, L"🔥MTP File Entry of " + std::to_wstring(itemSize) + L" bytes: too short, not decoded",
		    ERROR_INVALID_DATA);
		return;
	}
	modifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 26);
	createdUtc = *reinterpret_cast<FILETIME*>(buffer + 34);
	log(3, L"🔈timeToIso8601 modifiedUtc");
	if (!timeToIso8601Utc(modifiedUtc).empty()) {
		log(3, L"🔈utcVersLocalSuspect modifiedUtc");
		utcToSuspectLocal(modifiedUtc, &modified);
	}
	else
		modified = { 0 };
	log(3, L"🔈timeToIso8601 createdUtc");
	if (!timeToIso8601Utc(createdUtc).empty()) {
		log(3, L"🔈utcVersLocalSuspect created");
		utcToSuspectLocal(createdUtc, &created);
	}
	else
		created = { 0 };
	// Sizes in characters, unsigned: a huge one yields an offset beyond the
	// item, which readWideZ reads as empty and fits() refuses.
	const size_t folderName1Size = *reinterpret_cast<unsigned int*>(buffer + 62);
	const size_t folderName2Size = *reinterpret_cast<unsigned int*>(buffer + 66);
	const size_t folderIdentifiersize = *reinterpret_cast<unsigned int*>(buffer + 70);

	folderName1 = readWideZ(buffer, itemSize, 74);
	folderName2 = readWideZ(buffer, itemSize, 74 + folderName1Size * 2);
	folderIdentifier = readWideZ(buffer, itemSize, 74 + (folderName1Size + folderName2Size) * 2);

	size_t pos = 74 + (folderName1Size + folderName2Size + folderIdentifiersize) * 2;
	pos += 4;//unknown
	if (!fits(itemSize, pos, 16 + 4)) {   // class GUID and number of properties
		log(2, L"🔥MTP File Entry: names overrun the item, class and properties not read",
		    ERROR_INVALID_DATA);
		return;
	}
	log(3, L"🔈guid_to_wstring guidClass");
	guidClass = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guidClass);
	pos += 16;

	unsigned int numberProperties = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	for (unsigned int x = 0; x < numberProperties; x++) {
		log(3, L"🔈Property");
		if (pos >= itemSize) break;      // end of the shell item
		Property temp(buffer + pos, level + 1, itemSize - pos);
		if (temp.size == 0) break;       // nothing consumed: the walk would not advance
		const bool stop = temp.typeNotDecoded;   // undetermined size, see idList.h
		pos += temp.size;
		properties.push_back(std::move(temp));
		if (stop) {
			log(2, L"🔥Property: type not decoded, walk stopped after "
			     + std::to_wstring(x + 1) + L"/" + std::to_wstring(numberProperties),
			    ERROR_INVALID_DATA);
			break;
		}
	}
}

Json UserPropertyView0x07192006::toJson() {
	log(3, L"🔈UserPropertyView0x07192006 toJson");
	Json o = Json::obj();
	o.add(L"Folder1",          Json::str(folderName1));
	o.add(L"Folder2",          Json::str(folderName2));
	o.add(L"FolderIdentifier", Json::str(folderIdentifier));
	o.add(L"CreatedDate",      Json::str(timeToIso8601Local(created)));
	o.add(L"CreatedDateUtc",   Json::str(timeToIso8601Utc(createdUtc)));
	o.add(L"ModifiedDate",     Json::str(timeToIso8601Local(modified)));
	o.add(L"ModifiedDateUtc",  Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"GUIDClass",        Json::str(guidClass));
	o.add(L"FriendlyName",     Json::str(FriendlyName));
	Json props = Json::arr();
	for (Property& p : properties) props.push(p.toJson());
	o.add(L"Properties", std::move(props));
	return o;
}

UserPropertyView0x10312005::UserPropertyView0x10312005(LPBYTE buffer, int _level) {
	/* All the lengths below come from the file parsed — hence from an untrusted
	   source — and serve to compute reading offsets. Every read is bounded by
	   the item's declared size, which the caller checked against the buffer.
	   The lengths are also bounded to the PLAUSIBLE maximum: a shell item
	   carries its size on 16 bits, it cannot exceed 64 KiB, that is 32,768
	   UTF-16 characters. A value beyond that signals corrupted or forged data,
	   and the reading is abandoned. */
	constexpr int MAX_CARS = 32768;        // 64 KiB / 2: the maximum size of a shell item
	constexpr unsigned MAX_ELEMENTS = 1024; // well beyond the plausible, but finite

	level = _level;
	const size_t itemSize = declaredSize(buffer);
	if (itemSize < 0x36) {   // the four sizes, up to 0x36
		log(2, L"🔥MTP Volume of " + std::to_wstring(itemSize) + L" bytes: too short, not decoded",
		    ERROR_INVALID_DATA);
		return;
	}
	int namesize = *reinterpret_cast<unsigned int*>(buffer + 0x26);
	int identifiersize = *reinterpret_cast<unsigned int*>(buffer + 0x2A);
	int filesystemsize = *reinterpret_cast<unsigned int*>(buffer + 0x2E);
	int nbGUIDStrings = *reinterpret_cast<unsigned int*>(buffer + 0x32);

	if (namesize < 0 || namesize > MAX_CARS
	 || identifiersize < 0 || identifiersize > MAX_CARS
	 || filesystemsize < 0 || filesystemsize > MAX_CARS
	 || nbGUIDStrings < 0 || (unsigned)nbGUIDStrings > MAX_ELEMENTS) {
		log(2, L"🔥UserPropertyView0x10312005: invalid lengths (name "
		     + std::to_wstring(namesize) + L", id " + std::to_wstring(identifiersize)
		     + L", fs " + std::to_wstring(filesystemsize)
		     + L", guids " + std::to_wstring(nbGUIDStrings) + L")", ERROR_INVALID_DATA);
		return;                            // fields left empty: nothing doubtful is published
	}

	name = readWideZ(buffer, itemSize, 0x36);
	identifier = readWideZ(buffer, itemSize, 0x36 + namesize * 2);
	filesystem = readWideZ(buffer, itemSize, 0x36 + namesize * 2 + identifiersize * 2);

	size_t pos = 0x36 + (size_t)(namesize + identifiersize + filesystemsize) * 2;
	for (int x = 0; x < nbGUIDStrings && pos < itemSize; x++) {
		guidstrings.push_back(readWideZ(buffer, itemSize, pos));
		pos += 78;
	}
	pos += 4;//unknown
	if (!fits(itemSize, pos, 16 + 4)) {   // class GUID and number of properties
		log(2, L"🔥MTP Volume: strings overrun the item, class and properties not read",
		    ERROR_INVALID_DATA);
		return;
	}

	log(3, L"🔈guid_to_wstring guidClass");
	guidClass = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guidClass);
	pos += 16;

	/* Interpreting this field as a "number of properties" is not confirmed by the
	   specification: by observation, only the first 4 entries are usable. Until
	   that is settled, the value is bounded and the loop stops if a property
	   returns a null size — otherwise `pos` would no longer advance and the same
	   area would be read again. */
	unsigned int numberProperties = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	if (numberProperties > MAX_ELEMENTS) {
		log(2, L"🔥UserPropertyView0x10312005: implausible number of properties ("
		     + std::to_wstring(numberProperties) + L"): reading abandoned", ERROR_INVALID_DATA);
		numberProperties = 0;
	}
	for (unsigned int x = 0; x < numberProperties; x++) {
		log(3, L"🔈Property");
		if (pos >= declaredSize(buffer)) break;      // end of the shell item
		Property temp(buffer + pos, level + 1, declaredSize(buffer) - pos);
		if (temp.size == 0) {
			log(2, L"🔥Property of null size: walk stopped", ERROR_INVALID_DATA);
			break;
		}
		const bool stop = temp.typeNotDecoded;   // undetermined size, see idList.h
		pos += temp.size;
		properties.push_back(std::move(temp));
		if (stop) {
			log(2, L"🔥Property: type not decoded, walk stopped after "
			     + std::to_wstring(x + 1) + L"/" + std::to_wstring(numberProperties),
			    ERROR_INVALID_DATA);
			break;
		}
	}
}

Json UserPropertyView0x10312005::toJson() {
	log(3, L"🔈UserPropertyView0x10312005 toJson");
	Json o = Json::obj();
	o.add(L"Name",        Json::str(name));
	o.add(L"Identifier",  Json::str(identifier));
	// FIX: the original key was "Star-system", the remnant of a botched
	// search-and-replace. It published the file system's name under a heading no
	// one can guess: information collected but impossible to find in analysis.
	o.add(L"FileSystem",  Json::str(filesystem));
	Json guids = Json::arr();
	for (const std::wstring& g : guidstrings) {
		Json e = Json::obj();
		e.add(L"Guid",         Json::str(g));
		e.add(L"FriendlyName", Json::str(trans_guid_to_wstring(g)));
		guids.push(std::move(e));
	}
	o.add(L"GUIDStrings",  std::move(guids));
	o.add(L"GUIDClass",    Json::str(guidClass));
	o.add(L"Friendlyname", Json::str(FriendlyName));
	Json props = Json::arr();
	for (Property& p : properties) props.push(p.toJson());
	o.add(L"Properties", std::move(props));
	return o;
}

UsersPropertyView::UsersPropertyView(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	extensionOffset = 0;
	spsOffset = 0;
	delegate = NULL;
	unsigned int pos = 0;

	totalsize = *reinterpret_cast<unsigned short int*>(buffer + 0);
	dataSize = *reinterpret_cast<unsigned short int*>(buffer + 4);
	signature = *reinterpret_cast<unsigned int*>(buffer + 6);
	unsigned short int signature_short = *reinterpret_cast<unsigned short int*>(buffer + 6); // Some signatures are identified by their first 2 bytes
	SPSDataSize = *reinterpret_cast<unsigned short int*>(buffer + 10);
	identifierSize = *reinterpret_cast<unsigned short int*>(buffer + 12);
	dataOffset = 14;

	/* NATURE OF THE ITEM, from its signature.
	 *
	 * At libyal (libfwsi_users_property_view_values.c) the signature does not
	 * only serve to choose a decoder: it IDENTIFIES the kind of item. Two of
	 * those handled here are not "users property views" at all:
	 *   0x10312005 = MTP VOLUME,      0x07192006 = MTP FILE ENTRY,
	 * that is the trace that a phone, a camera or a media player was plugged in
	 * and browsed. The generic name hid that fact, which is precisely what an
	 * investigation looks for.
	 * The `itemType` field now names it in the output. */
	switch (signature) {
	case 0x10312005: itemType = L"MTP Volume";                          break;
	case 0x07192006: itemType = L"MTP File Entry";                       break;
	case 0x23febbee: itemType = L"Users Property View (known folder)";   break;
	/* The next four are recognised by libfwsi and were not handled: the item fell
	   into the "unknown signature" branch. */
	case 0x10141981:
	case 0x23a3dfd5:
	case 0x3b93afbb:
	case 0x49505241:
	case 0xbeebee00: itemType = L"Users Property View";                  break;
	default: break;
	}

	if (signature == (unsigned int)0x23febbee) {
		/* KNOWN FOLDER GUID, and only if the identifier IS a GUID.
		   libfwsi reads those 16 bytes on condition `identifier_size == 16`; WAC
		   checked nothing and therefore published a GUID made of arbitrary bytes
		   as soon as the identifier had another size. */
		if (identifierSize == 16 && fits(totalsize, 0xE, 16)) {
			log(3, L"🔈UserPropertyView0x23febbee");
			delegate = std::make_unique<UserPropertyView0x23febbee>(buffer, level);
		}
		else
			log(2, L"🔥0x23febbee: identifier of " + std::to_wstring(identifierSize)
			     + L" bytes instead of 16, GUID not read");
		identifierSize += 2;
	}
	else if (signature == (unsigned int)0x10312005) {
		log(3, L"🔈MTP Volume");
		delegate = std::make_unique<UserPropertyView0x10312005>(buffer, level);
	}
	else if (signature == (unsigned int)0x07192006) {
		log(3, L"🔈MTP File Entry");
		delegate = std::make_unique<UserPropertyView0x07192006>(buffer, level);
	}
	else if (signature_short == (unsigned int)0xC001) {
		log(3, L"🔈UserPropertyView0xC01");
		delegate = std::make_unique<UserPropertyView0xC01>(buffer, level);
		signature = signature_short;
	}
	/* Signatures listed by libfwsi without a structure of their own: the item
	   carries an identifier then its property store. Three of them have a 4-byte
	   identifier, which libfwsi reads. */
	else if (!itemType.empty()) {
		if (identifierSize == 4 && fits(totalsize, dataOffset, 4)) {
			identifier32 = *reinterpret_cast<unsigned int*>(buffer + dataOffset);
			identifier32Lu = true;
		}
		spsOffset = dataOffset + identifierSize;
		while (true) {
			log(3, L"🔈SPS");
			const size_t at = (size_t)spsOffset + pos;
			SPS block(buffer + at, level + 1, at < declaredSize(buffer) ? declaredSize(buffer) - at : 0);
			if (block.size && pos < SPSDataSize) SPSs.push_back(block);
			else break;
			pos += block.size;
		}
	}
	else if (SPSDataSize > 0) {
		spsOffset = dataOffset + identifierSize;
		while (true) {
			log(3, L"🔈SPS");
			const size_t at = (size_t)spsOffset + pos;
			SPS block(buffer + at, level + 1, at < declaredSize(buffer) ? declaredSize(buffer) - at : 0);
			if (block.size && pos < SPSDataSize) {
				SPSs.push_back(block);
			}
			else
				break;
			pos += block.size;
		}
	}
	else {
		/* Unrecognised signature: the bytes are kept IN THE OUTPUT, and no longer only
		   in the log (see idList.h). Otherwise the object came down to its type
		   and a signature, which allows neither analysing it nor even knowing
		   that something was lost. */
		log(3, L"🔈dump_wstring UsersPropertyView: unknown signature");
		data = dump_wstring(buffer, 0, totalsize);
		log(2, L"🔥UsersPropertyView Signature 0x" + to_hex(signature) + L" unknown");
	}

	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + totalsize - 2);
	if (extensionOffset != 0x00) {
		pos = extensionOffset;
		while (pos < totalsize) {
			// The block declares its size: it must fit in what is left of the item.
			unsigned short int size = ((size_t)pos + 2 <= (size_t)totalsize) ? *reinterpret_cast<unsigned short int*>(buffer + pos) : 0;
			if (size > 0 && pos < totalsize && size <= (size_t)totalsize - (size_t)pos) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, level + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

Json UsersPropertyView::toJson() {
	log(3, L"🔈UsersPropertyView toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"Signature", Json::str(L"0x" + to_hex(signature)));
	// Nature of the item: "MTP Volume", "MTP File Entry"… see idList.h.
	if (!itemType.empty()) o.add(L"ItemType", Json::str(itemType));
	if (identifier32Lu)    o.add(L"Identifier", Json::num(identifier32));
	// the delegate's fields are flattened (the original schema)
	if (delegate) o.merge(delegate->toJson());

	/* SPS AND EXTENSION BLOCKS: THEY WERE COLLECTED AND NEVER EMITTED.
	   The constructor fills `SPSs` (the branch without a delegate) and
	   `extensionBlocks` (always, if the object carries some), but toJson
	   published none of them: all their content — property names, values,
	   dates — was read then thrown away. The delegates carry `properties`, not
	   these two vectors: there is therefore no duplicate to fear. */
	if (!SPSs.empty()) {
		Json arr = Json::arr();
		for (SPS& sps : SPSs) arr.push(sps.toJson());
		o.add(L"PropertyStores", std::move(arr));
	}
	if (!extensionBlocks.empty()) {
		Json arr = Json::arr();
		for (const auto& b : extensionBlocks) arr.push(b->toJson());
		o.add(L"ExtensionBlocksCount", Json::num((unsigned long long)extensionBlocks.size()));
		o.add(L"ExtensionBlocks",      std::move(arr));
	}
	// Raw bytes if the signature was not recognised (see idList.h).
	if (!data.empty()) {
		o.add(L"Unknown", Json::boolean(true));
		o.add(L"Data",    Json::str(data));
	}
	return o;
}

RootFolder::RootFolder(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned char type = *reinterpret_cast<unsigned char*>(buffer + 3);
	log(3, L"🔈sort_index type");
	sortIndex = sort_index(type);

	guid = L"";
	identifier = L"";

	/* The SIGNATURE at 6 identifies the drive and search-folder forms, as in
	   libfwsi; the size decided first, and a drive item of 0x3a bytes or less —
	   the form a delegate folder holds once its trailer is removed — was read
	   as a GUID. */
	const unsigned int signature = (size >= 10) ? *reinterpret_cast<unsigned int*>(buffer + 6) : 0;
	if (signature == (unsigned int)0xf5a6b710) {
		sortIndex = L"DRIVE";
		log(3, L"🔈string_to_wstring identifier");
		identifier = string_to_wstring(readNarrowZ(buffer, size, 13));
	}
	else if (signature == (unsigned int)0x23a3dfd5) {
		sortIndex = L"SEARCH_FOLDER";
		unsigned int pos = 0x12;
		while (true) {
			log(3, L"🔈SPS");
			SPS block(buffer + pos, level + 1, pos < size ? size - pos : 0);
			if (block.size > 0 && pos < size) {
				SPSs.push_back(block);
			}
			else
				break;
			pos += block.size;
		}
	}
	else if (size >= (unsigned short int)0x14 && size <= (unsigned short int)0x3a) {
		sortIndex = L"GUID";
		log(3, L"🔈guid_to_wstring guid");
		guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 4));
		log(3, L"🔈trans_guid_to_wstring identifier");
		identifier = trans_guid_to_wstring(guid);
	}
	if (sortIndex == L"UNKNOWN") {
		log(2, L"🔥RootFolder : sortIndex Unknown 0x" + to_hex(type));
	}
	/* TODO: this is a simplified version that seems enough for now, in line with
	* the Windows Shell Item format specification https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#43-control-panel-shell-items
	* The code at the address below is more complete
	* https://github.com/49374/OverTheShellbags/blob/main/OverTheShellbags/shell_item_parser.py#L11
	*/

}

Json RootFolder::toJson() {
	log(3, L"🔈RootFolder toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"SortIndex", Json::str(sortIndex));
	if (!guid.empty())       o.add(L"GUID",       Json::str(guid));
	if (!identifier.empty()) o.add(L"Identifier", Json::str(identifier));
	if (!SPSs.empty()) {
		Json arr = Json::arr();
		for (SPS& sp : SPSs) arr.push(sp.toJson());
		o.add(L"SPS", std::move(arr));
	}
	return o;
}

NetworkShellItem::NetworkShellItem(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	unsigned char subtype = *reinterpret_cast<unsigned char*>(buffer + 2);
	log(3, L"🔈networkSubType");
	subtypename = networkSubType(subtype);

	if (subtypename == L"Unknown")
		log(2, L"🔥NetworkShellItem : Subtype Unknown 0x" + to_hex(subtype));
	if (subtype == 0xC3) {
		log(3, L"🔈string_to_wstring location");
		location = string_to_wstring(readNarrowZ(buffer, declaredSize(buffer), 5));
	}
	else if (fits(declaredSize(buffer), 0x54, 8)) {   // up to the two sizes at 0x54
		log(3, L"🔈wstring_to_filetime modifiedUtc");
		modifiedUtc = wstring_to_filetime(readWideZ(buffer, declaredSize(buffer), 0x24));
		log(3, L"🔈utcVersLocalSuspect modified");
		utcToSuspectLocal(modifiedUtc, &modified);
		unsigned int descriptionsize = *reinterpret_cast<unsigned int*>(buffer + 0x54);
		unsigned int commentssize = *reinterpret_cast<unsigned int*>(buffer + 0x58);
		int pos = 0x5c;
		if (descriptionsize > 0)
		{
			description = readWideZ(buffer, declaredSize(buffer), pos);
			pos += descriptionsize * 2 + 2;
		}
		if (commentssize > 0)
			comments = readWideZ(buffer, declaredSize(buffer), pos);
	}
}

Json NetworkShellItem::toJson() {
	log(3, L"🔈NetworkShellItem toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"Type", Json::str(subtypename));
	if (!location.empty()) {
		o.add(L"Location", Json::str(location));
	} else {
		o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
		o.add(L"Modified",    Json::str(timeToIso8601Local(modified)));
		o.add(L"Description", Json::str(description));
		o.add(L"Comments",    Json::str(comments));
	}
	return o;
}

ArchiveFileContent::ArchiveFileContent(LPBYTE buffer, int _level) {
	isPresent = true;
	level = _level;
	unsigned int date = *reinterpret_cast<unsigned int*>(buffer + 8);

	if (date == 0) {
		if (!fits(declaredSize(buffer), 0x10, 8)) {
			log(2, L"🔥ArchiveFileContent: item too short for its date", ERROR_INVALID_DATA);
		}
		else if (*reinterpret_cast<unsigned int*>(buffer + 0x10) != 0) { // FILETIME
			modifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 0x10);

			log(3, L"🔈timeToIso8601 modifiedUtc");
			if (timeToIso8601Utc(modifiedUtc) != L"") {
				log(3, L"🔈utcVersLocalSuspect modified");
				utcToSuspectLocal(modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = readWideZ(buffer, declaredSize(buffer), 0x20);
		}
		else { // DATE EN WSTRING
			log(3, L"🔈wstring_to_filetime modifiedUtc");
			modifiedUtc = wstring_to_filetime(readWideZ(buffer, declaredSize(buffer), 0x24));
			log(3, L"🔈timeToIso8601 modifiedUtc");
			if (timeToIso8601Utc(modifiedUtc) != L"") {
				log(3, L"🔈utcVersLocalSuspect modified");
				utcToSuspectLocal(modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = readWideZ(buffer, declaredSize(buffer), 0x5C);
		}
	}
	else {
		// FAT date = LOCAL time: UTC is derived from it, not the reverse.
		modified = FatDateTime(date).toFileTime();
		log(3, L"🔈LocalFileTimeToFileTime modified");
		LocalFileTimeToFileTime(&modified, &modifiedUtc);
		log(3, L"🔈string_to_wstring modified");
		name = string_to_wstring(readNarrowZ(buffer, declaredSize(buffer), 0x1C));
	}
}

Json ArchiveFileContent::toJson() {
	log(3, L"🔈ArchiveFileContent toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"ModifiedUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"Modified",    Json::str(timeToIso8601Local(modified)));
	o.add(L"Name",        Json::str(name));
	return o;
}

URIShellItem::URIShellItem(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	// SIZE OF THE ITEM: it bounds the URI, which was read up to the first zero
	// met — hence possibly beyond the item.
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned short int datasize = *reinterpret_cast<unsigned short int*>(buffer + 4);
	if (datasize == 0 && size > 8) {
		uri = std::wstring((const wchar_t*)(buffer + 8), (size - 8) / sizeof(wchar_t));
		while (!uri.empty() && uri.back() == L'\0') uri.pop_back();
	}
}

Json URIShellItem::toJson() {
	log(3, L"🔈URIShellItem toJson");
	Json o = Json::obj();
	if (isPresent) o.add(L"Uri", Json::str(uri));
	return o;
}

FileEntryShellItem::FileEntryShellItem(LPBYTE buffer, unsigned short int itemSize, unsigned char shell_item_type_char, int _level) {
	level = _level;
	isPresent = true;
	fsFileSize = *reinterpret_cast<unsigned int*>(buffer + 4);
	log(3, L"🔈FatDateTime");
	// FAT date = LOCAL time: UTC is derived from it, not the reverse.
	fsFileModification = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime fsFileModification");
	LocalFileTimeToFileTime(&fsFileModification, &fsFileModificationUtc);
	log(3, L"🔈FsFlags");
	fsFlags = FsFlags(shell_item_type_char);
	log(3, L"🔈FileAttributes");
	fsFileAttributes = FileAttributes((unsigned int)*reinterpret_cast<unsigned short int*>(buffer + 12));

	if (fsFlags.IS_UNICODE)  //Unicode
		fsPrimaryName = readWideZ(buffer, itemSize, 14);
	else {
		log(3, L"🔈string_to_wstring fsPrimaryName");
		fsPrimaryName = string_to_wstring(readNarrowZ(buffer, itemSize, 14));
	}

	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + itemSize - 2);
	unsigned short int pos = extensionOffset;
	if (extensionOffset != 0x00) {
		while (pos < itemSize) {
			// The block declares its size: it must fit in what is left of the item.
			unsigned short int size = ((size_t)pos + 2 <= (size_t)itemSize) ? *reinterpret_cast<unsigned short int*>(buffer + pos) : 0;
			if (size > 0 && pos < itemSize && size <= (size_t)itemSize - (size_t)pos) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, level + 1, &is_zip, fsFlags.IS_FILE);
				pos += size;
			}
			else
				break;
		}
	}
}

Json FileEntryShellItem::toJson() {
	log(3, L"🔈FileEntryShellItem toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"Attributes",          Json::str(fsFileAttributes.to_wstring()));
	o.add(L"Flags",               Json::str(fsFlags.to_wstring()));
	o.add(L"ModificationDate",    Json::str(timeToIso8601Local(fsFileModification)));
	o.add(L"ModificationDateUtc", Json::str(timeToIso8601Utc(fsFileModificationUtc)));
	o.add(L"Size",                Json::num((unsigned long long)fsFileSize));   // count
	o.add(L"Name",                Json::str(fsPrimaryName));
	Json blocks = Json::arr();
	for (const auto& b : extensionBlocks) blocks.push(b->toJson());
	o.add(L"ExtensionBlocksCount", Json::num((unsigned long long)extensionBlocks.size()));
	o.add(L"ExtensionBlocks",      std::move(blocks));
	return o;
}

UsersFilesFolder::UsersFilesFolder(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + size - 2);
	// FAT date = LOCAL time: UTC is derived from it, not the reverse.
	modified = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 0x12)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime modified");
	LocalFileTimeToFileTime(&modified, &modifiedUtc);
	log(3, L"🔈string_to_wstring primaryName");
	primaryName = string_to_wstring(readNarrowZ(buffer, size, 0x18));
	// The block's offset and size come from the item: both must stay inside it.
	const unsigned short blockSize = ((size_t)extensionOffset + 2 <= size)
	                                 ? *reinterpret_cast<unsigned short*>(buffer + extensionOffset) : 0;
	if (extensionOffset >= 4 && blockSize >= 8 && blockSize <= size - extensionOffset) {
		log(3, L"🔈Beef0004");
		extensionBlock = std::make_unique<Beef0004>(buffer + extensionOffset, level + 1, nullptr, false); // The block follows
	}
}

Json UsersFilesFolder::toJson() {
	log(3, L"🔈UsersFilesFolder toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"PrimaryName",     Json::str(primaryName));
	o.add(L"ModifiedDateUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"ModifiedDate",    Json::str(timeToIso8601Local(modified)));
	// guard: extensionBlock may be null
	if (extensionBlock && extensionBlock->isPresent)
		o.add(L"ExtensionBlock", extensionBlock->toJson());
	return o;
}

FavoriteShellitem::FavoriteShellitem(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	log(3, L"🔈UsersPropertyView");
	UPV = UsersPropertyView(buffer, level + 1);
}

Json FavoriteShellitem::toJson() {
	log(3, L"🔈FavoriteShellitem toJson");
	if (isPresent && UPV.isPresent) return UPV.toJson();
	return Json::obj();
}

TypedShellItem::TypedShellItem(LPBYTE buffer, unsigned short size,
                               const std::wstring& _typeName, int _level) {
	level = _level;
	isPresent = true;
	typeName = _typeName;
	log(3, L"🔈dump_wstring TypedShellItem");
	data = dump_wstring(buffer, 0, size);
}

Json TypedShellItem::toJson() {
	log(3, L"🔈TypedShellItem toJson");
	Json o = Json::obj();
	o.add(L"ItemType", Json::str(typeName));
	// Fields not decoded: the bytes stay attached (see idList.h).
	o.add(L"Data",     Json::str(data));
	return o;
}

DelegateFolder::DelegateFolder(LPBYTE buffer, unsigned short size, int _level) {
	level = _level;
	isPresent = true;

	/* GUID of the delegating class: the last 16 bytes of the item. */
	if (size >= 16) {
		log(3, L"🔈guid_to_wstring classGuid");
		classGuid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + size - 16));
		log(3, L"🔈trans_guid_to_wstring classFriendlyName");
		classFriendlyName = trans_guid_to_wstring(classGuid);
	}

	/* DELEGATED DATA: their size on 2 bytes at offset 4, the data from offset 6,
	   then the 32-byte trailer (delegation marker, class GUID). The data
	   continue an item of the class the class byte gives, at the offsets it
	   would have without delegation: the drive letter at 13, the search
	   folder's store at 0x12.
	   Checked on a real machine: 33 delegate items of four forms, the size at 4
	   always equal to the item's size minus 38. The previous version read a
	   4-byte size and expected a complete shell item at offset 6: it rejected
	   every one of them, and the drive letters (E:\, D:\) they carry were lost.
	   The data are decoded on a copy that ENDS before the trailer, its size
	   field adjusted, so that no decoder takes the trailer for its own bytes
	   (a file entry reads its extension offset in its last two bytes). */
	const size_t dataSize = *reinterpret_cast<unsigned short*>(buffer + 4);   // size >= 38
	if (dataSize == 0) {
		log(3, L"🔈DelegateFolder: no delegated data");
	}
	else if (fits((size_t)size - 32, 6, dataSize)) {
		std::vector<BYTE> inner(buffer, buffer + 6 + dataSize);
		*reinterpret_cast<unsigned short*>(inner.data()) = (unsigned short)inner.size();
		log(3, L"🔈makeShellItem: delegated data");
		innerItem = makeShellItem(inner.data(), level + 1, false);
	}
	else {
		log(2, L"🔥DelegateFolder: data size " + std::to_wstring(dataSize)
		     + L" overruns the item", ERROR_INVALID_DATA);
		log(3, L"🔈dump_wstring DelegateFolder");
		data = dump_wstring(buffer, 0, size);
	}
}

Json DelegateFolder::toJson() {
	log(3, L"🔈DelegateFolder toJson");
	Json o = Json::obj();
	o.add(L"ItemType", Json::str(L"Delegate Folder"));
	if (!classGuid.empty()) {
		o.add(L"ClassGuid",    Json::str(classGuid));
		o.add(L"FriendlyName", Json::str(classFriendlyName));
	}
	// The delegated item is flattened, like the other nested shell items.
	if (innerItem) o.add(L"DelegatedItem", innerItem->toJson());
	if (!data.empty()) o.add(L"Data", Json::str(data));
	return o;
}

UnknownShellItem::UnknownShellItem(LPBYTE buffer, int _level) {
	level = _level;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	log(3, L"🔈dump_wstring data");
	data = dump_wstring(buffer, 0, size);
}

Json UnknownShellItem::toJson() {
	log(3, L"🔈UnknownShellItem toJson");
	// FIX: the old version built the string without ever assigning it -> every
	// shell item of an unrecognised type was silently lost. The raw dump is now
	// always returned, so that an unknown type is visible and analysable instead
	// of being ignored.
	Json o = Json::obj();
	o.add(L"Unknown", Json::boolean(true));
	o.add(L"Data",    Json::str(data));   // hexadecimal dump of the item
	return o;
}

std::unique_ptr<IShellItem> makeShellItem(LPBYTE buffer, int _level, bool Parentiszip) {

	unsigned int item_size = *reinterpret_cast<unsigned short int*>(buffer);
	if (Parentiszip == false) {
		/* TYPES RECOGNISED BY A SIGNATURE IN THE DATA, tested BEFORE the class
		 * byte.
		 *
		 * WHAT WAS MISSING. WAC identified a shell item only by its class byte.
		 * But six documented types are not recognised there: they carry a
		 * signature in their data, and libfwsi identifies them by trying every
		 * decoder (libfwsi_item.c). All of them therefore fell into "UNKNOWN",
		 * the most costly being the delegate folder — common in the shellbags,
		 * and wrapping data decodable by the class of the item.
		 *
		 * The order matters: these tests are more specific than the class byte,
		 * they must prevail. Each criterion is libfwsi's, with its minimum size —
		 * without which the check would read outside the item. */
		const unsigned short size = (unsigned short)item_size;

		/* Delegate folder: delegation marker 32 bytes before the end. */
		static const unsigned char GUID_DELEGATION[16] = {
			0x74, 0x1a, 0x59, 0x5e, 0x96, 0xdf, 0xd3, 0x48,
			0x8d, 0x67, 0x17, 0x33, 0xbc, 0xee, 0x28, 0xba };
		if (size >= 38
		    && memcmp(buffer + size - 32, GUID_DELEGATION, 16) == 0) {
			log(3, L"🔈DelegateFolder");
			return std::make_unique<DelegateFolder>(buffer, size, _level);
		}
		// CD burner: ASCII signature "AugM".
		if (size >= 18 && memcmp(buffer + 4, "AugM", 4) == 0) {
			log(3, L"🔈CD Burn");
			return std::make_unique<TypedShellItem>(buffer, size, L"CD Burn", _level);
		}
		// Games folder: ASCII signature "GFSI".
		if (size >= 32 && memcmp(buffer + 4, "GFSI", 4) == 0) {
			log(3, L"🔈Game Folder");
			return std::make_unique<TypedShellItem>(buffer, size, L"Game Folder", _level);
		}
		// Control panel .cpl file: a precise 4-byte value.
		if (size >= 24
		    && *reinterpret_cast<unsigned int*>(buffer + 4) == 0xFFFFFF38UL) {
			log(3, L"🔈Control Panel CPL File");
			return std::make_unique<TypedShellItem>(buffer, size,
			                                        L"Control Panel CPL File", _level);
		}

		unsigned char type_char = *reinterpret_cast<unsigned char*>(buffer + 2);
		log(3, L"🔈shell_item_class");
		std::wstring type = shell_item_class(type_char);
		/* FIXED PART of each decoded type: the offsets its constructor reads
		   unconditionally. The caller has checked the item's declared size
		   against the real buffer, not that it holds the fields of the type the
		   class byte announces. A shorter item is kept raw, as an unknown one. */
		static const std::map<std::wstring, size_t> FIXED_PART = {
			{ L"CONTROL_PANEL",          30 },   // GUID at 14
			{ L"CONTROL_PANEL_CATEGORY", 12 },   // category at 8
			{ L"ROOT_FOLDER",             4 },   // sort index at 3
			{ L"FILE_ENTRY_SHELL_ITEM",  14 },   // size, FAT date, attributes
			{ L"USERS_PROPERTY_VIEW",    14 },   // sizes and signature, up to 14
			{ L"FAVORITE_SHELL_ITEM",    14 },   // a users property view
			{ L"URI",                     6 },   // data size at 4
			{ L"ARCHIVE_FILE_CONTENT",   12 },   // FAT date at 8
			{ L"USERS_FILES_FOLDER",     22 },   // FAT date at 0x12
		};
		const auto fixedPart = FIXED_PART.find(type);
		if (fixedPart != FIXED_PART.end() && item_size < fixedPart->second) {
			log(2, L"🔥Shell item " + type + L" of " + std::to_wstring(item_size)
			     + L" bytes, shorter than its fixed part (" + std::to_wstring(fixedPart->second)
			     + L"): kept raw", ERROR_INVALID_DATA);
			return std::make_unique<UnknownShellItem>(buffer, _level);
		}
		if (type == L"VOLUME_SHELL_ITEM") {
			log(3, L"🔈VolumeShellItem");
			return std::make_unique<VolumeShellItem>(buffer, type_char, _level);
		}
		if (type == L"CONTROL_PANEL") {
			log(3, L"🔈ControlPanel");
			return std::make_unique<ControlPanel>(buffer, item_size, _level);
		}
		if (type == L"CONTROL_PANEL_CATEGORY") {
			log(3, L"🔈ControlPanelCategory");
			return std::make_unique<ControlPanelCategory>(buffer, _level);
		}
		if (type == L"ROOT_FOLDER") {
			log(3, L"🔈RootFolder");
			return std::make_unique<RootFolder>(buffer, _level);
		}
		if (type == L"FILE_ENTRY_SHELL_ITEM") {
			log(3, L"🔈FileEntryShellItem");
			return std::make_unique<FileEntryShellItem>(buffer, item_size, type_char, _level);
		}
		if (type == L"USERS_PROPERTY_VIEW") {
			log(3, L"🔈UsersPropertyView");
			return std::make_unique<UsersPropertyView>(buffer, _level);
		}
		if (type == L"NETWORK_LOCATION_SHELL_ITEM") {
			log(3, L"🔈NetworkShellItem");
			return std::make_unique<NetworkShellItem>(buffer, _level);
		}
		if (type == L"URI") {
			log(3, L"🔈URIShellItem");
			return std::make_unique<URIShellItem>(buffer, _level);
		}
		if (type == L"ARCHIVE_FILE_CONTENT") {
			log(3, L"🔈ArchiveFileContent");
			return std::make_unique<ArchiveFileContent>(buffer, _level);
		}
		if (type == L"USERS_FILES_FOLDER") {
			log(3, L"🔈UsersFilesFolder");
			return std::make_unique<UsersFilesFolder>(buffer, _level);
		}
		if (type == L"FAVORITE_SHELL_ITEM") {
			log(3, L"🔈FavoriteShellitem");
			return std::make_unique<FavoriteShellitem>(buffer, _level);
		}
		/* WEAK CRITERIA, tested LAST — the order follows libfwsi's, which tries
		   `file_entry` before `web_site`.
		   The web site one bears on four bytes at offset 4, and that is where a
		   file entry writes its SIZE: a file of 0xC001B000 bytes would be taken
		   for a web site if that test came first. The Acronis archive one reads
		   the class byte itself. Both are therefore consulted only if no class
		   type answered. */
		if (size >= 24 && buffer[4] == 0x00 && buffer[5] == 0xb0
		    && buffer[6] == 0x01 && buffer[7] == 0xc0) {
			log(3, L"🔈Web Site");
			return std::make_unique<TypedShellItem>(buffer, size, L"Web Site", _level);
		}
		if (size >= 50 && buffer[2] == 0x52 && buffer[3] == 0x67
		    && buffer[4] == 0xb1 && buffer[5] == 0xac) {
			log(3, L"🔈Acronis TIB File");
			return std::make_unique<TypedShellItem>(buffer, size,
			                                        L"Acronis TIB File", _level);
		}

		if (type == L"UNKNOWN") {
			log(3, L"🔈UnknownShellItem");
			return std::make_unique<UnknownShellItem>(buffer, _level);
		}
	}
	else if (item_size >= 12) {   // FAT date at 8, as above
		log(3, L"🔈ArchiveFileContent");
		return std::make_unique<ArchiveFileContent>(buffer, _level);
	}
	else {
		log(2, L"🔥Archive content item of " + std::to_wstring(item_size)
		     + L" bytes, shorter than its fixed part (12): kept raw", ERROR_INVALID_DATA);
		return std::make_unique<UnknownShellItem>(buffer, _level);
	}
	return nullptr;   // no type recognised: never an implicit return
}