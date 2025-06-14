﻿#include "idList.h"
#include <exception>


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
		return std::wstring(&result[0], &result[0] + result.size() - 2);//suppression de la dernière virgule et espace
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
		return std::wstring(&result[0], &result[0] + result.size() - 2);//suppression de la dernière virgule et espace
	else
		return result;
}

/********************************************************************************************************************
* SPS (Property STORE)
*********************************************************************************************************************/

IdList::IdList(LPBYTE buffer, int _niveau, bool Parentiszip) {
	type_char = NULL;
	niveau = _niveau;
	shellItem = NULL;
	item_size = *reinterpret_cast<unsigned short int*>(buffer);

	if (conf._dump == true) {
		log(3, L"🔈dump_wstring idlist");
		pData = dump_wstring(buffer, 0, item_size);
	}
	else
		pData = L"";
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
		log(3, L"🔈getShellItem idlist");
		getShellItem(buffer, &shellItem, niveau + 1, Parentiszip);
	}
}

std::wstring IdList::to_json(int i) {
	log(3, L"🔈IdList to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	result += tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"TypeHex\" : \"0x" + type_hex + L"\",\n"
		+ tab(niveau + 1) + L"\"Type\" : \"" + type + L"\",\n";
	if (conf._dump == true)
		result += tab(niveau + 1) + L"\"Dump\" : \"" + pData + L"\",\n";
	result += shellItem->to_json(i);
	result += tab(niveau) + L"}";
	return result;
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
std::wstring get_type(unsigned int type) {
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

void get_value(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int niveau, std::wstring* value, bool* valueIsObject) {
	if (valueType == VT_EMPTY) { // VT_NULL
		*value = L"";
	}
	else if (valueType == VT_NULL) { // VT_NULL
		*value = L"NULL";
	}
	else if (valueType == VT_I2) {     // VT_I2(signed 16 - bit)
		*value = std::to_wstring(*reinterpret_cast<short int*>(buffer + *pos));
		*pos += 2;
	}
	else if (valueType == VT_I4 || valueType == VT_INT) {  // VT_I4, VT_INT(signed 32 - bit)
		*value = std::to_wstring(*reinterpret_cast<int*>(buffer + *pos));
		*pos += 4;
	}
	else if (valueType == VT_BSTR) {    // VT_BSTR
		*value = std::wstring((wchar_t*)(buffer + *pos + 4)).data();
		log(3, L"🔈replaceAll value");
		*value = replaceAll(*value, L"\\", L"\\\\"); //escape \ in std::string like path
		*pos += 4 + value->size() * 2 + 2;
	}
	else if (valueType == VT_DATE) {
		double t = *reinterpret_cast<double*>(buffer + *pos);
		SYSTEMTIME s;
		log(3, L"🔈VariantTimeToSystemTime value");
		VariantTimeToSystemTime(t, &s);
		log(3, L"🔈time_to_wstring value");
		*value = time_to_wstring(s);
		*pos += 8;
	}
	else if (valueType == VT_BOOL) {    // VT_BOOL
		if (*reinterpret_cast<unsigned short int*>(buffer + *pos) == 0xFFFF) {
			log(3, L"🔈bool_to_wstring value");
			*value = bool_to_wstring(true);
		}
		else if (*reinterpret_cast<unsigned short int*>(buffer + *pos) == 0x0000) {
			log(3, L"🔈bool_to_wstring value");
			*value = bool_to_wstring(false);
		}
		else
			*value = L"";
		*pos += 2;
	}
	else if (valueType == VT_R8) {
		*value = std::to_wstring(*reinterpret_cast<double*>(buffer + *pos));
		*pos += 8;
	}
	else if (valueType == VT_I1) {    // VT_I1(signed 8 - bit)
		*value = std::to_wstring((int)reinterpret_cast<char>(buffer + *pos));
		*pos += 1;
	}
	else if (valueType == VT_UI1) {    // VT_UI1(unsigned 8 - bit)
		*value = std::to_wstring((int)reinterpret_cast<unsigned char>(buffer + *pos));
		*pos += 1;
	}
	else if (valueType == VT_UI2) {    // VT_UI2(unsigned 16 - bit)
		*value = std::to_wstring(*reinterpret_cast<unsigned short int*>(buffer + *pos));
		*pos += 2;
	}
	else if (valueType == VT_UI4 || valueType == VT_UINT) {   // VT_UI4, VT_UINT(unsigned 32 - bit)
		*value = std::to_wstring(*reinterpret_cast<unsigned int*>(buffer + *pos));
		*pos += 4;
	}
	else if (valueType == VT_I8) {    // VT_I8(signed 64 - bit)
		*value = std::to_wstring(*reinterpret_cast<long long*>(buffer + *pos));
		*pos += 8;
	}
	else if (valueType == VT_UI8) {  // VT_UI8(unsigned 64 - bit)
		*value = std::to_wstring(*reinterpret_cast<unsigned long long*>(buffer + *pos));
		*pos += 8;
	}
	else if (valueType == VT_LPWSTR) {    // VT_LPWSTR(Unicode std::string)
		*value = std::wstring((wchar_t*)(buffer + *pos + 4)).data();
		log(3, L"🔈replaceAll value");
		*value = replaceAll(*value, L"\\", L"\\\\"); //escape \ in std::string like path
		*pos += 4 + value->size() * 2;
		while (buffer[*pos] == 0x00)
			*pos += 1; // unknown
	}
	else if (valueType == 0x101F) {    // Vector<VT_LPWSTR> (Unicode std::string)
		*valueIsObject = true;
		*value = L"[";
		unsigned int nbStrings = *reinterpret_cast<unsigned int*>(buffer + *pos);
		for (unsigned int x = 0; x < nbStrings; x++) {
			unsigned int stringsize = *reinterpret_cast<unsigned int*>(buffer + *pos + 4);
			std::wstring temp((wchar_t*)(buffer + *pos + 8));
			*value += L"\"" + temp + L"\"";
			if (x != nbStrings - 1)
				*value += L",";
			*pos += 4 + stringsize * 2;
		}
		*value += L"]";
		log(3, L"🔈replaceAll value");
		*value = replaceAll(*value, L"\\", L"\\\\"); //escape \ in std::string like path
	}
	else if (valueType == 0x1011) // Vector<VT_UI1> TABLEAU byte
	{
		*value = L"";
		*valueIsObject = false;
		unsigned short int itemsize = *reinterpret_cast<unsigned short int*>(buffer + *pos);
		if (*reinterpret_cast<unsigned int*>(buffer + *pos + 0x8) == 0x53505331) { // SPS
			*valueIsObject = true;
			log(3, L"🔈SPS");
			*value = SPS(buffer + *pos + 0x4, niveau + 2).to_json();
		}
		else if (*reinterpret_cast<unsigned int*>(buffer + *pos + 0x1c) == 0x53505331) { // SPS
			*valueIsObject = true;
			log(3, L"🔈SPS value");
			*value = SPS(buffer + *pos + 0x8, niveau + 2).to_json();
		}
		else *value = L"Not implemented"; //TODO Vector<VT_UI1>, il s'agit d'un std::vector de byte (LPBYTE) mais contenu unknown, il faudrait trouver à quoi correspond system.delegateidlist

		*pos += itemsize;

	}
	else if (valueType == VT_FILETIME) {    // VT_FILETIME(aka.Windows 64 - bit timestamp)
		log(3, L"🔈time_to_wstring value");
		*value = time_to_wstring(*reinterpret_cast<FILETIME*>(buffer + *pos));
		*pos += 8;
	}
	else if (valueType == VT_BLOB) {
		*valueIsObject = true;
		int pos2 = 0;

		//SPS
		pos2 = 17;
		log(3, L"🔈SPS sps1");
		SPS* sps1 = new SPS(buffer + pos2, niveau + 2);
		pos2 += sps1->size;

		//SPS
		log(3, L"🔈SPS sps2");
		SPS* sps2 = new SPS(buffer + pos2, niveau + 2);
		pos2 += sps2->size;

		//SPS
		log(3, L"🔈SPS sps3");
		SPS* sps3 = new SPS(buffer + pos2, niveau + 2);
		pos2 += sps3->size;

		*pos += pos2;

		//résultat
		*value = L"[\n";
		*value += sps1->to_json();
		*value += L",\n";
		*value += sps2->to_json();
		*value += L",\n";
		*value += sps3->to_json();
		*value += L"\n";
		*value += tab(niveau + 1) + L"]";

		delete sps1;
		delete sps2;
		delete sps3;
	}
	else if (valueType == VT_STREAM) {    // VT_STREAM, TODO calcul size pour maj pos
		*value = L"VT_STREAM not implemented";
		unsigned int stringsize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		*pos += 4;
		*value = std::wstring((wchar_t*)(buffer + *pos)).data();
		*pos += stringsize;
		*pos += 2;//padding
		unsigned int steamdatasize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		*pos += steamdatasize;
		*pos += 0;
	}
	else if (valueType == VT_CLSID) {
		log(3, L"🔈guid_to_wstring guid");
		std::wstring guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + *pos));
		log(3, L"🔈trans_guid_to_wstring FriendlyName");
		std::wstring FriendlyName = trans_guid_to_wstring(guid);
		*valueIsObject = true;
		*value = L"{\n"
			+ tab(niveau + 2) + L"\"GUID\" : \"" + guid + L"\",\n"
			+ tab(niveau + 2) + L"\"FriendlyName\" : \"" + FriendlyName + L"\"\n"
			+ tab(niveau + 1) + L"}";
		*pos += 16;
	}
	else
		*value = L"";
}

SPSValue::SPSValue(LPBYTE buffer, std::wstring _guid, int _niveau) {
	log(3, L"🔈SPSValue");
	niveau = _niveau;
	guid = _guid;
	valueIsObject = false;
	size = *reinterpret_cast<unsigned int*>(buffer);
	valueType = 0;
	if (size > 0) {
		unsigned int id_int = *reinterpret_cast<unsigned int*>(buffer + 4);
		id = std::to_wstring(id_int);
		//recherche value
		unsigned int pos = 13;
		if (guid == L"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}") {
			id = std::wstring((wchar_t*)(buffer + 9)).data();
			log(3, L"🔈trans_guid_to_wstring name");
			name = trans_guid_to_wstring(guid);
			valueType = *reinterpret_cast<unsigned short int*>(buffer + 9 + id_int); // id_int contient la taille de la std::string 
			pos = 9 + id_int + 2 + 2; // 2 de padding ?
		}
		else {
			valueType = *reinterpret_cast<unsigned short int*>(buffer + 9);
			log(3, L"🔈to_FriendlyName name");
			name = to_FriendlyName(guid, id_int);
			if (name == L"(Undefined)") {
				log(2, L"🔥SPS Value : Friendlyname Unknown " + guid + L"/" + std::to_wstring(id_int));
			}
			id = std::to_wstring(id_int);

		}
		log(3, L"🔈get_value");
		get_value(buffer, &pos, valueType, niveau, &value, &valueIsObject);
	}
}

std::wstring SPSValue::to_json(int i) {
	log(3, L"🔈SPSValue to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n";
	result += tab(niveau + 1) + L"\"ID\" : \"" + guid + L"/" + id + L"\",\n";
	result += tab(niveau + 1) + L"\"Name\" : \"" + name + L"\",\n";
	log(3, L"🔈get_type valueType");
	result += tab(niveau + 1) + L"\"Type\" : \"" + get_type(valueType) + L"\",\n";
	if (valueIsObject == false)
		result += tab(niveau + 1) + L"\"Value\" : \"" + value + L"\"\n"; // std::string
	else
		result += tab(niveau + 1) + L"\"Values\" : " + value + L"\n"; // Object
	result += tab(niveau) + L"}";
	return result;
}

SPS::SPS(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	size = *reinterpret_cast<unsigned int*>(buffer);
	version = *reinterpret_cast<unsigned int*>(buffer + 4);
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guid);
	unsigned int pos = 24;
	while (true) {
		if (pos >= size)
			break; //fin
		log(3, L"🔈SPSValue");
		SPSValue block(buffer + pos, guid, niveau + 2); // concordance avec to_json
		if (block.size == 0) { //vide
			break;
		}
		else
			values.push_back(block);
		pos += block.size;
	}
}

std::wstring SPS::to_json(int i) {
	log(3, L"🔈SPS to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Values\" : [\n";
	std::vector<SPSValue>::iterator it;
	for (it = values.begin(); it != values.end(); it++) {
		result += it->to_json(i);
		if (it != values.end() - 1)
			result += L",";
		result += L"\n";
	}
	result += tab(niveau + 1) + L"]\n";
	result += tab(niveau) + L"}";
	return result;
}

/********************************************************************************************************************
* Extension blocks
*********************************************************************************************************************/

Beef0000::Beef0000(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
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

std::wstring Beef0000::to_json(int i) {
	log(3, L"🔈Beef0000 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Guid1\" : \"" + guid1 + L"\",\n"
		+ tab(niveau + 1) + L"\"Identifier1\" : \"" + identifier1 + L"\",\n"
		+ tab(niveau + 1) + L"\"Guid2\" : \"" + guid2 + L"\",\n"
		+ tab(niveau + 1) + L"\"Identifier2\" : \"" + identifier2 + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0001::Beef0001(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0001";
	message = L"Unsupported Extension block";
}

std::wstring Beef0001::to_json(int i) {
	log(3, L"🔈Beef0001 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message \" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0002::Beef0002(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0002";
	message = L"Unsupported Extension block";
}

std::wstring Beef0002::to_json(int i) {
	log(3, L"🔈Beef0002 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message \" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0003::Beef0003(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0003";
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 8));
	log(3, L"🔈trans_guid_to_wstring identifier");
	identifier = trans_guid_to_wstring(guid);
}

std::wstring Beef0003::to_json(int i) {
	log(3, L"🔈Beef0003 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Guid\" : \"" + guid + L"\",\n"
		+ tab(niveau + 1) + L"\"Identifier\" : \"" + identifier + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0004::Beef0004(LPBYTE buffer, int _niveau, bool* is_zip, bool is_file) {
	ExtensionVersion = 0;
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0004";
	creationDateUtc = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).to_filetime();
	log(3, L"🔈time_to_wstring creationDateUtc");
	if (time_to_wstring(creationDateUtc) != L"") {
		log(3, L"🔈FileTimeToLocalFileTime creationDateUtc");
		FileTimeToLocalFileTime(&creationDateUtc, &creationDate);
	}
	accessedDateUtc = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 12)).to_filetime();
	if (time_to_wstring(accessedDateUtc) != L"") {
		log(3, L"🔈FileTimeToLocalFileTime accessedDateUtc");
		FileTimeToLocalFileTime(&accessedDateUtc, &accessedDate);
	}
	unsigned int off = 18;  //start of data part
	unsigned short int longNameSize = 0;
	longNameSize = *reinterpret_cast<unsigned short int*>(buffer + off + 18);
	longName = std::wstring((wchar_t*)(buffer + off + 28)).data();
	// le contenu des ZIP et autres archives ont un contenu format special, il faut donc identifier les archives.
	// L'attribut ARCHIVE ne signifie pas ZIP mais "prêt à être archivé" au sens l'explorer
	std::wstring extension = L"";
	if (longName.length() > 3)
		extension = longName.substr(longName.length() - 3, 3);
	transform(extension.begin(), extension.end(), extension.begin(), ::toupper);
	if (is_file == true && (extension == L"ZIP" || extension == L"TAR" || extension == L".GZ" || extension == L".7Z" || extension == L"RAR"))
		*is_zip = true;
	if (longNameSize > longName.size())
	{
		localizedName = std::wstring((wchar_t*)(buffer + off + 28 + (longName.size() + 1) * 2)).data();
		log(3, L"🔈replaceAll localizedName");
		localizedName = replaceAll(localizedName, L"\\", L"\\\\");
	}
}

std::wstring Beef0004::to_json(int i) {
	log(3, L"🔈Beef0004 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n";
	result += tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n";
	log(3, L"🔈time_to_wstring accessedDate");
	result += tab(niveau + 1) + L"\"CreatedDate\" : \"" + time_to_wstring(accessedDate) + L"\",\n";
	log(3, L"🔈time_to_wstring accessedDateUtc");
	result += tab(niveau + 1) + L"\"CreatedDateUtc\" : \"" + time_to_wstring(accessedDateUtc) + L"\",\n";
	log(3, L"🔈time_to_wstring accessedDate");
	result += tab(niveau + 1) + L"\"AccessedDate\" : \"" + time_to_wstring(accessedDate) + L"\",\n";
	log(3, L"🔈time_to_wstring accessedDateUtc");
	result += tab(niveau + 1) + L"\"AccessedDateUtc\" : \"" + time_to_wstring(accessedDateUtc) + L"\",\n";
	result += tab(niveau + 1) + L"\"LongName\" : \"" + longName + L"\",\n";
	result += tab(niveau + 1) + L"\"LocalizedName\" : \"" + localizedName + L"\"\n";
	result += tab(niveau) + L"}";
	return result;
}

Beef0006::Beef0006(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0006";
	int pos = 0;
	while (*reinterpret_cast<short int*>(buffer + pos) != 0x0000)
		pos += 1;
	username = std::wstring((wchar_t*)(buffer + pos + 2)).data();
}

std::wstring Beef0006::to_json(int i) {
	log(3, L"🔈Beef0006 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Username\" : \"" + username + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0008::Beef0008(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef008";
	message = L"Unsupported Extension block";
}

std::wstring Beef0008::to_json(int i) {
	log(3, L"🔈Beef0008 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0009::Beef0009(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0009";
	message = L"Unsupported Extension block";
}

std::wstring Beef0009::to_json(int i) {
	log(3, L"🔈Beef0009 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef000a::Beef000a(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef000a";
	message = L"Unsupported Extension block";
}

std::wstring Beef000a::to_json(int i) {
	log(3, L"🔈Beef000a to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef000c::Beef000c(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef000c";
	message = L"Unsupported Extension block";
}

std::wstring Beef000c::to_json(int i) {
	log(3, L"🔈Beef000c to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef000e::Beef000e(LPBYTE buffer, int _niveau) { // TODO A TESTER
	niveau = _niveau;
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
		SPS s = SPS(buffer + pos, niveau + 1);
		SPSs.push_back(s);
		pos += s.size;
	}
	pos += 11;
	for (int x = 0; x < 3; x++) {
		std::string s = std::string((char*)buffer + pos);
		pos += s.size() + 1;
	}
	pos += 16;
	std::string s = std::string((char*)buffer + pos);
	pos += s.size() + 1;

	pos += 1;

	for (int x = 0; x < 2; x++) { // 2 extension block
		unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
		if (size > 0) {
			log(3, L"🔈getExtensionBlock");
			getExtensionBlock(buffer + pos, &extensionblocks, niveau + 1, NULL, false);
			pos += size;
		}
		else
			break;
	}
	while (true) {
		unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos); // recherche de idlist
		if (size > 0) {
			log(3, L"🔈IShellItem");
			IShellItem* i;
			log(3, L"🔈getShellItem");
			getShellItem(buffer + pos, &i, niveau + 1);
			ishellitems.push_back(i);
			pos += size;
		}
		else
			break;
	}
}

std::wstring Beef000e::to_json(int i) {
	log(3, L"🔈Beef000e to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"IdLists\" : [\n";
	std::vector<IShellItem*>::iterator it;
	for (it = ishellitems.begin(); it != ishellitems.end(); it++) {
		IShellItem* temp = *it;
		result += temp->to_json(i);
		if (it != ishellitems.end() - 1)
			result += L",";
		result += L"\n";
	}
	result += L"]\n";
	result += L"}\n";
	return result;
}

Beef0010::Beef0010(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0010";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 16, niveau + 1);
}

std::wstring Beef0010::to_json(int i) {
	log(3, L"🔈Beef0010 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"SPS\" :\n"
		+ sps.to_json(i)
		+ L"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0013::Beef0013(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0013";
	message = L"The purpose of this extension block is unknown";
}

std::wstring Beef0013::to_json(int i) {
	log(3, L"🔈Beef0013 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0014::Beef0014(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0014";
	message = L"Unsupported Extension block";
}

std::wstring Beef0014::to_json(int i) {
	log(3, L"🔈Beef0014 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0016::Beef0016(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0016";
	value = std::wstring((wchar_t*)(buffer + 10)).data();
}

std::wstring Beef0016::to_json(int i) {
	log(3, L"🔈Beef0016 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Value\" : \"" + value + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0017::Beef0017(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0017";
	message = L"Unsupported Extension block";
}

std::wstring Beef0017::to_json(int i) {
	log(3, L"🔈Beef0017 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0019::Beef0019(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
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

std::wstring Beef0019::to_json(int i) {
	log(3, L"🔈Beef0019 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Guid1\" : \"" + guid1 + L"\",\n"
		+ tab(niveau + 1) + L"\"Identifier1\" : \"" + identifier1 + L"\",\n"
		+ tab(niveau + 1) + L"\"Guid2\" : \"" + guid2 + L"\",\n"
		+ tab(niveau + 1) + L"\"Identifier2\" : \"" + identifier2 + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef001a::Beef001a(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef001a";
	fileDocumentTypeString = std::wstring((wchar_t*)(buffer + 10)).data();
}

std::wstring Beef001a::to_json(int i) {
	log(3, L"🔈Beef001a to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"FileDocumentType\" : \"" + fileDocumentTypeString + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef001b::Beef001b(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef001b";
	fileDocumentTypeString = std::wstring((wchar_t*)(buffer + 10)).data();
}

std::wstring Beef001b::to_json(int i) {
	log(3, L"🔈Beef001b to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"FileDocumentType\" : \"" + fileDocumentTypeString + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef001d::Beef001d(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef001d";
	executable = std::wstring((wchar_t*)(buffer + 10)).data();
}

std::wstring Beef001d::to_json(int i) {
	log(3, L"🔈Beef001d to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Executable\" : \"" + executable + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef001e::Beef001e(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef001e";
	pinType = std::wstring((wchar_t*)(buffer + 10)).data();
}

std::wstring Beef001e::to_json(int i) {
	log(3, L"🔈Beef001e to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"PinType\" : \"" + pinType + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0021::Beef0021(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0021";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, niveau + 1);
}

std::wstring Beef0021::to_json(int i) {
	log(3, L"🔈Beef0021 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"SPS\" : \n" + sps.to_json(i) + L"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0024::Beef0024(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0024";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, niveau + 1);
}

std::wstring Beef0024::to_json(int i) {
	log(3, L"🔈Beef0024 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"SPS\" : \n" + sps.to_json(i) + L"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0025::Beef0025(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0025";
	filetime1 = *reinterpret_cast<FILETIME*>(buffer + 12);
	filetime2 = *reinterpret_cast<FILETIME*>(buffer + 20);
}

std::wstring Beef0025::to_json(int i) {
	log(3, L"🔈Beef0025 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Filetime1\" : \"" + time_to_wstring(filetime1) + L"\",\n"
		+ tab(niveau + 1) + L"\"Filetime2\" : \"" + time_to_wstring(filetime2) + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0026::Beef0026(LPBYTE buffer, int _niveau) {
	sps = NULL;
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0026";
	idlist = NULL;
	shellitem = NULL;
	if ((short int)buffer[8] == 0x11 || (short int)buffer[8] == 0x10 || (short int)buffer[8] == 0x12 || (short int)buffer[8] == 0x34 || (short int)buffer[8] == 0x31) {
		ctimeUtc = *reinterpret_cast<FILETIME*>(buffer + 12);
		log(3, L"🔈LocalFileTimeToFileTime ctimeUtc");
		LocalFileTimeToFileTime(&ctimeUtc, &ctime);
		mtimeUtc = *reinterpret_cast<FILETIME*>(buffer + 20);
		log(3, L"🔈LocalFileTimeToFileTime mtimeUtc");
		LocalFileTimeToFileTime(&mtimeUtc, &mtime);
		atimeUtc = *reinterpret_cast<FILETIME*>(buffer + 28);
		log(3, L"🔈LocalFileTimeToFileTime mtimeUtc");
		LocalFileTimeToFileTime(&mtimeUtc, &atime);
		// 2 octets Unknown
		log(3, L"🔈IdList");
		idlist = new IdList(buffer + 38, niveau + 2);
	}
	else {
		ctimeUtc = { 0 };
		ctime = { 0 };
		mtimeUtc = { 0 };
		mtime = { 0 };
		atimeUtc = { 0 };
		atime = { 0 };
		log(3, L"🔈SPS");
		sps = new SPS(buffer + 8, niveau + 2);
	}

}

std::wstring Beef0026::to_json(int i) {
	log(3, L"🔈Beef0026 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n";
	result += tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n";
	log(3, L"🔈time_to_wstring ctime");
	result += tab(niveau + 1) + L"\"CreationDate\" : \"" + time_to_wstring(ctime) + L"\",\n";
	log(3, L"🔈time_to_wstring ctimeUtc");
	result += tab(niveau + 1) + L"\"CreationDateUtc\" : \"" + time_to_wstring(ctimeUtc) + L"\",\n";
	log(3, L"🔈time_to_wstring mtime");
	result += tab(niveau + 1) + L"\"ModificationDate\" : \"" + time_to_wstring(mtime) + L"\",\n";
	log(3, L"🔈time_to_wstring mtimeUtc");
	result += tab(niveau + 1) + L"\"ModificationDateUtc\" : \"" + time_to_wstring(mtimeUtc) + L"\",\n";
	log(3, L"🔈time_to_wstring atime");
	result += tab(niveau + 1) + L"\"AccessedDate\" : \"" + time_to_wstring(atime) + L"\",\n";
	log(3, L"🔈time_to_wstring atimeUtc");
	result += tab(niveau + 1) + L"\"AccessedDateUtc\" : \"" + time_to_wstring(atimeUtc) + L"\"";
	if (sps != NULL) {
		result += L",\n";
		result += tab(niveau + 1) + L"\"SPS\" : " + sps->to_json(i) + L"\n";
	}

	if (idlist != NULL) {
		result += L",\n";
		result += tab(niveau + 1) + L"\"IdList\" : {\n"
			+ idlist->to_json(i) + L"\n"
			+ tab(niveau + 1) + L"}\n";
	}
	else {
		result += L"\n";
	}
	result += tab(niveau) + L"}";
	return result;
}

Beef0027::Beef0027(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0027";
	log(3, L"🔈SPS");
	sps = SPS(buffer + 8, niveau + 1);
}

std::wstring Beef0027::to_json(int i) {
	log(3, L"🔈Beef0027 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"SPS\" : \n" + sps.to_json(i) + L"\n"
		+ tab(niveau) + L"}";
	return result;
}

Beef0029::Beef0029(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	signature = L"0xbeef0029";
	message = L"The purpose of this extension block is unknown";
}

std::wstring Beef0029::to_json(int i) {
	log(3, L"🔈Beef0029 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n"
		+ tab(niveau + 1) + L"\"Signature\" : \"" + signature + L"\",\n"
		+ tab(niveau + 1) + L"\"Message\" : \"" + message + L"\"\n"
		+ tab(niveau) + L"}";
	return result;
}

void getExtensionBlock(LPBYTE buffer, std::vector<IExtensionBlock*>* extensionBlocks, int _niveau, bool* is_zip, bool is_file) {
	IExtensionBlock* block = NULL;
	unsigned int signature = *reinterpret_cast<unsigned int*>(buffer + 4);
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	if (signature == (unsigned int)0xBeef0000) {
		log(3, L"🔈Beef0000");
		block = new Beef0000(buffer, _niveau + 1);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0001) {
		log(3, L"🔈Beef0001");
		block = new Beef0001(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0002) {
		log(3, L"🔈Beef0002");
		block = new Beef0002(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0003) {
		log(3, L"🔈Beef0003");
		block = new Beef0003(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0004) {
		log(3, L"🔈Beef0004");
		block = new Beef0004(buffer, _niveau, is_zip, is_file);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0006) {
		log(3, L"🔈Beef0006");
		block = new Beef0006(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0008) {
		log(3, L"🔈Beef0008");
		block = new Beef0008(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0009) {
		log(3, L"🔈Beef0009");
		block = new Beef0009(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef000a) {
		log(3, L"🔈Beef000a");
		block = new Beef000a(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef000c) {
		log(3, L"🔈Beef000c");
		block = new Beef000c(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef000e) {
		log(3, L"🔈Beef000e");
		block = new Beef000e(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0010) {
		log(3, L"🔈Beef0010");
		block = new Beef0010(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0013) {
		log(3, L"🔈Beef0013");
		block = new Beef0013(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0014) {
		log(3, L"🔈Beef0014");
		block = new Beef0014(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0016) {
		log(3, L"🔈Beef0016");
		block = new Beef0016(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0017) {
		log(3, L"🔈Beef0017");
		block = new Beef0017(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0019) {
		log(3, L"🔈Beef0019");
		block = new Beef0019(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef001a) {
		log(3, L"🔈Beef001a");
		block = new Beef001a(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef001b) {
		log(3, L"🔈Beef001b");
		block = new Beef001b(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef001d) {
		log(3, L"🔈Beef001d");
		block = new Beef001d(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef001e) {
		log(3, L"🔈Beef001e");
		block = new Beef001e(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0021) {
		log(3, L"🔈Beef0021");
		block = new Beef0021(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0024) {
		log(3, L"🔈Beef0024");
		block = new Beef0024(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0025) {
		log(3, L"🔈Beef0025");
		block = new Beef0025(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0026) {
		log(3, L"🔈Beef0026");
		block = new Beef0026(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0027) {
		log(3, L"🔈Beef0027");
		block = new Beef0027(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else if (signature == (unsigned int)0xBeef0029) {
		log(3, L"🔈Beef0029");
		block = new Beef0029(buffer, _niveau);
		extensionBlocks->push_back(block);
	}
	else {
		log(3, L"🔈dump_wstring unknown extension block");
		std::wstring d = dump_wstring(buffer, 0, size);
		log(3, L"🔈to_hex signature");
		log(2, L"🔥Extension block unknown 0x" + to_hex(signature) + L" : " + d);
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
		return std::wstring(&result[0], &result[0] + result.size() - 2);//suppression de la dernière virgule et espace
	else
		return result;
}

VolumeShellItem::VolumeShellItem(LPBYTE buffer, unsigned char type_char, int _niveau) {

	niveau = _niveau;
	isPresent = true;
	name = L"";
	guid = L"";
	identifier = L"";
	log(3, L"🔈ShellVolumeFlags");
	flags = ShellVolumeFlags(type_char);
	std::wstring volumeName = L"";
	if (flags.LocalDisk == true) {
		log(3, L"🔈string_to_wstring name");
		name = string_to_wstring(std::string((char*)buffer + 3));
		log(3, L"🔈replaceAll name");
		name = replaceAll(name, L"\\", L"\\\\");
	}
	else if (flags.SystemFolder == true) {
		log(3, L"🔈guid_to_wstring guid");
		guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 4));
		log(3, L"🔈trans_guid_to_wstring name");
		name = trans_guid_to_wstring(guid);
		log(3, L"🔈replaceAll name");
		name = replaceAll(name, L"\\", L"\\\\");
		log(3, L"🔈trans_guid_to_wstring identifier");
		identifier = trans_guid_to_wstring(guid);
		log(3, L"🔈replaceAll identifier");
		identifier = replaceAll(identifier, L"\\", L"\\\\");
	}
	else if (flags.None != true) {
		log(2, L"🔥OROpenKey VolumeShellItem flag unknown : " + to_hex(type_char));
	}

}

std::wstring VolumeShellItem::to_json(int i) {
	log(3, L"🔈VolumeShellItem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		log(3, L"🔈to_wstring flags");
		result += tab(niveau) + L"\"Flags\" : \"" + flags.to_wstring() + L"\",\n"
			+ tab(niveau) + L"\"Name\" : \"" + name + L"\"";
		if (!guid.empty()) {
			result += L",\n"
				+ tab(niveau) + L"\"GUID\" : \"" + guid + L"\",\n"
				+ tab(niveau) + L"\"Identifier\" : \"" + identifier + L"\"\n";
		}
		else {
			result += L"\n";
		}
	}
	return result;
}

ControlPanel::ControlPanel(LPBYTE buffer, unsigned short int itemSize, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 14));
	log(3, L"🔈trans_guid_to_wstring identifier");
	identifier = trans_guid_to_wstring(guid);
	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + itemSize - 2);
	if (extensionOffset != 0x00) {
		unsigned short int pos = extensionOffset;
		while (pos < itemSize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < itemSize) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, niveau + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

std::wstring ControlPanel::to_json(int i) {
	log(3, L"🔈ControlPanel to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent == true) {
		result += tab(niveau) + L"\"GUID\" : \"" + guid + L"\",\n"
			+ tab(niveau) + L"\"Identifier\" : \"" + identifier + L"\",\n"
			+ tab(niveau) + L"\"ExtensionBlocksCount\" : \"" + std::to_wstring(extensionBlocks.size()) + L"\",\n"
			+ tab(niveau) + L"\"ExtensionBlocks\" : [\n";
		std::vector<IExtensionBlock*>::iterator it;
		for (it = extensionBlocks.begin(); it != extensionBlocks.end(); it++) {
			IExtensionBlock* temp = *it;
			result += temp->to_json(i);
			if (it != extensionBlocks.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau) + L"]\n";
	}
	return result;
}

ControlPanelCategory::ControlPanelCategory(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
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
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < totalsize) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, niveau + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

std::wstring ControlPanelCategory::to_json(int i) {
	log(3, L"🔈ControlPanelCategory to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent == true) {
		result += tab(niveau) + L"\"ID\" : \"" + id + L"\",\n"
			+ tab(niveau) + L"\"ExtensionBlocksCount\" : \"" + std::to_wstring(extensionBlocks.size()) + L"\",\n"
			+ tab(niveau) + L"\"ExtensionBlocks\" : [\n";
		std::vector<IExtensionBlock*>::iterator it;
		for (it = extensionBlocks.begin(); it != extensionBlocks.end(); it++) {
			IExtensionBlock* temp = *it;
			result += temp->to_json(i);
			if (it != extensionBlocks.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau) + L"]\n";
	}
	return result;
}

Property::Property(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	id = 0;
	type = 0;
	valueIsObject = false;
	unsigned int pos = 0;
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	pos += 16;
	id = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	log(3, L"🔈to_FriendlyName FriendlyName");
	FriendlyName = to_FriendlyName(guid, id);
	if (FriendlyName == L"(Undefined)") {
		log(2, L"🔥Property : Friendlyname Unknown " + guid + L"/" + std::to_wstring(id));
	}
	type = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	log(3, L"🔈get_value");
	get_value(buffer, &pos, type, niveau, &value, &valueIsObject);
	size = pos;
}

std::wstring Property::to_json(int i) {
	log(3, L"🔈Property to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"{\n";
	if (guid == L"{4D545058-4FCE-4578-95C8-8698A9BC0F49}" || guid == L"{4D545058-8900-40b3-8F1D-DC246E1E8370}")
		result += tab(niveau + 1) + L"\"ID\" : \"" + guid + L"/" + to_hex(id) + L"\",\n";
	else
		result += tab(niveau + 1) + L"\"ID\" : \"" + guid + L"/" + std::to_wstring(id) + L"\",\n";
	log(3, L"🔈get_type type");
	result += tab(niveau + 1) + L"\"Type\" : \"" + get_type(type) + L"\",\n"
		+ tab(niveau + 1) + L"\"FriendlyName\" : \"" + FriendlyName + L"\",\n";
	if (valueIsObject == false)
		result += tab(niveau + 1) + L"\"Value\" : \"" + value + L"\"\n";
	else
		result += tab(niveau + 1) + L"\"Value\" : " + value + L"\n";
	result += tab(niveau) + L"}";
	return result;
}

UserPropertyView0xC01::UserPropertyView0xC01(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	unsigned int pos = 0x14;//unknown
	unsigned int wstring1Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	folder = std::wstring((wchar_t*)(buffer + pos)).data();
	pos += wstring1Size;
	pos += 16;//unknown
	unsigned int wstring2Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	fullurl = std::wstring((wchar_t*)(buffer + pos)).data();
}

std::wstring UserPropertyView0xC01::to_json(int i) {
	log(3, L"🔈UserPropertyView0xC01 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"\"Folder\" : \"" + folder + L"\",\n"
		+ tab(niveau) + L"\"FullUrl\" : \"" + fullurl + L"\"";
	return result;
}

UserPropertyView0x23febbee::UserPropertyView0x23febbee(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	log(3, L"🔈guid_to_wstring guid");
	guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 0xE));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guid);
	log(3, L"🔈replaceAll FriendlyName");
	FriendlyName = replaceAll(FriendlyName, L"\\", L"\\\\"); // escape \ by \\ in std::string
}

std::wstring UserPropertyView0x23febbee::to_json(int i) {
	log(3, L"🔈UserPropertyView0x23febbee to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"\"GUID\" : \"" + guid + L"\",\n"
		+ tab(niveau) + L"\"FriendlyName\" : \"" + FriendlyName + L"\"";
	return result;
}

UserPropertyView0x07192006::UserPropertyView0x07192006(LPBYTE buffer, int _niveau) {
	unsigned int pos = 0;
	niveau = _niveau;
	modifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 26);
	createdUtc = *reinterpret_cast<FILETIME*>(buffer + 34);
	log(3, L"🔈time_to_wstring modifiedUtc");
	if (!time_to_wstring(modifiedUtc).empty()) {
		log(3, L"🔈FileTimeToLocalFileTime modifiedUtc");
		FileTimeToLocalFileTime(&modifiedUtc, &modified);
	}
	else
		modified = { 0 };
	log(3, L"🔈time_to_wstring createdUtc");
	if (!time_to_wstring(createdUtc).empty()) {
		log(3, L"🔈FileTimeToLocalFileTime created");
		FileTimeToLocalFileTime(&createdUtc, &created);
	}
	else
		created = { 0 };
	int folderName1Size = *reinterpret_cast<unsigned int*>(buffer + 62);
	int folderName2Size = *reinterpret_cast<unsigned int*>(buffer + 66);
	int folderIdentifiersize = *reinterpret_cast<unsigned int*>(buffer + 70);

	folderName1 = std::wstring((wchar_t*)(buffer + 74)).data();
	folderName2 = std::wstring((wchar_t*)(buffer + 74) + folderName1Size).data();
	folderIdentifier = std::wstring((wchar_t*)(buffer + 74) + folderName1Size + folderName2Size).data();

	pos = 74 + folderName1Size * 2 + folderName2Size * 2 + folderIdentifiersize * 2;
	pos += 4;//unknown
	log(3, L"🔈guid_to_wstring guidClass");
	guidClass = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guidClass);
	pos += 16;

	unsigned int numberProperties = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	for (unsigned int x = 0; x < numberProperties; x++) {
		log(3, L"🔈Property");
		Property temp(buffer + pos, niveau + 1);
		properties.push_back(temp);
		pos += temp.size;
	}
}

std::wstring UserPropertyView0x07192006::to_json(int i) {
	log(3, L"🔈UserPropertyView0x07192006 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"\"Folder1\" : \"" + folderName1 + L"\",\n";
	result += tab(niveau) + L"\"Folder2\" : \"" + folderName2 + L"\",\n";
	result += tab(niveau) + L"\"FolderIdentifier\" : \"" + folderIdentifier + L"\",\n";
	log(3, L"🔈time_to_wstring created");
	result += tab(niveau) + L"\"CreatedDate\" : \"" + time_to_wstring(created) + L"\",\n";
	log(3, L"🔈time_to_wstring createdUtc");
	result += tab(niveau) + L"\"CreatedDateUtc\" : \"" + time_to_wstring(createdUtc) + L"\",\n";
	log(3, L"🔈time_to_wstring modified");
	result += tab(niveau) + L"\"ModifiedDate\" : \"" + time_to_wstring(modified) + L"\",\n";
	log(3, L"🔈time_to_wstring modifiedUtc");
	result += tab(niveau) + L"\"ModifiedDateUtc\" : \"" + time_to_wstring(modifiedUtc) + L"\",\n";
	result += tab(niveau) + L"\"GUIDClass\" : \"" + guidClass + L"\",\n";
	result += tab(niveau) + L"\"FriendlyName\" : \"" + FriendlyName + L"\",\n";
	result += tab(niveau) + L"\"Properties\" : [\n";;
	std::vector<Property>::iterator it2;
	for (it2 = properties.begin(); it2 != properties.end(); it2++) {
		result += it2->to_json(i);
		if (it2 != properties.end() - 1)
			result += L",";
		result += L"\n";
	}
	result += tab(niveau) + L"]";
	return result;
}

UserPropertyView0x10312005::UserPropertyView0x10312005(LPBYTE buffer, int _niveau) {
	unsigned int pos = 0;
	niveau = _niveau;
	int namesize = *reinterpret_cast<unsigned int*>(buffer + 0x26);
	int identifiersize = *reinterpret_cast<unsigned int*>(buffer + 0x2A);
	int filesystemsize = *reinterpret_cast<unsigned int*>(buffer + 0x2E);
	int nbGUIDStrings = *reinterpret_cast<unsigned int*>(buffer + 0x32);

	name = std::wstring((wchar_t*)(buffer + 0x36)).data();
	identifier = std::wstring((wchar_t*)(buffer + 0x36 + namesize * 2)).data();
	filesystem = std::wstring((wchar_t*)(buffer + 0x36 + namesize * 2 + identifiersize * 2)).data();

	pos = 0x36 + namesize * 2 + identifiersize * 2 + filesystemsize * 2;
	for (int x = 0; x < nbGUIDStrings; x++) {
		guidstrings.push_back(std::wstring((wchar_t*)(buffer + pos)));
		pos += 78;
	}
	pos += 4;//unknown

	log(3, L"🔈guid_to_wstring guidClass");
	guidClass = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + pos));
	log(3, L"🔈trans_guid_to_wstring FriendlyName");
	FriendlyName = trans_guid_to_wstring(guidClass);
	pos += 16;

	unsigned int numberProperties = *reinterpret_cast<unsigned int*>(buffer + pos);// ?? TODO  seules les 4 premieres sont exploitables, est-ce vraiment le nombre de propriétés ?........
	pos += 4;
	for (unsigned int x = 0; x < numberProperties; x++) {
		log(3, L"🔈Property");
		Property temp(buffer + pos, niveau + 1);
		properties.push_back(temp);
		pos += temp.size;
	}
}

std::wstring UserPropertyView0x10312005::to_json(int i) {
	log(3, L"🔈UserPropertyView0x10312005 to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = tab(niveau) + L"\"Name\" : \"" + name + L"\",\n"
		+ tab(niveau) + L"\"Identifier\" : \"" + identifier + L"\",\n"
		+ tab(niveau) + L"\"Star-system\" : \"" + filesystem + L"\",\n"
		+ tab(niveau) + L"\"GUIDStrings\" : [\n";
	std::vector<std::wstring>::iterator it;
	for (it = guidstrings.begin(); it != guidstrings.end(); it++) {
		result += tab(niveau + 1) + L"{\n";
		result += tab(niveau + 2) + L"\"Guid\" : \"" + *it + L"\",\n";
		log(3, L"🔈trans_guid_to_wstring FriendlyName");
		result += tab(niveau + 2) + L"\"FriendlyName\" : \"" + trans_guid_to_wstring(*it) + L"\"\n";
		result += tab(niveau + 1) + L"}";
		if (it != guidstrings.end() - 1)
			result += L",";
		result += L"\n";
	}
	result += tab(niveau) + L"],\n";
	result += tab(niveau) + L"\"GUIDClass\" : \"" + guidClass + L"\",\n"
		+ tab(niveau) + L"\"Friendlyname\" : \"" + FriendlyName + L"\",\n"
		+ tab(niveau) + L"\"Properties\" : [\n";
	std::vector<Property>::iterator it2;
	for (it2 = properties.begin(); it2 != properties.end(); it2++) {
		result += it2->to_json(i);
		if (it2 != properties.end() - 1)
			result += L",";
		result += L"\n";
	}
	result += tab(niveau) + L"]";
	return result;

}

UsersPropertyView::UsersPropertyView(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	extensionOffset = 0;
	spsOffset = 0;
	delegate = NULL;
	unsigned int pos = 0;

	totalsize = *reinterpret_cast<unsigned short int*>(buffer + 0);
	dataSize = *reinterpret_cast<unsigned short int*>(buffer + 4);
	signature = *reinterpret_cast<unsigned int*>(buffer + 6);
	unsigned short int signature_short = *reinterpret_cast<unsigned short int*>(buffer + 6); // Certaines signatures sont identifiées par leurs 2 premiers octets
	SPSDataSize = *reinterpret_cast<unsigned short int*>(buffer + 10);
	identifierSize = *reinterpret_cast<unsigned short int*>(buffer + 12);
	dataOffset = 14;

	if (signature == (unsigned int)0x23febbee) {
		log(3, L"🔈UserPropertyView0x23febbee");
		delegate = new UserPropertyView0x23febbee(buffer, niveau);
		identifierSize += 2;
	}
	else if (signature == (unsigned int)0x10312005) {
		log(3, L"🔈UserPropertyView0x10312005");
		delegate = new UserPropertyView0x10312005(buffer, niveau);
	}
	else if (signature == (unsigned int)0x07192006) {
		log(3, L"🔈UserPropertyView0x07192006");
		delegate = new UserPropertyView0x07192006(buffer, niveau);
	}
	else if (signature_short == (unsigned int)0xC001) {
		log(3, L"🔈UserPropertyView0xC01");
		delegate = new UserPropertyView0xC01(buffer, niveau);
		signature = signature_short;
	}

	else if (SPSDataSize > 0) {
		spsOffset = dataOffset + identifierSize;
		while (true) {
			log(3, L"🔈SPS");
			SPS block(buffer + spsOffset + pos, niveau + 1);
			if (block.size && pos < SPSDataSize) {
				SPSs.push_back(block);
			}
			else
				break;
			pos += block.size;
		}
	}
	else {
		log(2, L"🔥UsersPropertyView Signature 0x" + to_hex(signature) + L" unknown : " + dump_wstring(buffer, 0, totalsize));
	}

	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + totalsize - 2);
	if (extensionOffset != 0x00) {
		pos = extensionOffset;
		while (pos < totalsize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < totalsize) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, niveau + 1, NULL, false);
				pos += size;
			}
			else
				break;
		}
	}
}

std::wstring UsersPropertyView::to_json(int i) {
	log(3, L"🔈UsersPropertyView to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		log(3, L"🔈to_hex signature");
		result += tab(niveau) + L"\"Signature\" : \"0x" + to_hex(signature) + L"\"";
		if (delegate != NULL) {
			result += L",\n"
				+ delegate->to_json(i);
		}

		if (SPSs.size() > 0) {
			result += L",\n"; // block SPS donc il nous faut une "," après identifier
			result += tab(niveau) + L"\"SPS\" : [\n";
			std::vector<SPS>::iterator it;
			for (it = SPSs.begin(); it != SPSs.end(); it++) {
				result += it->to_json(i);
				if (it != SPSs.end() - 1)
					result += L",";
				result += L"\n";
			}
			result += tab(niveau) + L"]\n";
		}

		if (extensionBlocks.size() > 0) {
			result += L",\n"; // block Extension donc il nous faut une "," après identifier
			result += tab(niveau) + L"\"Extension Blocks Count\" : \"" + std::to_wstring(extensionBlocks.size()) + L"\",\n";
			result += tab(niveau) + L"\"Extension Blocks\" : [\n";
			std::vector<IExtensionBlock*>::iterator it;
			for (it = extensionBlocks.begin(); it != extensionBlocks.end(); it++) {
				IExtensionBlock* temp = *it;
				result += temp->to_json(i);
				if (it != extensionBlocks.end() - 1)
					result += L",";
				result += L"\n";
			}
			result += tab(niveau) + L"]\n";
		}

		if (extensionBlocks.size() == 0 && SPSs.size() == 0)
			result += L"\n"; // fin, pas de extension BLock
	}
	return result;
}

RootFolder::RootFolder(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned char type = *reinterpret_cast<unsigned char*>(buffer + 3);
	log(3, L"🔈sort_index type");
	sortIndex = sort_index(type);

	guid = L"";
	identifier = L"";

	if (size >= (unsigned short int)0x14 && size <= (unsigned short int)0x3a) {
		sortIndex = L"GUID";
		log(3, L"🔈guid_to_wstring guid");
		guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 4));
		log(3, L"🔈trans_guid_to_wstring identifier");
		identifier = trans_guid_to_wstring(guid);
		log(3, L"🔈replaceAll identifier");
		identifier = replaceAll(identifier, L"\\", L"\\\\");
		int pos = 0;
	}
	else if (size > (unsigned short int)0x3a) {
		unsigned int signature = *reinterpret_cast<unsigned int*>(buffer + 6);
		if (signature == (unsigned int)0xf5a6b710) {
			sortIndex = L"DRIVE";
			log(3, L"🔈string_to_wstring identifier");
			identifier = string_to_wstring(std::string((char*)(buffer + 13)));
			log(3, L"🔈replaceAll identifier");
			identifier = replaceAll(identifier, L"\\", L"\\\\");

		}
		if (signature == (unsigned int)0x23a3dfd5) {
			sortIndex = L"SEARCH_FOLDER";
			unsigned int pos = 0x12;
			while (true) {
				log(3, L"🔈SPS");
				SPS block(buffer + pos, niveau + 1);
				if (block.size > 0 && pos < size) {
					SPSs.push_back(block);
				}
				else
					break;
				pos += block.size;
			}
		}
	}
	if (sortIndex == L"UNKNOWN") {
		log(2, L"🔥RootFolder : sortIndex Unknown 0x" + to_hex(type));
	}
	/* TODO: C'est une version simplifiée qui semble suffire pour le moment
	* conforme à la documentation Windows Shell Item format specification https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#43-control-panel-shell-items
	* Le code à l'adresse ci dessous est plus complet
	* https://github.com/49374/OverTheShellbags/blob/main/OverTheShellbags/shell_item_parser.py#L11
	*/

}

std::wstring RootFolder::to_json(int i) {
	log(3, L"🔈RootFolder to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		result += tab(niveau) + L"\"SortIndex\" : \"" + sortIndex + L"\"";
		if (!guid.empty())
			result += L",\n"
			+ tab(niveau) + L"\"GUID\" : \"" + guid + L"\"";
		if (!identifier.empty())
			result += L",\n"
			+ tab(niveau) + L"\"Identifier\" : \"" + identifier + L"\"";

		if (SPSs.size() > 0) {
			result += L",\n";
			result += tab(niveau) + L"\"SPS\" : [\n";
			std::vector<SPS>::iterator it;
			for (it = SPSs.begin(); it != SPSs.end(); it++) {
				result += it->to_json(i);
				if (it != SPSs.end() - 1)
					result += L",";
				result += L"\n";
			}
			result += tab(niveau) + L"]\n";
		}
		else
			result += L"\n";
	}
	return result;
}

NetworkShellItem::NetworkShellItem(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	unsigned char subtype = *reinterpret_cast<unsigned char*>(buffer + 2);
	log(3, L"🔈networkSubType");
	subtypename = networkSubType(subtype);

	if (subtypename == L"Unknown")
		log(2, L"🔥NetworkShellItem : Subtype Unknown 0x" + to_hex(subtype));
	if (subtype == 0xC3) {
		log(3, L"🔈string_to_wstring location");
		location = string_to_wstring(std::string((char*)buffer + 5));
		log(3, L"🔈replaceAll location");
		location = replaceAll(location, L"\\", L"\\\\");
	}
	else {
		log(3, L"🔈wstring_to_filetime modifiedUtc");
		modifiedUtc = wstring_to_filetime(std::wstring((wchar_t*)(buffer + 0x24)));
		log(3, L"🔈FileTimeToLocalFileTime modified");
		FileTimeToLocalFileTime(&modifiedUtc, &modified);
		unsigned int descriptionsize = *reinterpret_cast<unsigned int*>(buffer + 0x54);
		unsigned int commentssize = *reinterpret_cast<unsigned int*>(buffer + 0x58);
		int pos = 0x5c;
		if (descriptionsize > 0)
		{
			description = std::wstring((wchar_t*)(buffer + pos)).data();
			log(3, L"🔈replaceAll description");
			description = replaceAll(description, L"\\", L"\\\\");
			pos += descriptionsize * 2 + 2;
		}
		if (commentssize > 0)
		{
			comments = std::wstring((wchar_t*)(buffer + pos)).data();
			log(3, L"🔈replaceAll comments");
			comments = replaceAll(comments, L"\\", L"\\\\");
			pos += commentssize * 2 + 2;
		}
	}
}

std::wstring NetworkShellItem::to_json(int i) {
	log(3, L"🔈NetworkShellItem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		result += tab(niveau) + L"\"Type\" : \"" + subtypename + L"\",\n";
		if (!location.empty())
			result += tab(niveau) + L"\"Location\" : \"" + location + L"\"\n";
		else {
			log(3, L"🔈time_to_wstring modifiedUtc");
			result += tab(niveau) + L"\"ModifiedUtc\" : \"" + time_to_wstring(modifiedUtc) + L"\",\n";
			log(3, L"🔈time_to_wstring modified");
			result += tab(niveau) + L"\"Modified\" : \"" + time_to_wstring(modified) + L"\",\n";
			result += tab(niveau) + L"\"Description\" : \"" + description + L"\",\n";
			result += tab(niveau) + L"\"Comments\" : \"" + comments + L"\"\n";
		}
	}
	return result;
}

ArchiveFileContent::ArchiveFileContent(LPBYTE buffer, int _niveau) {
	isPresent = true;
	niveau = _niveau;
	unsigned int date = *reinterpret_cast<unsigned int*>(buffer + 8);

	if (date == 0) {
		if (*reinterpret_cast<unsigned int*>(buffer + 0x10) != 0) { // FILETIME
			modifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 0x10);

			log(3, L"🔈time_to_wstring modifiedUtc");
			if (time_to_wstring(modifiedUtc) != L"") {
				log(3, L"🔈FileTimeToLocalFileTime modified");
				FileTimeToLocalFileTime(&modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = std::wstring((wchar_t*)(buffer + 0x20)).data();
		}
		else { // DATE EN WSTRING
			log(3, L"🔈wstring_to_filetime modifiedUtc");
			modifiedUtc = wstring_to_filetime(std::wstring((wchar_t*)(buffer + 0x24)));
			log(3, L"🔈time_to_wstring modifiedUtc");
			if (time_to_wstring(modifiedUtc) != L"") {
				log(3, L"🔈FileTimeToLocalFileTime modified");
				FileTimeToLocalFileTime(&modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = std::wstring((wchar_t*)(buffer + 0x5C)).data();
		}
	}
	else {
		modifiedUtc = FatDateTime(date).to_filetime();
		log(3, L"🔈time_to_wstring modifiedUtc");
		if (time_to_wstring(modifiedUtc) != L"") {
			log(3, L"🔈FileTimeToLocalFileTime modified");
			FileTimeToLocalFileTime(&modifiedUtc, &modified);
		}
		else
			modifiedUtc = { 0 };
		log(3, L"🔈string_to_wstring modified");
		name = string_to_wstring(std::string((char*)(buffer + 0x1C)));
	}
}

std::wstring ArchiveFileContent::to_json(int i) {
	log(3, L"🔈ArchiveFileContent to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		log(3, L"🔈time_to_wstring modifiedUtc");
		result += tab(niveau) + L"\"ModifiedUtc\" : \"" + time_to_wstring(modifiedUtc) + L"\",\n";
		log(3, L"🔈time_to_wstring modified");
		result += tab(niveau) + L"\"Modified\" : \"" + time_to_wstring(modified) + L"\",\n";
		result += tab(niveau) + L"\"Name\" : \"" + name + L"\",\n";
	}
	return result;
}

URIShellItem::URIShellItem(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned short int datasize = *reinterpret_cast<unsigned short int*>(buffer + 4);
	if (datasize == 0) {
		uri = std::wstring((wchar_t*)(buffer + 8)).data();
	}
}

std::wstring URIShellItem::to_json(int i) {
	log(3, L"🔈URIShellItem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		result += tab(niveau) + L"\"Uri\" : \"" + uri + L"\"\n";
	}
	return result;
}

FileEntryShellItem::FileEntryShellItem(LPBYTE buffer, unsigned short int itemSize, unsigned char shell_item_type_char, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	fsFileSize = *reinterpret_cast<unsigned int*>(buffer + 4);
	log(3, L"🔈FatDateTime");
	fsFileModificationUtc = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).to_filetime();
	log(3, L"🔈time_to_wstring fsFileModificationUtc");
	if (time_to_wstring(fsFileModificationUtc) != L"") {
		log(3, L"🔈FileTimeToLocalFileTime fsFileModification");
		FileTimeToLocalFileTime(&fsFileModificationUtc, &fsFileModification);
	}
	else
		fsFileModification = { 0 };
	log(3, L"🔈FsFlags");
	fsFlags = FsFlags(shell_item_type_char);
	log(3, L"🔈FileAttributes");
	fsFileAttributes = FileAttributes((unsigned int)*reinterpret_cast<unsigned short int*>(buffer + 12));

	if (fsFlags.IS_UNICODE)  //Unicode
		fsPrimaryName = std::wstring((wchar_t*)(buffer + 14)).data();
	else {
		log(3, L"🔈string_to_wstring fsPrimaryName");
		fsPrimaryName = string_to_wstring(std::string((char*)(buffer + 14)));
	}

	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + itemSize - 2);
	unsigned short int pos = extensionOffset;
	if (extensionOffset != 0x00) {
		while (pos < itemSize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < itemSize) {
				log(3, L"🔈getExtensionBlock");
				getExtensionBlock(buffer + pos, &extensionBlocks, niveau + 1, &is_zip, fsFlags.IS_FILE);
				pos += size;
			}
			else
				break;
		}
	}
}

std::wstring FileEntryShellItem::to_json(int i) {
	log(3, L"🔈FileEntryShellItem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent == true) {
		log(3, L"🔈to_wstring fsFileAttributes");
		result += tab(niveau) + L"\"Attributes\" : \"" + fsFileAttributes.to_wstring() + L"\",\n";
		log(3, L"🔈to_wstring flags");
		result += tab(niveau) + L"\"Flags\" : \"" + fsFlags.to_wstring() + L"\",\n";
		log(3, L"🔈time_to_wstring fsFileModification");
		result += tab(niveau) + L"\"ModificationDate\" : \"" + time_to_wstring(fsFileModification) + L"\",\n";
		log(3, L"🔈time_to_wstring fsFileModificationUtc");
		result += tab(niveau) + L"\"ModificationDateUtc\" : \"" + time_to_wstring(fsFileModificationUtc) + L"\",\n";
		result += tab(niveau) + L"\"Size\" : \"" + std::to_wstring(fsFileSize) + L"\",\n";
		result += tab(niveau) + L"\"Name\" : \"" + fsPrimaryName + L"\",\n";
		result += tab(niveau) + L"\"ExtensionBlocksCount\" : \"" + std::to_wstring(extensionBlocks.size()) + L"\",\n";
		result += tab(niveau) + L"\"ExtensionBlocks\" : [\n";
		std::vector<IExtensionBlock*>::iterator it;
		for (it = extensionBlocks.begin(); it != extensionBlocks.end(); it++) {
			IExtensionBlock* temp = *it;
			result += temp->to_json(i);
			if (it != extensionBlocks.end() - 1)
				result += L",";
			result += L"\n";
		}
		result += tab(niveau) + L"]\n";
	}
	return result;
}

UsersFilesFolder::UsersFilesFolder(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + size - 2);
	modifiedUtc = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 0x12)).to_filetime();
	log(3, L"🔈FileTimeToLocalFileTime modified");
	FileTimeToLocalFileTime(&modifiedUtc, &modified);
	log(3, L"🔈string_to_wstring primaryName");
	primaryName = string_to_wstring(std::string((char*)buffer + 0x18));
	log(3, L"🔈Beef0004");
	extensionBlock = new Beef0004(buffer + extensionOffset, niveau + 1, NULL, false); // Le bloc suit 
}

std::wstring UsersFilesFolder::to_json(int i) {
	log(3, L"🔈UsersFilesFolder to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		result += tab(niveau) + L"\"PrimaryName\" : \"" + primaryName + L"\",\n";
		log(3, L"🔈time_to_wstring modifiedUtc");
		result += tab(niveau) + L"\"ModifiedDateUtc\" : \"" + time_to_wstring(modifiedUtc) + L"\",\n";
		log(3, L"🔈time_to_wstring modified");
		result += tab(niveau) + L"\"ModifiedDate\" : \"" + time_to_wstring(modified) + L"\"";
		if (extensionBlock->isPresent == true) {
			result += L",\n";
			result += tab(niveau) + L"\"ExtensionBlock\" : \n";
			result += extensionBlock->to_json(i) + L"\n";
		}
		else {
			result += L"\n";
		}
	}
	return result;
}

FavoriteShellitem::FavoriteShellitem(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	log(3, L"🔈UsersPropertyView");
	UPV = UsersPropertyView(buffer, niveau + 1);
}

std::wstring FavoriteShellitem::to_json(int i) {
	log(3, L"🔈FavoriteShellitem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (isPresent) {
		if (UPV.isPresent == true) {
			result = UPV.to_json(i);
		}
	}
	return result;
}

UnknownShellItem::UnknownShellItem(LPBYTE buffer, int _niveau) {
	niveau = _niveau;
	isPresent = true;
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	log(3, L"🔈dump_wstring data");
	data = dump_wstring(buffer, 0, size);
}

std::wstring UnknownShellItem::to_json(int i) {
	log(3, L"🔈UnknownShellItem to_json");
	niveau += i; // décalage supplémentaire si besoin notamment pour les jumplist
	std::wstring result = L"";
	if (!conf._dump)
		tab(niveau) + L"\"Data\" : \"" + data + L"\"\n"; //sinon dump deja present donc pas besoin de data
	return result;
}

void getShellItem(LPBYTE buffer, IShellItem** p, int _niveau, bool Parentiszip) {

	unsigned int item_size = *reinterpret_cast<unsigned short int*>(buffer);
	if (Parentiszip == false) {
		unsigned char type_char = *reinterpret_cast<unsigned char*>(buffer + 2);
		log(3, L"🔈shell_item_class");
		std::wstring type = shell_item_class(type_char);
		if (type == L"VOLUME_SHELL_ITEM") {
			log(3, L"🔈VolumeShellItem");
			*p = new VolumeShellItem(buffer, type_char, _niveau);
		}
		if (type == L"CONTROL_PANEL") {
			log(3, L"🔈ControlPanel");
			*p = new ControlPanel(buffer, item_size, _niveau);
		}
		if (type == L"CONTROL_PANEL_CATEGORY") {
			log(3, L"🔈ControlPanelCategory");
			*p = new ControlPanelCategory(buffer, _niveau);
		}
		if (type == L"ROOT_FOLDER") {
			log(3, L"🔈RootFolder");
			*p = new RootFolder(buffer, _niveau);
		}
		if (type == L"FILE_ENTRY_SHELL_ITEM") {
			log(3, L"🔈FileEntryShellItem");
			*p = new FileEntryShellItem(buffer, item_size, type_char, _niveau);
		}
		if (type == L"USERS_PROPERTY_VIEW") {
			log(3, L"🔈UsersPropertyView");
			*p = new UsersPropertyView(buffer, _niveau);
		}
		if (type == L"NETWORK_LOCATION_SHELL_ITEM") {
			log(3, L"🔈NetworkShellItem");
			*p = new NetworkShellItem(buffer, _niveau);
		}
		if (type == L"URI") {
			log(3, L"🔈URIShellItem");
			*p = new URIShellItem(buffer, _niveau);
		}
		if (type == L"ARCHIVE_FILE_CONTENT") {
			log(3, L"🔈ArchiveFileContent");
			*p = new ArchiveFileContent(buffer, _niveau);
		}
		if (type == L"USERS_FILES_FOLDER") {
			log(3, L"🔈UsersFilesFolder");
			*p = new UsersFilesFolder(buffer, _niveau);
		}
		if (type == L"FAVORITE_SHELL_ITEM") {
			log(3, L"🔈FavoriteShellitem");
			*p = new FavoriteShellitem(buffer, _niveau);
		}
		if (type == L"UNKNOWN") {
			log(3, L"🔈UnknownShellItem");
			*p = new UnknownShellItem(buffer, _niveau);
		}
	}
	else {
		log(3, L"🔈ArchiveFileContent");
		*p = new ArchiveFileContent(buffer, _niveau);
	}
}