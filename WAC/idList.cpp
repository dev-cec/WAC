#include "idList.h"
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
	// Les champs du shell item sont mis a plat dans cet objet (schema d'origine).
	// Garde : shellItem peut etre nul (item de taille nulle, ou type non reconnu).
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

/*! Lit UNE valeur scalaire. Voir `getValue`, qui traite en plus les vecteurs. */
static Json readScalar(LPBYTE buffer, unsigned int* pos, unsigned short valueType,
                         unsigned int level, unsigned int inputSize, bool* typeNotDecoded) {
	// Renvoie desormais une valeur Json typee (et non une chaine pre-serialisee) :
	// l'echappement est fait par le writer, une seule fois, a la serialisation.
	// NB : les backslashes ne sont PLUS doubles ici, ce qui corrige aussi
	// l'avancement de *pos qui etait calcule sur la chaine echappee (donc faux
	// pour toute valeur contenant un backslash, c'est-a-dire tout chemin).
	if (valueType == VT_EMPTY) return Json::str(L"");
	if (valueType == VT_NULL)  return Json::null();
	if (valueType == VT_I2) {
		short v = *reinterpret_cast<short*>(buffer + *pos); *pos += 2; return Json::num((long long)v);
	}
	if (valueType == VT_I4 || valueType == VT_INT) {
		int v = *reinterpret_cast<int*>(buffer + *pos); *pos += 4; return Json::num((long long)v);
	}
	if (valueType == VT_BSTR) {
		std::wstring v((wchar_t*)(buffer + *pos + 4));
		*pos += 4 + (unsigned int)v.size() * 2 + 2;
		return Json::str(v);
	}
	if (valueType == VT_DATE) {
		double t = *reinterpret_cast<double*>(buffer + *pos);
		SYSTEMTIME st = { 0 };
		if (!VariantTimeToSystemTime(t, &st)) { *pos += 8; return Json::null(); }
		*pos += 8;
		// Une date VARIANT (VT_DATE) est exprimee en heure LOCALE par convention OLE.
		return Json::str(timeToIso8601(st, false));
	}
	if (valueType == VT_BOOL) {
		unsigned short v = *reinterpret_cast<unsigned short*>(buffer + *pos); *pos += 2;
		if (v == 0xFFFF) return Json::boolean(true);
		if (v == 0x0000) return Json::boolean(false);
		/* VARIANT_BOOL hors des deux valeurs canoniques : la valeur brute est
		   restituée plutôt qu'une chaîne vide, qui perdait la donnée. */
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
		std::wstring v((wchar_t*)(buffer + *pos + 4));
		*pos += 4 + (unsigned int)v.size() * 2;
		while (buffer[*pos] == 0x00) *pos += 1;   // rembourrage
		return Json::str(v);
	}
	if (valueType == 0x101F) {                     // Vector<VT_LPWSTR>
		Json arr = Json::arr();
		unsigned int nb = *reinterpret_cast<unsigned int*>(buffer + *pos);
		for (unsigned int x = 0; x < nb; x++) {
			unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos + 4);
			arr.push(Json::str(std::wstring((wchar_t*)(buffer + *pos + 8))));
			*pos += 4 + size * 2;
		}
		return arr;
	}
	if (valueType == 0x1011) {                     // Vector<VT_UI1>
		unsigned short size = *reinterpret_cast<unsigned short*>(buffer + *pos);
		Json r = Json::str(L"Not implemented");    // contenu inconnu (system.delegateidlist)
		if (*reinterpret_cast<unsigned int*>(buffer + *pos + 0x8) == 0x53505331)
			r = SPS(buffer + *pos + 0x4, level + 2).toJson();
		else if (*reinterpret_cast<unsigned int*>(buffer + *pos + 0x1c) == 0x53505331)
			r = SPS(buffer + *pos + 0x8, level + 2).toJson();
		*pos += size;
		return r;
	}
	if (valueType == VT_FILETIME) {
		// Un FILETIME est UTC par definition : etiquette « Z », pas le fuseau local.
		Json r = Json::str(timeToIso8601Utc(*reinterpret_cast<FILETIME*>(buffer + *pos)));
		*pos += 8; return r;
	}
	if (valueType == VT_BLOB) {
		/* L'ANCIENNE VERSION SUPPOSAIT TOUJOURS TROIS PROPERTY STORES à
		   l'offset 17, codé en dur et sans vérifier quoi que ce soit. Sur un
		   BLOB d'une autre forme — et rien ne garantit celle-là — les trois
		   lectures partaient dans des octets arbitraires et publiaient des
		   propriétés inventées. Le contenu brut, lui, n'était jamais rendu.

		   Désormais : la taille annoncée borne la lecture, la signature
		   « SPS1 » est vérifiée avant de décoder, et l'on enchaîne autant de
		   stores que le BLOB en contient réellement. À défaut, les octets. */
		const unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos);
		const unsigned int start = *pos + 4;
		Json o = Json::obj();
		o.add(L"DataSize", Json::num(size));
		const bool boundsOk = (size > 0)
		                   && (inputSize == 0 || start + size <= inputSize);
		if (!boundsOk) {
			log(2, L"🔥VT_BLOB: size outside the entry (" + std::to_wstring(size) + L")");
		}
		/* Le décalage de 13 octets entre le début du BLOB et le premier store a
		   été relevé empiriquement ; il n'est appliqué que si la signature s'y
		   trouve effectivement. */
		else if (*reinterpret_cast<const unsigned int*>(buffer + start + 13 + 4) == 0x53505331) {
			Json arr = Json::arr();
			unsigned int p = start + 13;
			const unsigned int end = start + size;
			while (p + 8 < end) {
				if (*reinterpret_cast<const unsigned int*>(buffer + p + 4) != 0x53505331) break;
				SPS sps(buffer + p, level + 2);
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
		/* LE CONTENU DU FLUX ÉTAIT JETÉ. Le code lisait le nom du flux, lisait la
		   taille des données, avançait d'autant… et ne rendait que le nom. Or ce
		   nom est un simple identifiant d'indirection : sur une collecte réelle,
		   les quinze valeurs VT_STREAM rendaient toutes « prop4294967295 ».
		   Autrement dit l'artefact ne portait rien d'exploitable, alors que les
		   données étaient là.

		   Le contenu est désormais restitué. Quand il commence par la signature
		   « SPS1 », c'est un property store imbriqué : il est décodé comme tel —
		   même cas que Vector<VT_UI1>. Sinon, les octets sont rendus en
		   hexadécimal. */
		const unsigned int nameSize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		*pos += 4;
		const std::wstring name((wchar_t*)(buffer + *pos));
		*pos += nameSize + 2;
		const unsigned int dataSize = *reinterpret_cast<unsigned int*>(buffer + *pos);
		const unsigned int dataStart = *pos + 4;

		Json o = Json::obj();
		o.add(L"StreamName", Json::str(name));
		o.add(L"DataSize",   Json::num(dataSize));
		const bool boundsOk = (dataSize > 0)
		                   && (inputSize == 0 || dataStart + dataSize <= inputSize);
		if (!boundsOk) {
			if (dataSize > 0)
				log(2, L"🔥VT_STREAM: data size outside the entry ("
				     + std::to_wstring(dataSize) + L")");
		}
		else if (*reinterpret_cast<const unsigned int*>(buffer + dataStart + 4) == 0x53505331) {
			// Property store imbrique : la signature « SPS1 » suit la taille.
			log(3, L"🔈VT_STREAM: nested property store");
			o.add(L"PropertyStore", SPS(buffer + dataStart, level + 2).toJson());
		}
		else {
			log(3, L"🔈dump_wstring VT_STREAM");
			o.add(L"Data", Json::str(dump_wstring(buffer, (int)dataStart,
			                                      (int)dataSize)));
		}
		*pos += dataSize;
		return o;
	}
	/* TYPES AJOUTÉS pour aligner la couverture sur libfwps (libyal), référence du
	   format des property stores. Ils manquaient tous les cinq, et sortaient
	   donc sans valeur. Tailles et sémantique d'après MS-OLEPS. */
	if (valueType == VT_R4) {                      // 0x0004 : flottant 32 bits
		float v = *reinterpret_cast<float*>(buffer + *pos); *pos += 4;
		return Json::str(std::to_wstring(v));
	}
	if (valueType == VT_CY) {                      // 0x0006 : monétaire
		/* Entier signé 64 bits valant le montant multiplié par 10 000. La valeur
		   brute est conservée : la diviser ici imposerait un format décimal et
		   perdrait de la précision. */
		long long v = *reinterpret_cast<long long*>(buffer + *pos); *pos += 8;
		Json o = Json::obj();
		o.add(L"ScaledBy10000", Json::num(v));
		return o;
	}
	if (valueType == VT_ERROR) {                   // 0x000A : HRESULT
		unsigned int v = *reinterpret_cast<unsigned int*>(buffer + *pos); *pos += 4;
		return Json::str(L"0x" + to_hex(v));
	}
	if (valueType == VT_DECIMAL) {                 // 0x000E : décimal 128 bits
		/* Structure DECIMAL de Windows : 16 octets. Restituée en octets bruts
		   plutôt que convertie — une conversion en double perdrait justement la
		   précision qui fait l'intérêt de ce type. */
		Json o = Json::obj();
		o.add(L"Decimal128", Json::str(dump_wstring(buffer, (int)*pos, 16)));
		*pos += 16;
		return o;
	}
	if (valueType == VT_LPSTR) {                   // 0x001E : chaîne ASCII
		/* Taille en OCTETS, terminateur inclus — contrairement à VT_LPWSTR dont
		   la taille est en caractères. */
		unsigned int size = *reinterpret_cast<unsigned int*>(buffer + *pos);
		std::wstring v = string_to_wstring(std::string((char*)(buffer + *pos + 4)));
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

	/* TYPE NON DÉCODÉ : ON REND LES OCTETS.
	 *
	 * La version précédente rendait une chaîne vide. La propriété apparaissait
	 * donc avec son nom et son type, mais SANS valeur — indiscernable d'une
	 * propriété réellement vide, et la donnée était perdue alors qu'elle est
	 * présente dans le fichier. Un type que nous ne savons pas lire ne doit pas
	 * faire disparaître son contenu : on restitue les octets restants de
	 * l'entrée, en hexadécimal, pour qu'un analyste puisse les décoder — même
	 * raison d'être que le dump de `UnknownShellItem` et de `BeefUnknown`.
	 *
	 * La position n'est pas avancée : elle ne sert qu'à l'intérieur de l'entrée,
	 * dont le parcours est borné par sa propre taille chez l'appelant. */
	if (typeNotDecoded) *typeNotDecoded = true;
	Json o = Json::obj();
	o.add(L"UnsupportedValueType", Json::str(L"0x" + to_hex(valueType)));
	if (inputSize > *pos) {
		log(3, L"🔈dump_wstring: value type not supported");
		// « tailleEntree - pos » est bien une LONGUEUR : les octets restants.
		o.add(L"Data", Json::str(dump_wstring(buffer, (int)*pos, (int)(inputSize - *pos))));
	}
	log(2, L"🔥getValue: value type not supported 0x" + to_hex(valueType));
	return o;
}

/*! Lit une valeur de property store, scalaire ou VECTEUR.
*
*  LES VECTEURS SONT DÉSORMAIS TRAITÉS GÉNÉRIQUEMENT. Le bit `VT_VECTOR`
*  (0x1000) signale un tableau : un compteur d'éléments sur 32 bits, puis les
*  éléments du type scalaire correspondant (MS-OLEPS). Deux vecteurs seulement
*  étaient reconnus — `Vector<VT_UI1>` et `Vector<VT_LPWSTR>` — et tous les
*  autres (`Vector<VT_FILETIME>`, `Vector<VT_CLSID>`, `Vector<VT_I4>`,
*  `Vector<VT_LPSTR>`…) tombaient dans le cas « type non pris en charge ».
*  Décoder le compteur puis déléguer chaque élément au lecteur scalaire les
*  couvre tous d'un coup, et tout type scalaire ajouté plus tard bénéficie
*  automatiquement de sa forme vectorielle.
*
*  Les deux vecteurs historiques gardent leur traitement propre : celui de
*  `Vector<VT_UI1>` n'est pas un simple tableau d'octets mais peut contenir un
*  property store imbriqué (signature « SPS1 »), ce qu'aucune règle générique ne
*  devinerait.
*/
Json getValue(LPBYTE buffer, unsigned int* pos, unsigned short valueType, unsigned int level,
              unsigned int inputSize, bool* typeNotDecoded) {
	const unsigned short VT_VECTOR_BIT = 0x1000;

	// Cas particuliers conserves : heuristiques propres a ces deux vecteurs.
	if (valueType == 0x1011 || valueType == 0x101F)
		return readScalar(buffer, pos, valueType, level, inputSize, typeNotDecoded);

	if ((valueType & VT_VECTOR_BIT) == 0)
		return readScalar(buffer, pos, valueType, level, inputSize, typeNotDecoded);

	const unsigned short typeElement = (unsigned short)(valueType & 0x0FFF);
	const unsigned int nb = *reinterpret_cast<unsigned int*>(buffer + *pos);
	*pos += 4;
	log(3, L"🔈vector of " + std::to_wstring(nb) + L" element(s) de type 0x"
	     + to_hex(typeElement));

	/* Un compteur aberrant vient d'une donnee corrompue ou d'un type mal
	   identifie : on rend les octets au lieu d'iterer des millions de fois. */
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
			/* Sans savoir la taille d'un element, la position n'avance pas :
			   continuer relirait le meme octet. On s'arrete en le signalant. */
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
			// Le nom inconnu est desormais la CLE BRUTE, journalisee par
			// to_FriendlyName lui-meme : le test sur « (Undefined) » n'a plus
			// d'objet et faisait doublon.
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
	o.add(L"Value", value);          // valeur deja typee (chaine, nombre, objet, tableau)
	return o;
}

SPS::SPS(LPBYTE buffer, int _level) {
	level = _level;
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
		SPSValue block(buffer + pos, guid, level + 2); // concordance avec toJson
		if (block.size == 0) { //vide
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
	/* GUID du property store (son « format ID ») et son libelle : releves par le
	   constructeur et jamais emis. Chaque valeur porte deja le GUID dans son
	   champ ID, mais un store SANS valeur perdait toute identification — et le
	   libelle du store n'apparaissait nulle part. */
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
	/* VERSION DU BLOC : elle etait mise a zero et jamais relue, donc ni exploitee
	   ni emise. Or c'est une donnee d'enquete : elle indique quelle version de
	   Windows a ECRIT l'entree — 0x0003 (XP), 0x0007 (Vista), 0x0008 (Windows 7),
	   0x0009 (Windows 8.1 et au-dela) — et determine quels champs le bloc
	   contient. Offset 2, juste avant la signature lue en 4. */
	ExtensionVersion = *reinterpret_cast<unsigned short int*>(buffer + 2);
	/* CORRECTION (double decalage sur les dates FAT,).
	   Une date FAT/DOS est stockee en HEURE LOCALE, par specification du format.
	   Le code affectait cette valeur locale a `creationDateUtc`, puis lui
	   appliquait FileTimeToLocalFileTime — traitant donc du local comme de l'UTC.
	   Resultat : la cle *Utc publiait une heure locale etiquetee UTC, et la cle
	   locale une heure decalee une SECONDE fois (+2 h a Paris en ete).
	   Le sens correct est l'inverse : la valeur native est locale, on en derive
	   l'UTC. */
	creationDate = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime creationDate");
	LocalFileTimeToFileTime(&creationDate, &creationDateUtc);

	accessedDate = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 12)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime accessedDate");
	LocalFileTimeToFileTime(&accessedDate, &accessedDateUtc);
	/* IDENTIFIANT ET RÉFÉRENCE $MFT (versions >= 7), et surtout OFFSETS CALCULÉS
	 * D'APRÈS LA VERSION.
	 *
	 * CE QUI ÉTAIT FAUX. Les offsets du nom long étaient codés en dur (36 et 46)
	 * — ils ne sont exacts que pour la VERSION 9 du bloc, celle de Windows 8.1
	 * et au-delà. Sur un bloc de version 3 (Windows XP), 7 (Vista) ou 8
	 * (Windows 7), le nom long était donc lu au mauvais endroit. C'est
	 * exactement le genre de défaut qui ne se voit pas sur une machine récente
	 * et se révèle sur un système ancien, comme l'attribut $ATTRIBUTE_LIST
	 *. La version, désormais lue (offset 2), sert à calculer la
	 * position réelle — même enchaînement que l'implémentation de référence
	 * d'Eric Zimmerman (ExtensionBlocks). */
	identifier = *reinterpret_cast<unsigned short int*>(buffer + 16);
	unsigned int off = 18;                        // fin de la partie fixe
	if (ExtensionVersion >= 7) {
		off += 2;                                 // deux octets vides
		/* Référence de fichier : 6 octets d'index d'entrée, 2 de séquence. */
		const unsigned long long brut = *reinterpret_cast<unsigned long long*>(buffer + off);
		mftEntryNumber    = brut & 0x0000FFFFFFFFFFFFULL;
		mftSequenceNumber = (unsigned short int)(brut >> 48);
		if (mftEntryNumber != 0 && mftSequenceNumber != 0)      mftNote = L"NTFS";
		else if (mftEntryNumber != 0 && mftSequenceNumber == 0) mftNote = L"FAT";
		else                                                    mftNote = L"Network/special item";
		off += 8;                                 // reference de fichier
		off += 8;                                 // huit octets inconnus
	}
	if (ExtensionVersion >= 3) off += 2;
	if (ExtensionVersion >= 9) off += 4;
	if (ExtensionVersion >= 8) off += 4;

	unsigned short int longNameSize = 0;
	longNameSize = *reinterpret_cast<unsigned short int*>(buffer + 36);
	longName = std::wstring((wchar_t*)(buffer + off)).data();
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
		localizedName = std::wstring((wchar_t*)(buffer + off + (longName.size() + 1) * 2)).data();
	}
}

Json Beef0004::toJson() {
	log(3, L"🔈Beef0004 toJson");
	Json o = Json::obj();
	o.add(L"Signature", Json::str(signature));
	// Version du bloc : dit quelle version de Windows a ecrit l'entree.
	o.add(L"ExtensionVersion", Json::str(L"0x" + to_hex(ExtensionVersion)));
	o.add(L"Identifier",       Json::num(identifier));
	/* Reference $MFT : n'existe qu'a partir de la version 7 du bloc. Emise
	   seulement si elle est presente, pour ne pas publier de zeros trompeurs. */
	if (!mftNote.empty()) {
		o.add(L"MftEntryNumber",    Json::num(mftEntryNumber));
		o.add(L"MftSequenceNumber", Json::num(mftSequenceNumber));
		o.add(L"MftNote",           Json::str(mftNote));
	}
	// CORRECTION : les cles Created* publiaient accessedDate/accessedDateUtc,
	// alors que creationDate/creationDateUtc sont bien parses. La date de
	// creation etait donc perdue et remplacee par la date d'acces.
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
	int pos = 0;
	while (*reinterpret_cast<short int*>(buffer + pos) != 0x0000)
		pos += 1;
	username = std::wstring((wchar_t*)(buffer + pos + 2)).data();
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

/* NON COUVERT PAR LES TESTS (vérifié le 2026-09-15).
 * La VM de validation ne produit que des blocs 0xbeef0004 : ce constructeur n'est
 * jamais exercé, ses offsets (GUID en +16, 3 SPS à partir de +50, puis +11 avant
 * 3 chaînes) restent donc des hypothèses non vérifiées.
 * Pour l'exercer il faut des shellbags contenant ce bloc — ce qui suppose une
 * session INTERACTIVE dans l'explorateur (les shellbags ne sont pas alimentés par
 * un processus lancé en service), ou un jeu de ruches de référence.
 * Tant que ce n'est pas fait : sortie à considérer comme non validée. */
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
		SPS s = SPS(buffer + pos, level + 1);
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
			getExtensionBlock(buffer + pos, &extensionblocks, level + 1, NULL, false);
			pos += size;
		}
		else
			break;
	}
	while (true) {
		unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos); // recherche de idlist
		if (size > 0) {
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
	/* MEMBRES COLLECTES ET JAMAIS EMIS. Le constructeur relevait le GUID, son
	   libelle, TROIS property stores et des blocs d'extension ; toJson ne
	   publiait que la signature et les shell items. Tout le reste etait lu puis
	   jete — meme defaut que UsersPropertyView, trouve par le meme audit. */
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
	sps = SPS(buffer + 16, level + 1);
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
	value = std::wstring((wchar_t*)(buffer + 10)).data();
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
	fileDocumentTypeString = std::wstring((wchar_t*)(buffer + 10)).data();
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
	fileDocumentTypeString = std::wstring((wchar_t*)(buffer + 10)).data();
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
	executable = std::wstring((wchar_t*)(buffer + 10)).data();
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
	pinType = std::wstring((wchar_t*)(buffer + 10)).data();
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
	sps = SPS(buffer + 8, level + 1);
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
	sps = SPS(buffer + 8, level + 1);
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
	// FILETIME bruts lus du buffer : UTC par definition du type.
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
		idlist = std::make_unique<IdList>(buffer + 38, level + 2);
	}
	else {
		ctimeUtc = { 0 };
		ctime = { 0 };
		mtimeUtc = { 0 };
		mtime = { 0 };
		atimeUtc = { 0 };
		atime = { 0 };
		log(3, L"🔈SPS");
		sps = std::make_unique<SPS>(buffer + 8, level + 2);
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
	sps = SPS(buffer + 8, level + 1);
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
	// Les octets, pour que le bloc reste decodable plus tard.
	o.add(L"Data",      Json::str(data));
	return o;
}

void getExtensionBlock(LPBYTE buffer, std::vector<std::unique_ptr<IExtensionBlock>>* extensionBlocks, int _level, bool* is_zip, bool is_file) {
	std::unique_ptr<IExtensionBlock> block;
	unsigned int signature = *reinterpret_cast<unsigned int*>(buffer + 4);
	/*  TAILLE ANNONCEE du bloc. Un bloc d'extension fait au moins 8 octets : sa
	    taille, sa version et sa signature. En deca, la structure est fausse et
	    la faire analyser ferait lire des champs pris n'importe ou. */
	unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer);
	if (size < 8) {
		log(2, L"🔥Extension block of size " + std::to_wstring(size)
		     + L" (minimum 8) : signature " + to_hex(signature) + L" ignored",
		    ERROR_INVALID_DATA);
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
		/* Le dump n'allait QUE dans le journal, et le bloc n'était pas ajouté à
		   la liste : il n'apparaissait donc pas dans le JSON, et disparaissait
		   entièrement au niveau de journalisation par défaut. Il est désormais
		   émis comme les autres, avec ses octets (cf. BeefUnknown). */
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
		return std::wstring(&result[0], &result[0] + result.size() - 2);//suppression de la dernière virgule et espace
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
		name = string_to_wstring(std::string((char*)buffer + 3));
	}
	else if (flags.SystemFolder == true) {
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
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < itemSize) {
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
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < totalsize) {
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

Property::Property(LPBYTE buffer, int _level) {
	level = _level;
	id = 0;
	type = 0;
	unsigned int pos = 0;
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
	value = getValue(buffer, &pos, type, level, 0, &typeNotDecoded);
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
	/*  Les DEUX chaines annoncent leur taille, en octets. Elles etaient lues
	    jusqu'au premier zero rencontre : sur une structure abimee, la lecture
	    partait au-dela de la zone. La taille annoncee borne desormais chacune,
	    et le terminateur eventuel est retire apres coup. */
	auto boundedString = [](LPBYTE p, unsigned int bytes) {
		if (bytes == 0 || bytes > 64 * 1024) return std::wstring();
		std::wstring s((const wchar_t*)p, bytes / sizeof(wchar_t));
		while (!s.empty() && s.back() == L'\0') s.pop_back();
		return s;
	};
	unsigned int pos = 0x14;//unknown
	unsigned int wstring1Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	folder = boundedString(buffer + pos, wstring1Size);
	pos += wstring1Size;
	pos += 16;//unknown
	unsigned int wstring2Size = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	fullurl = boundedString(buffer + pos, wstring2Size);
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
	unsigned int pos = 0;
	level = _level;
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
		Property temp(buffer + pos, level + 1);
		const bool stop = temp.typeNotDecoded;   // taille indeterminee, cf. idList.h
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
	/* Toutes les longueurs ci-dessous viennent du fichier analysé — donc d'une
	   source non fiable — et servent à calculer des offsets de lecture. Le
	   constructeur ne reçoit pas la taille du tampon, il ne peut donc pas les
	   valider contre elle. On les borne au maximum PLAUSIBLE : un shell item
	   porte sa taille sur 16 bits, il ne peut pas dépasser 64 Kio, soit 32768
	   caractères UTF-16. Une valeur au-delà signale une donnée corrompue ou
	   forgée, et la lecture est abandonnée plutôt que de parcourir la mémoire
	   au hasard. */
	constexpr int MAX_CARS = 32768;        // 64 Kio / 2 : taille max d'un shell item
	constexpr unsigned MAX_ELEMENTS = 1024; // bien au-delà du plausible, mais fini

	unsigned int pos = 0;
	level = _level;
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
		return;                            // champs laissés vides : rien de douteux n'est publié
	}

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

	/* L'interprétation de ce champ comme « nombre de propriétés » n'est pas
	   confirmée par la spécification : à l'observation, seules les 4 premières
	   entrées sont exploitables. Tant que ce n'est pas tranché, la valeur est
	   bornée et la boucle s'arrête si une propriété rend une taille nulle —
	   sinon `pos` n'avancerait plus et on relirait la même zone. */
	unsigned int numberProperties = *reinterpret_cast<unsigned int*>(buffer + pos);
	pos += 4;
	if (numberProperties > MAX_ELEMENTS) {
		log(2, L"🔥UserPropertyView0x10312005: implausible number of properties ("
		     + std::to_wstring(numberProperties) + L"): reading abandoned", ERROR_INVALID_DATA);
		numberProperties = 0;
	}
	for (unsigned int x = 0; x < numberProperties; x++) {
		log(3, L"🔈Property");
		Property temp(buffer + pos, level + 1);
		if (temp.size == 0) {
			log(2, L"🔥Property of null size: walk stopped", ERROR_INVALID_DATA);
			break;
		}
		const bool stop = temp.typeNotDecoded;   // taille indeterminee, cf. idList.h
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
	// CORRECTION : la cle d'origine etait « Star-system », vestige d'un
	// rechercher-remplacer manque. Elle publiait le nom du systeme de fichiers
	// sous un intitule que personne ne peut deviner : information collectee mais
	// introuvable a l'analyse.
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
	unsigned short int signature_short = *reinterpret_cast<unsigned short int*>(buffer + 6); // Certaines signatures sont identifiées par leurs 2 premiers octets
	SPSDataSize = *reinterpret_cast<unsigned short int*>(buffer + 10);
	identifierSize = *reinterpret_cast<unsigned short int*>(buffer + 12);
	dataOffset = 14;

	/* NATURE DE L'ITEM, d'après sa signature.
	 *
	 * Chez libyal (libfwsi_users_property_view_values.c) la signature ne sert
	 * pas seulement à choisir un décodeur : elle IDENTIFIE le type d'item. Deux
	 * de celles traitées ici ne sont pas des « users property view » du tout :
	 *   0x10312005 = VOLUME MTP,      0x07192006 = ENTRÉE DE FICHIER MTP,
	 * c'est-à-dire la trace qu'un téléphone, un appareil photo ou un lecteur
	 * multimédia a été branché et parcouru. Le nom générique masquait ce fait,
	 * qui est justement ce qu'une investigation cherche.
	 * Le champ `itemType` le nomme désormais dans la sortie. */
	switch (signature) {
	case 0x10312005: itemType = L"MTP Volume";                          break;
	case 0x07192006: itemType = L"MTP File Entry";                       break;
	case 0x23febbee: itemType = L"Users Property View (known folder)";   break;
	/* Les quatre suivantes sont reconnues par libfwsi et n'étaient pas
	   traitées : l'item tombait dans la branche « signature inconnue ». */
	case 0x10141981:
	case 0x23a3dfd5:
	case 0x3b93afbb:
	case 0x49505241:
	case 0xbeebee00: itemType = L"Users Property View";                  break;
	default: break;
	}

	if (signature == (unsigned int)0x23febbee) {
		/* GUID DE DOSSIER CONNU, et seulement si l'identifiant EST un GUID.
		   libfwsi lit ces 16 octets sous condition `identifier_size == 16` ;
		   WAC ne vérifiait rien et publiait donc un GUID composé d'octets
		   arbitraires dès que l'identifiant avait une autre taille. */
		if (identifierSize == 16) {
			log(3, L"🔈UserPropertyView0x23febbee");
			delegate = std::make_unique<UserPropertyView0x23febbee>(buffer, level);
		}
		else
			log(2, L"🔥0x23febbee: identifier of " + std::to_wstring(identifierSize)
			     + L" octets au lieu de 16, GUID non lu");
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
	/* Signatures repertoriees par libfwsi sans structure propre : l'item porte
	   un identifiant puis son property store. Trois d'entre elles ont un
	   identifiant de 4 octets, que libfwsi relève. */
	else if (!itemType.empty()) {
		if (identifierSize == 4) {
			identifier32 = *reinterpret_cast<unsigned int*>(buffer + dataOffset);
			identifier32Lu = true;
		}
		spsOffset = dataOffset + identifierSize;
		while (true) {
			log(3, L"🔈SPS");
			SPS block(buffer + spsOffset + pos, level + 1);
			if (block.size && pos < SPSDataSize) SPSs.push_back(block);
			else break;
			pos += block.size;
		}
	}
	else if (SPSDataSize > 0) {
		spsOffset = dataOffset + identifierSize;
		while (true) {
			log(3, L"🔈SPS");
			SPS block(buffer + spsOffset + pos, level + 1);
			if (block.size && pos < SPSDataSize) {
				SPSs.push_back(block);
			}
			else
				break;
			pos += block.size;
		}
	}
	else {
		/* Signature non reconnue : les octets sont conservés DANS LA SORTIE, et
		   non plus seulement dans le journal (cf. idList.h). Sans quoi l'objet
		   se réduisait à son type et à une signature, ce qui ne permet ni de
		   l'analyser ni même de savoir qu'on a perdu quelque chose. */
		log(3, L"🔈dump_wstring UsersPropertyView: unknown signature");
		data = dump_wstring(buffer, 0, totalsize);
		log(2, L"🔥UsersPropertyView Signature 0x" + to_hex(signature) + L" unknown");
	}

	unsigned short int extensionOffset = *reinterpret_cast<unsigned short int*>(buffer + totalsize - 2);
	if (extensionOffset != 0x00) {
		pos = extensionOffset;
		while (pos < totalsize) {
			unsigned short int size = *reinterpret_cast<unsigned short int*>(buffer + pos);
			if (size > 0 && pos < totalsize) {
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
	// Nature de l'item : « MTP Volume », « MTP File Entry »… cf. idList.h.
	if (!itemType.empty()) o.add(L"ItemType", Json::str(itemType));
	if (identifier32Lu)    o.add(L"Identifier", Json::num(identifier32));
	// les champs du delegue sont mis a plat (schema d'origine)
	if (delegate) o.merge(delegate->toJson());

	/* SPS et blocs d'extension : ILS ETAIENT COLLECTES ET JAMAIS EMIS.
	   Le constructeur remplit `SPSs` (branche sans delegue) et `extensionBlocks`
	   (systematiquement, si l'objet en porte), mais toJson n'en publiait aucun :
	   tout leur contenu — noms de proprietes, valeurs, dates — etait lu puis
	   jete. Les delegues portent des `properties`, pas ces deux vecteurs : il
	   n'y a donc pas de doublon a craindre. */
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
	// Octets bruts si la signature n'a pas ete reconnue (cf. idList.h).
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

	if (size >= (unsigned short int)0x14 && size <= (unsigned short int)0x3a) {
		sortIndex = L"GUID";
		log(3, L"🔈guid_to_wstring guid");
		guid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + 4));
		log(3, L"🔈trans_guid_to_wstring identifier");
		identifier = trans_guid_to_wstring(guid);
	}
	else if (size > (unsigned short int)0x3a) {
		unsigned int signature = *reinterpret_cast<unsigned int*>(buffer + 6);
		if (signature == (unsigned int)0xf5a6b710) {
			sortIndex = L"DRIVE";
			log(3, L"🔈string_to_wstring identifier");
			identifier = string_to_wstring(std::string((char*)(buffer + 13)));

		}
		if (signature == (unsigned int)0x23a3dfd5) {
			sortIndex = L"SEARCH_FOLDER";
			unsigned int pos = 0x12;
			while (true) {
				log(3, L"🔈SPS");
				SPS block(buffer + pos, level + 1);
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
		location = string_to_wstring(std::string((char*)buffer + 5));
	}
	else {
		log(3, L"🔈wstring_to_filetime modifiedUtc");
		modifiedUtc = wstring_to_filetime(std::wstring((wchar_t*)(buffer + 0x24)));
		log(3, L"🔈utcVersLocalSuspect modified");
		utcToSuspectLocal(modifiedUtc, &modified);
		unsigned int descriptionsize = *reinterpret_cast<unsigned int*>(buffer + 0x54);
		unsigned int commentssize = *reinterpret_cast<unsigned int*>(buffer + 0x58);
		int pos = 0x5c;
		if (descriptionsize > 0)
		{
			description = std::wstring((wchar_t*)(buffer + pos)).data();
			pos += descriptionsize * 2 + 2;
		}
		if (commentssize > 0)
		{
			comments = std::wstring((wchar_t*)(buffer + pos)).data();
			pos += commentssize * 2 + 2;
		}
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
		if (*reinterpret_cast<unsigned int*>(buffer + 0x10) != 0) { // FILETIME
			modifiedUtc = *reinterpret_cast<FILETIME*>(buffer + 0x10);

			log(3, L"🔈timeToIso8601 modifiedUtc");
			if (timeToIso8601Utc(modifiedUtc) != L"") {
				log(3, L"🔈utcVersLocalSuspect modified");
				utcToSuspectLocal(modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = std::wstring((wchar_t*)(buffer + 0x20)).data();
		}
		else { // DATE EN WSTRING
			log(3, L"🔈wstring_to_filetime modifiedUtc");
			modifiedUtc = wstring_to_filetime(std::wstring((wchar_t*)(buffer + 0x24)));
			log(3, L"🔈timeToIso8601 modifiedUtc");
			if (timeToIso8601Utc(modifiedUtc) != L"") {
				log(3, L"🔈utcVersLocalSuspect modified");
				utcToSuspectLocal(modifiedUtc, &modified);
			}
			else
				modifiedUtc = { 0 };
			name = std::wstring((wchar_t*)(buffer + 0x5C)).data();
		}
	}
	else {
		// Date FAT = heure LOCALE : on en derive l'UTC, pas l'inverse.
		modified = FatDateTime(date).toFileTime();
		log(3, L"🔈LocalFileTimeToFileTime modified");
		LocalFileTimeToFileTime(&modified, &modifiedUtc);
		log(3, L"🔈string_to_wstring modified");
		name = string_to_wstring(std::string((char*)(buffer + 0x1C)));
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
	// TAILLE DE L'ITEM : elle borne l'URI, qui etait lue jusqu'au premier zero
	// rencontre — donc potentiellement au-dela de l'item.
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
	// Date FAT = heure LOCALE : on en derive l'UTC, pas l'inverse.
	fsFileModification = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 8)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime fsFileModification");
	LocalFileTimeToFileTime(&fsFileModification, &fsFileModificationUtc);
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
	o.add(L"Size",                Json::num((unsigned long long)fsFileSize));   // nombre
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
	// Date FAT = heure LOCALE : on en derive l'UTC, pas l'inverse.
	modified = FatDateTime(*reinterpret_cast<unsigned int*>(buffer + 0x12)).toFileTime();
	log(3, L"🔈LocalFileTimeToFileTime modified");
	LocalFileTimeToFileTime(&modified, &modifiedUtc);
	log(3, L"🔈string_to_wstring primaryName");
	primaryName = string_to_wstring(std::string((char*)buffer + 0x18));
	log(3, L"🔈Beef0004");
	extensionBlock = std::make_unique<Beef0004>(buffer + extensionOffset, level + 1, nullptr, false); // Le bloc suit 
}

Json UsersFilesFolder::toJson() {
	log(3, L"🔈UsersFilesFolder toJson");
	Json o = Json::obj();
	if (!isPresent) return o;
	o.add(L"PrimaryName",     Json::str(primaryName));
	o.add(L"ModifiedDateUtc", Json::str(timeToIso8601Utc(modifiedUtc)));
	o.add(L"ModifiedDate",    Json::str(timeToIso8601Local(modified)));
	// garde : extensionBlock peut etre nul
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
	// Champs non decodes : les octets restent joints (cf. idList.h).
	o.add(L"Data",     Json::str(data));
	return o;
}

DelegateFolder::DelegateFolder(LPBYTE buffer, unsigned short size, int _level) {
	level = _level;
	isPresent = true;

	/* GUID de la classe qui delegue : les 16 derniers octets de l'item. */
	if (size >= 16) {
		log(3, L"🔈guid_to_wstring classGuid");
		classGuid = guid_to_wstring(*reinterpret_cast<GUID*>(buffer + size - 16));
		log(3, L"🔈trans_guid_to_wstring classFriendlyName");
		classFriendlyName = trans_guid_to_wstring(classGuid);
	}

	/* SHELL ITEM IMBRIQUE : taille sur 4 octets a l'offset 4, contenu a partir
	   de l'offset 6. Les 32 derniers octets portent le marqueur de delegation et
	   le GUID de classe, ils ne font pas partie de l'item interne. */
	const unsigned int internalSize = *reinterpret_cast<unsigned int*>(buffer + 4);
	if (size > 38 && internalSize > 0 && internalSize <= (unsigned int)(size - 38)) {
		log(3, L"🔈makeShellItem: delegate");
		innerItem = makeShellItem(buffer + 6, level + 1, false);
	}
	else {
		log(2, L"🔥DelegateFolder: inconsistent internal size ("
		     + std::to_wstring(internalSize) + L")");
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
	// L'item delegue est mis a plat, comme les autres shell items imbriques.
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
	// CORRECTION : l'ancienne version construisait la chaine sans jamais
	// l'affecter -> tout shell item de type non reconnu etait silencieusement
	// perdu. On remonte desormais systematiquement le dump brut, pour qu'un
	// type inconnu soit visible et analysable au lieu d'etre ignore.
	Json o = Json::obj();
	o.add(L"Unknown", Json::boolean(true));
	o.add(L"Data",    Json::str(data));   // dump hexa de l'item
	return o;
}

std::unique_ptr<IShellItem> makeShellItem(LPBYTE buffer, int _level, bool Parentiszip) {

	unsigned int item_size = *reinterpret_cast<unsigned short int*>(buffer);
	if (Parentiszip == false) {
		/* TYPES RECONNUS PAR UNE SIGNATURE DANS LES DONNÉES, testés AVANT
		 * l'octet de classe.
		 *
		 * CE QUI MANQUAIT. WAC n'identifiait un shell item que par son octet de
		 * classe. Or six types documentés ne se reconnaissent pas là : ils
		 * portent une signature dans leurs données, et libfwsi les identifie en
		 * essayant chaque décodeur (libfwsi_item.c). Tous tombaient donc dans
		 * « UNKNOWN », le plus coûteux étant le dossier délégué — courant dans
		 * les shellbags, et qui enveloppe un shell item entièrement décodable.
		 *
		 * L'ordre importe : ces tests sont plus spécifiques que l'octet de
		 * classe, ils doivent primer. Chaque critère est celui de libfwsi, avec
		 * sa taille minimale — sans quoi la vérification lirait hors de l'item. */
		const unsigned short size = (unsigned short)item_size;

		/* Dossier délégué : marqueur de délégation 32 octets avant la fin. */
		static const unsigned char GUID_DELEGATION[16] = {
			0x74, 0x1a, 0x59, 0x5e, 0x96, 0xdf, 0xd3, 0x48,
			0x8d, 0x67, 0x17, 0x33, 0xbc, 0xee, 0x28, 0xba };
		if (size >= 38
		    && memcmp(buffer + size - 32, GUID_DELEGATION, 16) == 0) {
			log(3, L"🔈DelegateFolder");
			return std::make_unique<DelegateFolder>(buffer, size, _level);
		}
		// Graveur de CD : signature ASCII « AugM ».
		if (size >= 18 && memcmp(buffer + 4, "AugM", 4) == 0) {
			log(3, L"🔈CD Burn");
			return std::make_unique<TypedShellItem>(buffer, size, L"CD Burn", _level);
		}
		// Dossier de jeux : signature ASCII « GFSI ».
		if (size >= 32 && memcmp(buffer + 4, "GFSI", 4) == 0) {
			log(3, L"🔈Game Folder");
			return std::make_unique<TypedShellItem>(buffer, size, L"Game Folder", _level);
		}
		// Fichier .cpl du panneau de configuration : valeur de 4 octets precise.
		if (size >= 24
		    && *reinterpret_cast<unsigned int*>(buffer + 4) == 0xFFFFFF38UL) {
			log(3, L"🔈Control Panel CPL File");
			return std::make_unique<TypedShellItem>(buffer, size,
			                                        L"Control Panel CPL File", _level);
		}

		unsigned char type_char = *reinterpret_cast<unsigned char*>(buffer + 2);
		log(3, L"🔈shell_item_class");
		std::wstring type = shell_item_class(type_char);
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
		/* CRITÈRES FAIBLES, testés en DERNIER — l'ordre suit celui de libfwsi,
		   qui essaie `file_entry` avant `web_site`.
		   Celui du site web porte sur quatre octets à l'offset 4, or c'est là
		   qu'une entrée de fichier écrit sa TAILLE : un fichier de 0xC001B000
		   octets serait pris pour un site web si ce test venait d'abord. Celui
		   de l'archive Acronis lit l'octet de classe lui-même. Les deux ne sont
		   donc consultés que si aucun type de classe n'a répondu. */
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
	else {
		log(3, L"🔈ArchiveFileContent");
		return std::make_unique<ArchiveFileContent>(buffer, _level);
	}
	return nullptr;   // aucun type reconnu : jamais de retour implicite
}