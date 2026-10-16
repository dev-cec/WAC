/*! \file
 *  \brief Offline reader of the WMI repository (CIM): `\Windows\System32\wbem\Repository`.
 *
 *  WHY OFFLINE. Querying WMI runs code on the examined machine and leaves its
 *  own traces; a subscription an intruder planted is precisely what a live
 *  query may be steered around. The repository's files, copied raw, say what
 *  WMI would load, without WMI.
 *
 *  THE FORMAT (Vista and later), described by FireEye's FLARE team
 *  ("WMI Offense, Defense, and Forensics", 2015; python-cim) and checked on
 *  the test VM against Get-CimInstance:
 *   - MAPPING1..3.MAP: the one with the highest version maps the logical
 *     pages (0x2000 bytes) of OBJECTS.DATA, then those of INDEX.BTR, to
 *     physical ones;
 *   - INDEX.BTR: a B-tree of keys, "NS_<hash>/CI_<hash>/IL_<hash>.<page>.<id>.<size>",
 *     each part a prefix and the SHA-256 of an upper-case UTF-16 name
 *     (namespace, class, instance); the last part locates the record;
 *   - OBJECTS.DATA: each page starts with a table (record id, offset, size,
 *     CRC); a record larger than its page continues on the next logical pages;
 *   - a class definition (CD_) gives its superclass, its properties (type,
 *     index, offset in the value table) and default values; an instance
 *     (CI_…/IL_) gives, for each property of its class and ancestors, two
 *     state bits, then a value table, then a heap of strings and arrays.
 *  Every length read in the files is bounded by the page or the record.
 *
 *  WINDOWS XP (python-cim's "XP" type, measured on the XP VMs): the names are
 *  hashed with MD5 (32 hexadecimal digits, an instance's class hash 0x40
 *  bytes); a mapping's header is 16 bytes (no two identifiers) and its
 *  entries 4 (the physical page alone); the index's root is in the header
 *  of the index's logical page 0. The files are in `Repository\\FS`: the
 *  mappings in MAPPING1..2.MAP (SP2 and later), or in OBJECTS.MAP and
 *  INDEX.MAP, the same two mappings in two files (SP1).
 */
#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "tools.h"

//! A property of a class, as its definition gives it.
struct CimProperty {
	std::wstring name;
	uint8_t type = 0;          //!< CIM type: 0x08 string, 0x13 uint32, 0x66 reference…
	bool array = false;
	uint16_t index = 0;        //!< its place in an instance's state bits
	uint32_t offset = 0;       //!< its value's offset in an instance's value table
};

//! A class definition (CD_ record).
struct CimClass {
	std::wstring name, superName;
	std::vector<CimProperty> properties;   //!< its own, not the inherited ones
	std::vector<uint8_t> defaults;         //!< default values: two state bits per property, then a value table
	std::vector<uint8_t> heap;             //!< strings and arrays the definition refers to
};

/*! Parses a class definition record.
 *  @param record the record
 *  @param out receives the class
 *  @return false if a length does not fit in the record */
bool parseCimClass(const std::vector<uint8_t>& record, CimClass& out);

//! An instance's values, by property name, in the class's order.
using CimValues = std::vector<std::pair<std::wstring, Json>>;

/*! Decodes an instance record. A property not set is left out; a property
 *  set to its default takes it from the class or the nearest ancestor that
 *  holds it.
 *  @param record the record
 *  @param chain the class and its ancestors, the root first
 *  @param out receives the values
 *  @return false if the record does not fit its class */
bool parseCimInstance(const std::vector<uint8_t>& record, const std::vector<const CimClass*>& chain, CimValues& out,
                      bool xp = false);

/*! The hash WMI files a name under: SHA-256 of the upper-case UTF-16 name,
 *  MD5 on Windows XP, in upper-case hexadecimal.
 *  @param name a namespace, class or instance name
 *  @param md5 Windows XP's repository
 *  @return the 64 (or 32) hexadecimal digits */
std::string cimNameHash(const std::wstring& name, bool md5 = false);

/*! The page mapping of one file: logical page → physical page. */
struct CimMapping {
	std::vector<uint32_t> physical;    //!< UNMAPPED when a logical page has none
	uint32_t indexRoot = 0;            //!< for the index: the logical page of the B-tree's root
	static const uint32_t UNMAPPED = 0x3FFFFFFF;
};

/*! Reads the two mappings of a MAPPING file: OBJECTS.DATA's, then INDEX.BTR's.
 *  @param file the file's bytes
 *  @param data receives OBJECTS.DATA's
 *  @param index receives INDEX.BTR's
 *  @return false if a signature is missing or a count exceeds the file */
bool parseCimMappings(const std::vector<uint8_t>& file, CimMapping& data, CimMapping& index, bool xp = false);

/*! A WMI repository, read from its copied files. */
class CimRepository {
public:
	/*! Opens the repository: the current mapping, the index's keys.
	 *  @param index INDEX.BTR
	 *  @param objects OBJECTS.DATA
	 *  @param mappings MAPPING1..3.MAP, those present
	 *  @param xp Windows XP's format (see the file's header)
	 *  @return ERROR_SUCCESS, or why the repository cannot be read */
	HRESULT open(const std::wstring& index, const std::wstring& objects, const std::vector<std::wstring>& mappings,
	             bool xp = false);

	/*! The same, from the mappings' contents already read — Windows XP SP1's
	 *  OBJECTS.MAP and INDEX.MAP joined into the one mapping file they make.
	 *  @return ERROR_SUCCESS, or why the repository cannot be read */
	HRESULT openMappings(const std::wstring& index, const std::wstring& objects,
	                     const std::vector<std::vector<uint8_t>>& mappings, bool xp);

	/*! @return every namespace, from root down (root\\subscription, root\\cimv2…) */
	std::vector<std::wstring> namespaces();

	/*! The class hashes that have instances in a namespace (the CI_ parts).
	 *  @param space the namespace
	 *  @return the hashes */
	std::vector<std::string> classHashesWithInstances(const std::wstring& space);

	/*! A class and its ancestors, the root first, found by the class's hash
	 *  in the namespace, then among the system classes.
	 *  @return empty if a definition is missing or unreadable */
	std::vector<const CimClass*> classChain(const std::wstring& space, const std::string& classHash);

	/*! The instances of a class in a namespace.
	 *  @param space the namespace
	 *  @param classHash the class's hash
	 *  @param chain its layout (classChain)
	 *  @return the values of each instance read */
	std::vector<CimValues> instances(const std::wstring& space, const std::string& classHash,
	                                 const std::vector<const CimClass*>& chain);

private:
	bool xp_ = false;   //!< Windows XP's format
	//! "NS_<hash>" of a namespace, hashed as the repository's version does.
	std::string namespacePart(const std::wstring& space) const;
	std::vector<std::string> keys(const std::string& prefix) const;
	bool object(const std::string& key, std::vector<uint8_t>& out);
	bool readPage(std::ifstream& file, uint64_t size, const CimMapping& mapping, uint32_t logical, std::vector<uint8_t>& page);
	void collectKeys(uint32_t logical, unsigned depth, std::vector<bool>& visited);
	const CimClass* definition(const std::wstring& space, const std::string& classHash);

	std::ifstream indexFile_, objectsFile_;
	uint64_t indexSize_ = 0, objectsSize_ = 0;
	CimMapping data_, index_;
	std::vector<std::string> keys_;                                  //!< every key of the index, sorted
	std::map<std::string, std::unique_ptr<CimClass>> classes_;       //!< by "namespace hash/class hash"
};
