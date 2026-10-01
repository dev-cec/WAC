/*! \file
 *  \brief NTFS security descriptors (see security_descriptors.h).
 */
#include "security_descriptors.h"
#include "consigne.h"
#include "running_machine.h"
#include <fstream>
#include <algorithm>
#include <set>

namespace {

const size_t SDS_BLOCK = 0x40000;        //!< 256 KiB: a block of $SDS, then its mirror
const size_t SDS_ENTRY_HEADER = 20;      //!< hash, SecurityId, offset, length
const size_t SDS_ALIGNMENT = 16;         //!< entries start on 16 bytes

//! @return the start of the block after the one holding `at`
size_t nextBlock(size_t at) { return (at / SDS_BLOCK + 1) * SDS_BLOCK; }

} // namespace

uint32_t securityDescriptorHash(const uint8_t* data, size_t size) {
	uint32_t hash = 0;
	for (size_t at = 0; at + 4 <= size; at += 4)
		hash = readLittleEndian<uint32_t>(data + at) + ((hash << 3) | (hash >> 29));
	return hash;
}

std::vector<SecurityDescriptorEntry> parseSds(const uint8_t* data, size_t size, const std::wstring& volume) {
	std::vector<SecurityDescriptorEntry> entries;
	std::set<uint32_t> seen;
	size_t at = 0;
	while (at < size && size - at >= SDS_ENTRY_HEADER) {
		if ((at / SDS_BLOCK) % 2 == 1) { at = nextBlock(at); continue; }   // a mirror block
		const size_t blockEnd = std::min(size, nextBlock(at));
		const uint32_t hash = readLittleEndian<uint32_t>(data + at);
		const uint32_t securityId = readLittleEndian<uint32_t>(data + at + 4);
		const uint64_t recordedOffset = readLittleEndian<uint64_t>(data + at + 8);
		const uint32_t length = readLittleEndian<uint32_t>(data + at + 16);
		// The end of the block's entries: zeros, or an entry that lies about itself.
		if (length <= SDS_ENTRY_HEADER || recordedOffset != at || length > blockEnd - at) {
			at = nextBlock(at);
			continue;
		}
		if (securityId != 0 && seen.insert(securityId).second) {
			SecurityDescriptorEntry e;
			e.volume = volume;
			e.securityId = securityId;
			e.hash = hash;
			e.descriptor.assign(data + at + SDS_ENTRY_HEADER, data + at + length);
			e.hashMatches = securityDescriptorHash(e.descriptor.data(), e.descriptor.size()) == hash;
			if (!e.hashMatches)
				log(2, L"🔥$SDS: descriptor " + std::to_wstring(securityId) + L" does not match its hash");
			entries.push_back(std::move(e));
		}
		at += (length + SDS_ALIGNMENT - 1) / SDS_ALIGNMENT * SDS_ALIGNMENT;
	}
	return entries;
}

Json SecurityDescriptorEntry::toJson() const {
	Json o = Json::obj();
	o.add(L"Volume", Json::str(volume));
	o.add(L"SecurityId", Json::num((unsigned long long)securityId));
	if (!hashMatches) o.add(L"HashMismatch", Json::boolean(true));
	o.merge(securityDescriptorToJson(descriptor.data(), descriptor.size()));
	return o;
}

HRESULT SecurityDescriptors::getData() {
	log(0, L"ℹ️Security descriptors ($Secure:$SDS) :");
	const auto& index = ExhibitStoreIndex();
	HRESULT result = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
	for (const std::wstring& drive : fixedNtfsVolumes()) {
		const std::wstring volume = drive.substr(0, 2);
		const auto found = index.find(toLower(volume + L"\\$Secure:$SDS"));
		if (found == index.end() || found->second.file.empty()) {
			log(2, L"🔥$SDS not collected for " + volume);
			continue;
		}
		std::ifstream in(std::filesystem::path(found->second.file), std::ios::binary);
		const std::vector<uint8_t> stream((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		std::vector<SecurityDescriptorEntry> entries = parseSds(stream.data(), stream.size(), volume);
		log(2, L"❇️" + volume + L" : " + std::to_wstring(entries.size()) + L" descriptor(s)");
		for (SecurityDescriptorEntry& e : entries) entries_.push_back(std::move(e));
		result = ERROR_SUCCESS;
	}
	return result;
}

HRESULT SecurityDescriptors::toJson() {
	Json list = Json::arr();
	for (const SecurityDescriptorEntry& e : entries_) list.push(e.toJson());
	return writeJsonFile("security_descriptors.json", list);
}

void SecurityDescriptors::clear() {
	entries_.clear();
}
