/*! \file
 *  \brief Volume shadow copies read raw: see vss.h.
 *
 *  Offsets and record types are those of libvshadow's documentation
 *  ("Volume Shadow Snapshot (VSS) format"); every offset read from the
 *  volume is checked against the volume's size before it is followed, and
 *  every chain of blocks against the blocks already visited.
 */
#include "vss.h"
#include "portable_conversions.h"
#include <algorithm>
#include <cstring>
#include <set>

namespace {

//! The VSS identifier {3808876b-c176-4e48-b7ae-04046e6cc752}, as stored.
const uint8_t VSS_IDENTIFIER[16] = { 0x6B, 0x87, 0x08, 0x38, 0x76, 0xC1, 0x48, 0x4E,
                                     0xB7, 0xAE, 0x04, 0x04, 0x6E, 0x6C, 0xC7, 0x52 };
const uint64_t VOLUME_HEADER_OFFSET = 0x1E00;
const size_t HEADER_SIZE = 128;    //!< a catalog or store block's header
const size_t CATALOG_ENTRY = 128;
const size_t BLOCK_DESCRIPTOR = 32;

// Record types of a block header.
const uint32_t RECORD_VOLUME_HEADER = 1, RECORD_CATALOG = 2, RECORD_BLOCK_LIST = 3, RECORD_STORE_HEADER = 4,
               RECORD_BITMAP = 6;

//! Catalog entry type 2: the copy was deleted, its store kept for the older ones.
const uint64_t DELETED = 0x100;

// Block descriptor flags.
const uint32_t FORWARDER = 0x1, OVERLAY = 0x2, NOT_USED = 0x4;

const size_t SECTOR = 512;   //!< an overlay's unit: one bit of its bitmap

//! Bit `index` of a bitmap whose bytes give their least significant bit first.
bool bitSet(const std::vector<uint8_t>& bits, uint64_t index) {
	return index / 8 < bits.size() && (bits[index / 8] >> (index % 8)) & 1;
}

std::wstring hex(uint64_t value) {
	static const wchar_t DIGITS[] = L"0123456789abcdef";
	std::wstring text;
	do { text.insert(text.begin(), DIGITS[value & 0xF]); value >>= 4; } while (value);
	return L"0x" + text;
}

} // namespace

bool ShadowCopies::readVolume(uint64_t offset, uint8_t* out, size_t size) {
	if (offset > volumeSize_ || size > volumeSize_ - offset) return false;
	return read_(offset, out, size);
}

/*! One 16 KiB block of the catalog or of a store, its header checked.
 *  @param offset the block's offset on the volume
 *  @param block receives the block
 *  @param recordType the record type its header must carry
 *  @param diagnostic receives why it was refused
 *  @return true if the block was read and carries the VSS identifier and that type */
bool ShadowCopies::readBlock(uint64_t offset, std::vector<uint8_t>& block, uint32_t recordType, std::wstring& diagnostic) {
	block.assign(BLOCK, 0);
	if (!readVolume(offset, block.data(), block.size())) {
		diagnostic = L"block at " + hex(offset) + L" unreadable or past the volume";
		return false;
	}
	if (std::memcmp(block.data(), VSS_IDENTIFIER, 16) != 0 || readLittleEndian<uint32_t>(block.data() + 20) != recordType) {
		diagnostic = L"block at " + hex(offset) + L" is not a VSS record of type " + std::to_wstring(recordType);
		return false;
	}
	return true;
}

bool ShadowCopies::open(VolumeReader read, uint64_t volumeSize, std::wstring& diagnostic) {
	read_ = std::move(read);
	volumeSize_ = volumeSize;
	return readCatalog(diagnostic) && readStores(diagnostic);
}

bool ShadowCopies::refresh(std::wstring& diagnostic) {
	std::vector<ShadowCopyInfo> before = std::move(copies_);
	std::vector<Store> beforeStores = std::move(stores_);
	if (!readCatalog(diagnostic)) return false;
	bool same = before.size() == copies_.size();
	for (size_t i = 0; same && i < before.size(); ++i) same = before[i].storeId == copies_[i].storeId;
	if (!same) return readStores(diagnostic);
	if (copies_.empty()) return true;
	// The same copies: the older stores as read before, the most recent read again.
	for (size_t i = 0; i + 1 < copies_.size(); ++i) {
		copies_[i] = before[i];
		stores_[i] = std::move(beforeStores[i]);
	}
	return readStore(copies_.size() - 1, diagnostic);
}

/*! Every store's header, block list and bitmaps. */
bool ShadowCopies::readStores(std::wstring& diagnostic) {
	for (size_t i = 0; i < copies_.size(); ++i)
		if (!readStore(i, diagnostic)) return false;
	// No copy: the catalog's reading said why (no header, no catalog).
	if (!copies_.empty()) diagnostic = std::to_wstring(copies_.size()) + L" shadow cop" + (copies_.size() == 1 ? L"y" : L"ies");
	return true;
}

/*! One store: its header, its block list merged afresh, its bitmaps. */
bool ShadowCopies::readStore(size_t index, std::wstring& diagnostic) {
	ShadowCopyInfo& info = copies_[index];
	Store& store = stores_[index];
	if (!info.hasStore) return true;
	store.forward.clear();
	store.reverse.clear();
	store.previousUnused.clear();
	if (!readStoreHeader(info, store, diagnostic) || !readBlockList(store, diagnostic)
	    || !readBitmap(store.bitmapOffset, store.unused, diagnostic)
	    || (store.previousBitmapOffset && !readBitmap(store.previousBitmapOffset, store.previousUnused, diagnostic)))
		return false;
	info.storedBlocks = 0;
	for (const auto& entry : store.forward)
		if (!(entry.second->flags & (FORWARDER | OVERLAY))) ++info.storedBlocks;
	return true;
}

/*! The volume header, then the catalog's chain of blocks: each copy (entry
 *  type 2) in the order of its creation, and where its store lies (type 3,
 *  matched by identifier). No header or no catalog: no copy, and said so. */
bool ShadowCopies::readCatalog(std::wstring& diagnostic) {
	copies_.clear();
	stores_.clear();
	uint8_t header[SECTOR];
	if (!readVolume(VOLUME_HEADER_OFFSET, header, sizeof header)) {
		diagnostic = L"volume header unreadable";
		return false;
	}
	if (std::memcmp(header, VSS_IDENTIFIER, 16) != 0 || readLittleEndian<uint32_t>(header + 20) != RECORD_VOLUME_HEADER) {
		diagnostic = L"no VSS header: the volume holds no shadow copy";
		return true;
	}
	const uint64_t catalogOffset = readLittleEndian<uint64_t>(header + 48);
	if (catalogOffset == 0) {
		diagnostic = L"no catalog: shadow copies enabled, none stored";
		return true;
	}
	std::set<uint64_t> visited;
	std::vector<uint8_t> block;
	size_t last = SIZE_MAX;   // the copy the previous type 2 entry described
	for (uint64_t offset = catalogOffset; offset != 0;) {
		if (!visited.insert(offset).second) { diagnostic = L"catalog chain loops at " + hex(offset); return false; }
		if (visited.size() > volumeSize_ / BLOCK) { diagnostic = L"catalog longer than the volume"; return false; }
		if (!readBlock(offset, block, RECORD_CATALOG, diagnostic)) return false;
		for (size_t at = HEADER_SIZE; at + CATALOG_ENTRY <= block.size(); at += CATALOG_ENTRY) {
			const uint8_t* e = block.data() + at;
			const uint64_t type = readLittleEndian<uint64_t>(e);
			std::array<uint8_t, 16> id;
			std::memcpy(id.data(), e + 16, 16);
			if (type == 2) {
				ShadowCopyInfo info;
				info.volumeSize = readLittleEndian<uint64_t>(e + 8);
				info.storeId = id;
				info.creationTime = readLittleEndian<uint64_t>(e + 48);
				info.deleted = (readLittleEndian<uint64_t>(e + 40) & DELETED) != 0;
				// Kept in order of creation, each store once (libvshadow: unique entries).
				auto same = std::find_if(copies_.begin(), copies_.end(), [&](const ShadowCopyInfo& c) { return c.storeId == id; });
				if (same != copies_.end()) { last = (size_t)(same - copies_.begin()); continue; }
				auto place = std::upper_bound(copies_.begin(), copies_.end(), info.creationTime,
				                              [](uint64_t t, const ShadowCopyInfo& c) { return t < c.creationTime; });
				last = (size_t)(place - copies_.begin());
				copies_.insert(place, info);
				stores_.insert(stores_.begin() + (std::ptrdiff_t)last, Store());
			} else if (type == 3) {
				size_t index = last;
				if (index >= copies_.size() || copies_[index].storeId != id) {
					auto match = std::find_if(copies_.begin(), copies_.end(), [&](const ShadowCopyInfo& c) { return c.storeId == id; });
					if (match == copies_.end()) continue;   // a store without its copy: nothing to read it as
					index = (size_t)(match - copies_.begin());
				}
				Store& s = stores_[index];
				s.blockListOffset = readLittleEndian<uint64_t>(e + 8);
				s.headerOffset = readLittleEndian<uint64_t>(e + 32);
				s.bitmapOffset = readLittleEndian<uint64_t>(e + 48);
				s.previousBitmapOffset = readLittleEndian<uint64_t>(e + 72);
				copies_[index].hasStore = true;
			}
		}
		offset = readLittleEndian<uint64_t>(block.data() + 40);
	}
	return true;
}

/*! The store information that follows the store header: the copy's and its
 *  set's identifiers, its context and attributes, and two machine names,
 *  each a 16-bit byte count then UTF-16 text, read within the block. */
bool ShadowCopies::readStoreHeader(ShadowCopyInfo& info, const Store& store, std::wstring& diagnostic) {
	std::vector<uint8_t> block;
	if (!readBlock(store.headerOffset, block, RECORD_STORE_HEADER, diagnostic)) return false;
	const uint8_t* s = block.data() + HEADER_SIZE;
	const size_t room = block.size() - HEADER_SIZE;
	std::memcpy(info.copyId.data(), s + 16, 16);
	std::memcpy(info.copySetId.data(), s + 32, 16);
	info.context = readLittleEndian<uint32_t>(s + 48);
	info.attributes = readLittleEndian<uint32_t>(s + 56);
	size_t at = 64;
	for (std::wstring* name : { &info.operatingMachine, &info.serviceMachine }) {
		const size_t bytes = readLittleEndian<uint16_t>(s, room, at);
		at += 2;
		if (bytes > room - std::min(at, room)) { diagnostic = L"store header at " + hex(store.headerOffset) + L": machine name past its block"; return false; }
		for (size_t i = 0; i + 1 < bytes; i += 2) name->push_back((wchar_t)readLittleEndian<uint16_t>(s + at + i));
		at += bytes;
	}
	return true;
}

/*! The store's block list, each descriptor merged into the store's maps as
 *  libvshadow does (see insert). */
bool ShadowCopies::readBlockList(Store& store, std::wstring& diagnostic) {
	std::set<uint64_t> visited;
	std::vector<uint8_t> block;
	for (uint64_t offset = store.blockListOffset; offset != 0;) {
		if (!visited.insert(offset).second) { diagnostic = L"block list loops at " + hex(offset); return false; }
		// More blocks than the volume has: no store describes that much.
		if (visited.size() > volumeSize_ / BLOCK) { diagnostic = L"block list longer than the volume"; return false; }
		if (!readBlock(offset, block, RECORD_BLOCK_LIST, diagnostic)) return false;
		static const uint8_t EMPTY[BLOCK_DESCRIPTOR] = {};
		for (size_t at = HEADER_SIZE; at + BLOCK_DESCRIPTOR <= block.size(); at += BLOCK_DESCRIPTOR) {
			const uint8_t* e = block.data() + at;
			if (std::memcmp(e, EMPTY, BLOCK_DESCRIPTOR) == 0) continue;   // an unused slot
			Descriptor d;
			d.original = readLittleEndian<uint64_t>(e);
			d.relative = readLittleEndian<uint64_t>(e + 8);
			d.stored = readLittleEndian<uint64_t>(e + 16);
			d.flags = readLittleEndian<uint32_t>(e + 24);
			d.bitmap = readLittleEndian<uint32_t>(e + 28);
			insert(store, d);
		}
		offset = readLittleEndian<uint64_t>(block.data() + 40);
	}
	return true;
}

/*! A bitmap's chain of blocks, their bits concatenated: bit n stands for the
 *  volume's n-th 16 KiB block, set when the copy did not use it. */
bool ShadowCopies::readBitmap(uint64_t offset, std::vector<uint8_t>& bits, std::wstring& diagnostic) {
	std::set<uint64_t> visited;
	std::vector<uint8_t> block;
	bits.clear();
	while (offset != 0) {
		if (!visited.insert(offset).second) { diagnostic = L"bitmap loops at " + hex(offset); return false; }
		// One bit per block of the volume, a block to spare: a longer chain is not a bitmap of it.
		if (bits.size() > volumeSize_ / BLOCK / 8 + BLOCK) { diagnostic = L"bitmap longer than the volume"; return false; }
		if (!readBlock(offset, block, RECORD_BITMAP, diagnostic)) return false;
		bits.insert(bits.end(), block.begin() + HEADER_SIZE, block.end());
		offset = readLittleEndian<uint64_t>(block.data() + 40);
	}
	return true;
}

/*! Merges one descriptor into a store's maps (libvshadow_block_tree_insert).
 *
 *  A forwarder says "this block is in the next store, at `relative`"; when a
 *  later descriptor describes that block, it takes the forwarder's original
 *  block and the forwarder leaves the reverse map. An overlay holds a few
 *  sectors of a block: it is attached to the block's descriptor, or extends
 *  the overlay already there. A later descriptor of the same block replaces
 *  the earlier one, keeping its overlay. */
void ShadowCopies::insert(Store& store, const Descriptor& d) {
	if (d.flags & NOT_USED) return;
	uint64_t original = d.original;
	if (!(d.flags & OVERLAY)) {
		auto reverse = store.reverse.find(d.original / BLOCK);
		if (reverse != store.reverse.end()) {
			original = reverse->second->original;
			store.reverse.erase(reverse);
		}
	}
	if ((d.flags & FORWARDER) && original == d.relative) return;   // a forwarder to itself
	DescriptorPtr added = std::make_shared<Descriptor>(d);
	added->original = original;
	DescriptorPtr& slot = store.forward[original / BLOCK];
	if (slot) {
		if (added->flags & OVERLAY) {
			DescriptorPtr overlay = (slot->flags & OVERLAY) ? slot : slot->overlay;
			if (overlay) overlay->bitmap |= added->bitmap;
			else slot->overlay = added;
			return;
		}
		if (slot->flags & OVERLAY) added->overlay = slot;
		else { added->overlay = slot->overlay; slot->overlay.reset(); }
	}
	slot = added;
	if (added->flags & FORWARDER) store.reverse[added->relative / BLOCK] = added;
}

bool ShadowCopies::read(size_t index, uint64_t offset, uint8_t* out, size_t size) {
	if (index >= copies_.size() || offset > volumeSize_ || size > volumeSize_ - offset) return false;
	return readFromStore(index, index, offset, out, size);
}

/*! Reads through store `storeIndex` for copy `active`
 *  (libvshadow_store_descriptor_read_buffer): a block the store describes is
 *  read where its descriptor says — in the next store for a forwarder —, any
 *  other from the next store, and from the current volume past the last. A
 *  block the most recent copy did not use reads as zeros, as libvshadow
 *  gives it (Windows' own reading leaves the buffer as it was). */
bool ShadowCopies::readFromStore(size_t storeIndex, size_t active, uint64_t offset, uint8_t* out, size_t size) {
	/* A copy without a store (Server 2003's catalog) has nothing to read
	   from. Each step goes to a newer store: the depth is bounded by their
	   number. */
	if (!copies_[storeIndex].hasStore) return false;
	const Store& store = stores_[storeIndex];
	const bool hasNext = storeIndex + 1 < stores_.size();
	while (size > 0) {
		const uint64_t within = offset % BLOCK;
		uint64_t span = BLOCK - within;
		const Descriptor* d = nullptr;
		uint64_t from = 0;
		auto found = store.forward.find(offset / BLOCK);
		if (found != store.forward.end()) {
			d = found->second.get();
			from = (d->flags & FORWARDER) ? d->relative : d->stored;
			const Descriptor* overlay = (d->flags & OVERLAY) ? d : d->overlay.get();
			if (overlay) {
				if (storeIndex != active) {
					if (d == overlay) d = nullptr;   // an overlay serves its own copy only
				} else {
					// The run of sectors, from this one, that the overlay holds or not.
					const uint64_t sector = within / SECTOR;
					const bool held = (overlay->bitmap >> sector) & 1;
					uint64_t run = sector;
					while (run < BLOCK / SECTOR && (((overlay->bitmap >> run) & 1) != 0) == held) ++run;
					span = run * SECTOR - within;
					if (held) { d = overlay; from = overlay->stored; }
					else if (d == overlay) d = nullptr;
				}
			}
			from += within;
		}
		const size_t chunk = (size_t)std::min<uint64_t>(span, size);
		bool ok;
		if (d) {
			ok = ((d->flags & FORWARDER) && hasNext) ? readFromStore(storeIndex + 1, active, from, out, chunk)
			                                         : readVolume(from, out, chunk);
		} else if (hasNext) {
			ok = readFromStore(storeIndex + 1, active, offset, out, chunk);
		} else {
			const uint64_t blockIndex = offset / BLOCK;
			const bool unused = storeIndex == active && store.reverse.find(blockIndex) == store.reverse.end()
			                    && bitSet(store.unused, blockIndex)
			                    && (store.previousBitmapOffset == 0 || bitSet(store.previousUnused, blockIndex));
			if (unused) { std::memset(out, 0, chunk); ok = true; }
			else ok = readVolume(offset, out, chunk);
		}
		if (!ok) return false;
		out += chunk;
		offset += chunk;
		size -= chunk;
	}
	return true;
}
