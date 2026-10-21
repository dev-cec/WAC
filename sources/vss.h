/*! \file
 *  \brief Volume shadow copies read raw: the catalog and stores that the
 *         Volume Shadow Copy service keeps on an NTFS volume, and each copy
 *         rebuilt as the volume was when it was taken — without the service.
 *
 *  WHY RAW. A copy read through the service would make WAC call it, mount
 *  devices and leave its traces on the examined machine; the copies are data
 *  on the volume, which WAC reads raw like the rest (raw_hive.h).
 *
 *  THE FORMAT, from Joachim Metz's documentation of libvshadow and its
 *  sources (Vista and later; Windows XP keeps no persistent copy). At 0x1E00
 *  of the volume, a header gives the CATALOG: blocks of 16 KiB whose entries
 *  describe each copy (type 2: volume size, store identifier, creation time)
 *  and where its store lies (type 3). A STORE keeps the previous content of
 *  the 16 KiB blocks written after its copy was taken: a list of block
 *  descriptors (original block -> copy on the volume), with forwarders (the
 *  block is in a newer store), overlays (some 512-byte sectors only) and
 *  ignored entries, and two bitmaps of the blocks unused by the copy.
 *
 *  A copy is read by applying the stores from the most recent down to its
 *  own over the current volume: a block its store does not hold is read from
 *  the newer stores, then from the volume. The algorithm is libvshadow's,
 *  step for step, so that the two read the same bytes — libvshadow is the
 *  independent reference of the tests.
 *
 *  Portable C++ without windows.h: the volume is read through a callback,
 *  and the module is checked on an image of a real volume (vss_test).
 */
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

/*! Reads `size` bytes at `offset` of the current volume.
 *  @return false on a read error or a short read */
using VolumeReader = std::function<bool(uint64_t offset, uint8_t* out, size_t size)>;

//! What the catalog and the store header say of one shadow copy.
struct ShadowCopyInfo {
	std::array<uint8_t, 16> storeId{};     //!< the store's identifier, in its file name
	std::array<uint8_t, 16> copyId{};      //!< the shadow copy's identifier (vssadmin's "Shadow Copy ID")
	std::array<uint8_t, 16> copySetId{};   //!< the identifier of the set it was taken in
	uint64_t creationTime = 0;             //!< FILETIME, UTC
	uint64_t volumeSize = 0;               //!< bytes, as the catalog gives it
	uint32_t context = 0;                  //!< VSS_SNAPSHOT_CONTEXT
	uint32_t attributes = 0;               //!< VSS_VOLUME_SNAPSHOT_ATTRIBUTES
	std::wstring operatingMachine;         //!< the machine the copy was taken on
	std::wstring serviceMachine;           //!< the machine that served it
	uint64_t storedBlocks = 0;             //!< 16 KiB blocks whose earlier content the store holds
	bool hasStore = false;                 //!< a type 3 entry gave its store (not so on Server 2003)
	/*! Deleted, its store kept: the catalog entry carries flag 0x100. Windows
	 *  no longer lists it, but keeps its store while an older copy reads
	 *  through it (Vista, measured: the newest copy, deleted while an older
	 *  one read through its store, kept its entry flagged 0x140, where the
	 *  others had 0x40; under 8.1 the oldest copy, deleted, left the
	 *  catalog). Its store intact, it is read like the others. */
	bool deleted = false;
};

/*! The shadow copies of one volume, and the reading of each. */
class ShadowCopies {
public:
	//! The block size of the stores and of the catalog.
	static const uint64_t BLOCK = 0x4000;

	/*! Reads the volume header, the catalog and every store's header and
	 *  block descriptors.
	 *  @param read the current volume's reader
	 *  @param volumeSize the current volume's size in bytes: no offset read
	 *         from the data may go past it
	 *  @param diagnostic receives why the reading stopped, if it did
	 *  @return true if the volume holds a catalog that was read (zero copies
	 *          is a valid answer: "no catalog" is said by the diagnostic) */
	bool open(VolumeReader read, uint64_t volumeSize, std::wstring& diagnostic);

	/*! Reads the catalog again and, if the copies are the same, the most
	 *  recent store's block list — the only one Windows adds to while the
	 *  volume is written; any other change of the catalog (a copy created or
	 *  deleted) reads everything again.
	 *
	 *  WHY. On a running machine, a block written after the block lists were
	 *  read has had its earlier content copied to the most recent store by a
	 *  descriptor not known yet: read from the volume, it would give the
	 *  copy a block it never held. Refreshed before each file, the lists
	 *  know every block copied so far.
	 *  @param diagnostic receives why the reading stopped, if it did
	 *  @return false if the catalog or a store could not be read */
	bool refresh(std::wstring& diagnostic);

	//! The copies, oldest first.
	const std::vector<ShadowCopyInfo>& copies() const { return copies_; }

	/*! Reads the volume as copy `index` saw it.
	 *  @param index the copy, in the order of copies()
	 *  @param offset the offset on the volume
	 *  @param out receives `size` bytes
	 *  @param size the number of bytes
	 *  @return false on a read error, an index or a range out of bounds */
	bool read(size_t index, uint64_t offset, uint8_t* out, size_t size);

private:
	//! A block descriptor of a store, as the list gives it once merged.
	struct Descriptor {
		uint64_t original = 0;   //!< the block on the volume it describes
		uint64_t relative = 0;   //!< offset in the store; for a forwarder, the block in the next store
		uint64_t stored = 0;     //!< where the copy lies on the volume
		uint32_t flags = 0;
		uint32_t bitmap = 0;     //!< for an overlay, its 512-byte sectors (bit 0: the first)
		std::shared_ptr<Descriptor> overlay;   //!< the overlay applied to this block
	};
	using DescriptorPtr = std::shared_ptr<Descriptor>;

	//! One store: its block maps (by block index) and bitmaps.
	struct Store {
		uint64_t blockListOffset = 0, headerOffset = 0, bitmapOffset = 0, previousBitmapOffset = 0;
		std::map<uint64_t, DescriptorPtr> forward;   //!< by original block
		std::map<uint64_t, DescriptorPtr> reverse;   //!< forwarders, by the block they point to
		std::vector<uint8_t> unused;                 //!< current bitmap: bit set = block unused
		std::vector<uint8_t> previousUnused;         //!< previous bitmap, empty if none
	};

	bool readCatalog(std::wstring& diagnostic);
	bool readStores(std::wstring& diagnostic);
	bool readStore(size_t index, std::wstring& diagnostic);
	bool readStoreHeader(ShadowCopyInfo& info, const Store& store, std::wstring& diagnostic);
	bool readBlockList(Store& store, std::wstring& diagnostic);
	bool readBitmap(uint64_t offset, std::vector<uint8_t>& bits, std::wstring& diagnostic);
	void insert(Store& store, const Descriptor& d);
	bool readFromStore(size_t storeIndex, size_t active, uint64_t offset, uint8_t* out, size_t size);
	bool readBlock(uint64_t offset, std::vector<uint8_t>& block, uint32_t recordType, std::wstring& diagnostic);
	bool readVolume(uint64_t offset, uint8_t* out, size_t size);

	VolumeReader read_;
	uint64_t volumeSize_ = 0;
	std::vector<ShadowCopyInfo> copies_;
	std::vector<Store> stores_;   //!< in the order of copies_
};
