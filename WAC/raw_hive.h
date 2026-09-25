/*! \file
 *  \brief File extraction by raw NTFS reading (no VSS).
 *
 *  Opens the volume read-only (`\\.\C:`), parses the VBR and the $MFT, resolves a
 *  path through the directory indexes, then extracts the target file's $DATA
 *  attribute to an output file — WITHOUT going through the system's file
 *  opening (no lock, no VSS, no symlink, no write to the target).
 *
 *  Dependencies: Win32 (CreateFileW/ReadFile), and the fingerprinting and
 *  decompression modules (quickdigest5, sha, lznt1, xpress): fingerprints are
 *  computed while writing, so the copy is never read back from the collection
 *  medium. No third-party library, no link with the rest of WAC: the module
 *  stays testable on its own (raw_hive_test).
 *  Privileges: administrator required (raw volume access).
 */
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <utility>
#include <cstdint>
#include <memory>
#include <streambuf>

/*! Enables diagnostic messages on stderr (silent by default). */
void RawHiveSetVerbose(bool on);

/*! Checks then applies the fixups of an NTFS multi-sector record ($MFT
 *  record "FILE", index block "INDX").
 *
 *  WHY. NTFS writes such a record sector by sector. To detect a write cut in
 *  the middle, it replaces the last two bytes of every 512-byte stride with an
 *  update sequence number, and keeps the real bytes in the update sequence
 *  array. A stride that does not end with that number was not written with the
 *  others: the record is TORN, a mix of two versions. Applying the fixups
 *  without checking them, as WAC used to, silently turned such a record into
 *  plausible data.
 *
 *  The stride is always 512 bytes, whatever the sector size the volume
 *  declares (as Linux's ntfs3 driver does): on a 4K-native disk, using the
 *  sector size would read the wrong bytes.
 *
 *  Nothing is modified unless the whole record checks out.
 *  @param record the record, as read from the volume
 *  @param size its size (a multiple of 512)
 *  @return true if the array is well formed and every stride ends with the
 *          update sequence number; false otherwise (record left as it is) */
bool applyNtfsFixup(uint8_t* record, size_t size);

/*! Signature of a progress reporter.
 *  @param item  what is being extracted (path on the volume)
 *  @param done  bytes already written
 *  @param total bytes expected
 */
using RawHiveProgressFn = void (*)(const wchar_t* item, unsigned long long done,
                                   unsigned long long total);

/*! Installs a progress reporter, called during extraction.
 *
 *  Passed as a callback rather than calling the display directly: this module
 *  depends only on Win32, which keeps it testable on its own (raw_hive_test).
 *  Passing nullptr disables reporting.
 */
void RawHiveSetProgress(RawHiveProgressFn fn);

/*! Extracts a file from the volume by raw NTFS reading.
 *  @param volumeLetter   volume letter, e.g. L"C"
 *  @param filePathOnVolume path relative to the volume, e.g.
 *         L"\\Windows\\System32\\config\\SYSTEM"
 *  @param outFile        local output path (overwritten if it exists)
 *  @return ERROR_SUCCESS, or a Win32/application error code
 */
HRESULT ExtractFileRaw(const std::wstring& volumeLetter,
                       const std::wstring& filePathOnVolume,
                       const std::wstring& outFile);

/*! What is recorded about a file when it is extracted.
 *
 *  Everything is gathered DURING extraction, on the bytes already passing
 *  through memory: reading the copy back from the collection medium took
 *  almost half the extraction time on a USB stick, and a re-read does not
 *  prove what was read from the volume — only what is in the copy.
 *
 *  THREE FINGERPRINTS, not one. MD5 is no longer enough to identify an exhibit
 *  beyond dispute (collisions producible at will since 2008), nor is SHA-1
 *  since 2017; SHA-256 remains undisputed. The three together settle it.
 *
 *  The timestamps and the $MFT record number describe the SOURCE file: they
 *  identify the exhibit on the volume independently of its name, and attest
 *  that the raw reading changed no date on the target.
 */
struct RawHiveFingerprints {
    std::wstring md5;            //!< MD5 fingerprint, uppercase hexadecimal
    std::wstring sha1;           //!< SHA-1 fingerprint
    std::wstring sha256;         //!< SHA-256 fingerprint
    uint64_t bytes = 0;         //!< size actually extracted
    uint64_t declaredSize = 0; //!< size declared by the $DATA attribute
    /*! Valid data length of the non-resident attribute. Beyond it, the content is
     *  zero by definition and is NOT read from the disk. Equal to `declaredSize`
     *  for an ordinary file; smaller for a preallocated file (event logs). */
    uint64_t validDataLength = 0;
    uint64_t mftEntry = 0;       //!< record number in the $MFT
    bool     resident = false;   //!< data held inside the $MFT record
    // $STANDARD_INFORMATION of the source file, as FILETIME (UTC, 0 if absent).
    uint64_t creeUtc = 0;        //!< creation date
    uint64_t modifiedUtc = 0;     //!< last content change
    uint64_t mftModifiedUtc = 0;  //!< last record change
    uint64_t accedeUtc = 0;      //!< last access
    uint64_t extractedUtc = 0;     //!< when THIS exhibit was extracted (FILETIME UTC)
    /*! The four timestamps of the $FILE_NAME attribute of the name read (UTC,
     *  0 if absent). Updated by NTFS itself, not by SetFileTime: an earlier
     *  $STANDARD_INFORMATION reveals forged timestamps (timestomping). */
    uint64_t fnCreatedUtc = 0, fnModifiedUtc = 0, fnMftModifiedUtc = 0, fnAccessedUtc = 0;
    /*! INPUT, set before the read: false to skip MD5, SHA-1 and SHA-256 when
     *  only the content is needed (authenticating an executable, whose
     *  Authenticode digest the caller computes itself). */
    bool computeHashes = true;
    //! Authenticode digests of a PE (hexadecimal), when the caller computed them.
    std::wstring authenticodeSha1, authenticodeSha256;
    /*! TimeDateStamp and SizeOfImage of a PE's headers, when the caller read
     *  them (0 otherwise): the key under which Microsoft's symbol server keeps
     *  every build of its binaries (see PeAnalyser::timeDateStamp). */
    uint32_t peTimeDateStamp = 0, peSizeOfImage = 0;
};

/*! An extracted file, as it will be recorded in the manifest. */
struct RawHiveExtraction {
    std::wstring volumePath;   //!< path on the source volume
    std::wstring outputPath;   //!< file written to the collection medium
    HRESULT      result = E_FAIL;   //!< outcome of the extraction
    RawHiveFingerprints fingerprints;     //!< empty if the extraction failed
};

/*! Extracts several files with a SINGLE opening of the volume (efficient).
 *  @param volumeLetter letter of the volume to read, without the colon (e.g. L"C")
 *  @param items  pairs {path on the volume, output file}
 *  @param perItem (optional) receives the HRESULT of each item, in order
 *  @param reading (optional) receives a record per item, fingerprints included.
 *         It is the source of the exhibit store manifest: without it, an
 *         exhibit is copied with nothing to identify it.
 *  @return S_OK if everything succeeds, S_FALSE if at least one item fails,
 *          or an error code if the volume cannot be opened.
 */
HRESULT ExtractFilesRaw(const std::wstring& volumeLetter,
                        const std::vector<std::pair<std::wstring, std::wstring>>& items,
                        std::vector<HRESULT>* perItem = nullptr,
                        std::vector<RawHiveExtraction>* reading = nullptr);

/*! PERSISTENT raw reader, to read thousands of scattered files.
 *
 *  `ExtractFilesRaw` opens the volume, bootstraps the $MFT and walks every
 *  directory from the root again on each call. For the binaries cited by the
 *  artefacts (several thousand, scattered), that would mean as many volume
 *  openings — the only WAC operation object-access auditing can log — and as
 *  many re-reads of System32's 4,659 entries.
 *  The RawReader keeps each volume open ONCE for its whole lifetime, and
 *  caches the index of the directories it walks.
 */
struct RawDirEntry;

/*! Where the files a conversion needs are read from: the examined volume
 *  itself (RawReader, collection on the machine), or the exhibit store of a
 *  collection made earlier (ExhibitReader, --convert on an analysis
 *  workstation). The consumers — cited binaries, signature catalogs — read
 *  through this interface and do not know which one serves them. */
class FileSource {
public:
    virtual ~FileSource() = default;

    /*! Reads a file by its absolute path on the examined machine.
     *  @param absolutePath the file, as "`X:\\…`"
     *  @param output file to write; EMPTY to compute the fingerprints only
     *  @param line  receives the record, fingerprints included
     *  @param observer receives the content as it is read — written to
     *         `output` as well, if one is given (one read for both)
     *  @return the result, also carried by `line.result` */
    virtual HRESULT read(const std::wstring& absolutePath, const std::wstring& output,
                         RawHiveExtraction& line, std::streambuf* observer = nullptr) = 0;

    /*! Lists a directory by its absolute path on the examined machine.
     *  @param absoluteFolder the directory ("X:\\…")
     *  @param entries receives its entries
     *  @return the result of the listing */
    virtual HRESULT list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) = 0;
};

/*! Persistent raw reader: reads files and lists directories on NTFS volumes
 *  kept open for the reader's whole lifetime.
 *
 *  Not copyable: it owns one handle per volume and the directory index cache. */
class RawReader : public FileSource {
public:
    RawReader();
    ~RawReader();
    RawReader(const RawReader&) = delete;
    RawReader& operator=(const RawReader&) = delete;

    /*! Reads a file by its absolute path.
     *  @param absolutePath the file, as "`X:\\…`"
     *  @param output file to write; EMPTY to compute the fingerprints only —
     *         nothing is then written anywhere
     *  @param observer receives the content as it is read (PE analysis,
     *         reading a catalog into memory), whether written to `output` or not
     *  @param line  receives the record, fingerprints and timestamps included
     *  @return the result, also carried by `line.result` */
    HRESULT read(const std::wstring& absolutePath, const std::wstring& output,
                 RawHiveExtraction& line, std::streambuf* observer = nullptr) override;

    /*! Lists a directory by its absolute path, on the volume already open.
     *  @param absoluteFolder the directory ("X:\\…")
     *  @param entries receives its entries
     *  @return the result of the listing */
    HRESULT list(const std::wstring& absoluteFolder, std::vector<RawDirEntry>& entries) override;

    //! @return the number of volumes actually opened (one handle each).
    unsigned openVolumes() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/*! An attribute of a $MFT record, as written on the disk. */
struct RawAttribute {
    uint32_t type = 0;          //!< 0x10 $STANDARD_INFORMATION, 0x80 $DATA, 0xC0 $REPARSE_POINT…
    std::wstring name;           //!< attribute name, empty for the unnamed attribute
    bool     resident = true;   //!< held inside the record
    uint64_t actualSize = 0;  //!< data size
    /*! Non-resident only: VALID data length. Beyond it, NTFS returns zeros,
     *  whatever the clusters hold — they may carry remnants of former files. */
    uint64_t initializedSize = 0;
    uint16_t flags = 0;      //!< 0x0001 compressed, 0x4000 encrypted, 0x8000 sparse
    uint32_t tagReparse = 0;    //!< for 0xC0: the reparse point's tag
    std::vector<uint8_t> preview; //!< first bytes of the content, if resident
};

/*! Writes the compressed stream of a WOF ("Compact OS") file as it lies on
 *  the disk: the test data of the decompressors, compressed by Windows itself
 *  (raw_hive_test --wof, lzx_test).
 *  @param volumeLetter volume letter, e.g. L"C"
 *  @param pathOnVolume path of the file on that volume
 *  @param outFile where to write the stream
 *  @param algorithm (optional) receives the WOF algorithm: 0, 2, 3 XPRESS on
 *         4, 8, 16 KiB chunks, 1 LZX on 32 KiB
 *  @return S_OK, or an error code (ERROR_NOT_SUPPORTED if the file is not WOF) */
HRESULT ExtractWofStreamRaw(const std::wstring& volumeLetter, const std::wstring& pathOnVolume,
                            const std::wstring& outFile, uint32_t* algorithm = nullptr);

/*! Lists a file's attributes, as they appear in the $MFT.
 *
 *  WHY THIS FUNCTION EXISTS. What the Windows API shows of a file and what the
 *  disk holds can differ radically: a "Compact OS" binary looks like an
 *  ordinary file — normal attributes, a single stream — whereas it actually
 *  carries a reparse point, a sparse `$DATA` and a named stream holding
 *  everything. The system's filter hides this structure from any ordinary
 *  query. Without a direct look at the $MFT, a file extracted entirely as zeros
 *  remains unexplainable.
 *
 *  @param volumeLetter volume letter, e.g. L"C"
 *  @param pathOnVolume path of the file on that volume
 *  @param out receives the attributes found (cleared first)
 *  @return ERROR_SUCCESS, or an error code
 */
HRESULT ListAttributesRaw(const std::wstring& volumeLetter,
                          const std::wstring& pathOnVolume,
                          std::vector<RawAttribute>& out);

/*! A directory entry read from the NTFS index. */
struct RawDirEntry {
    std::wstring name;          //!< name of the file or directory (without a path)
    uint64_t mftIndex = 0;      //!< index of its record in the $MFT
    uint64_t size = 0;          //!< real size in bytes (0 for a directory)
    bool isDirectory = false;   //!< true if the entry is a directory
};

/*! Lists a directory's content by raw NTFS reading.
 *  8.3 short names are discarded: NTFS often records two entries for one file
 *  (DOS and Win32 namespaces), which would produce duplicates.
 *  @param volumeLetter volume letter, e.g. L"C"
 *  @param dirPathOnVolume path of the directory, e.g. L"\\Windows\\Prefetch"
 *  @param out receives the entries found (cleared first)
 *  @return ERROR_SUCCESS, or a Win32/application error code
 */
HRESULT ListDirectoryRaw(const std::wstring& volumeLetter,
                         const std::wstring& dirPathOnVolume,
                         std::vector<RawDirEntry>& out);

/*! Extracts the files of a directory by raw NTFS reading.
 *
 *  A missing directory is NOT an error: it is the nominal case during a
 *  collection (not every profile has every folder). It then yields 0 files.
 *
 *  @param volumeLetter volume letter, e.g. L"C"
 *  @param dirPathOnVolume path of the directory on the volume
 *  @param outDir local output directory (created if missing)
 *  @param extensions extensions to keep, dot included, case-insensitive
 *         (e.g. { L".pf" }); empty list = every file
 *  @param extracted (optional) receives the number of files actually extracted
 *  @param diagnostic (optional) receives a readable state of the listing:
 *         "absent", "empty", "N entries, M kept". Without it, a count of 0 does
 *         not say whether the directory is missing, empty, or whether the
 *         extension filter discarded everything — three very different causes.
 *  @param reading (optional) receives a record per file, fingerprints included,
 *         also for files whose extraction failed: it is the source of the
 *         exhibit store manifest
 *  @return ERROR_SUCCESS if the directory could be listed (even empty),
 *          S_FALSE if at least one file could not be extracted,
 *          an error code if the volume is inaccessible
 */
HRESULT ExtractDirectoryRaw(const std::wstring& volumeLetter,
                            const std::wstring& dirPathOnVolume,
                            const std::wstring& outDir,
                            const std::vector<std::wstring>& extensions = {},
                            size_t* extracted = nullptr,
                            std::wstring* diagnostic = nullptr,
                            std::vector<RawHiveExtraction>* reading = nullptr);

/*! Like ExtractDirectoryRaw, but descends into subdirectories.
 *
 *  Needed for `\\Windows\\System32\\Tasks\`, which is a tree: scheduled tasks
 *  are filed there by folder (Microsoft\\Windows\...), and the relative path
 *  is part of the task's identity. The tree is reproduced as is in `outDir`.
 *
 *  @param volumeLetter letter of the volume to read, without the colon (e.g. L"C")
 *  @param dirPathOnVolume path of the directory on the volume
 *  @param outDir destination directory; the tree is reproduced there
 *  @param extensions extensions to extract (empty = all)
 *  @param extracted receives the number of files extracted
 *  @param maxDepth guard against a cyclic or abnormal tree (a corrupt
 *         NTFS index could loop); 0 = no descent
 *  @param reading (optional) receives a record per file, fingerprints included:
 *         it is the source of the exhibit store manifest
 *  @return ERROR_SUCCESS if the listing succeeded (even without files),
 *          S_FALSE if at least one file failed,
 *          an error code if the volume is inaccessible
 */
HRESULT ExtractDirectoryTreeRaw(const std::wstring& volumeLetter,
                                const std::wstring& dirPathOnVolume,
                                const std::wstring& outDir,
                                const std::vector<std::wstring>& extensions = {},
                                size_t* extracted = nullptr,
                                unsigned maxDepth = 8,
                                std::vector<RawHiveExtraction>* reading = nullptr);
