/*! \file
 *  \brief Fingerprinting and collection of the files cited by artefacts.
 *
 *  WHY THIS MODULE. With `--binary`, WAC fingerprints every file an artefact
 *  points to: executable of a process, a service or a scheduled task, files
 *  loaded by a program (Prefetch), Shimcache and Amcache entries, a shortcut's
 *  target. These fingerprints used to be computed by OPENING each file through
 *  the API: the only file read WAC still made on the examined machine, and one
 *  that updates the last-access date where Windows maintains it. They are now
 *  computed by reading the volume raw: no file is opened.
 *
 *  COLLECTION. A fingerprint is enough to query a public database without
 *  sending it anything, but it says nothing about a binary nobody knows — the
 *  case that matters to the investigation — and a binary left behind may be
 *  gone by the time a detection comes in. The executables, libraries, drivers,
 *  scripts and Office documents able to carry macros that are cited are
 *  therefore COPIED into the exhibit store, with their three fingerprints, like
 *  any other exhibit. The other cited files (documents without macros, data)
 *  are only hashed: they are not payloads, and copying them would turn the
 *  collection into a copy of the user's documents.
 *
 *  AUTHENTIC MICROSOFT BINARIES. An executable whose Microsoft authenticity is
 *  verified — digest listed in a Windows catalog with a valid Microsoft
 *  signature, or valid embedded Microsoft signature — is hashed without being
 *  collected: identical on every machine of the same build, it does not serve
 *  the investigation. The check is done in memory, with no API or service (see
 *  authenticode.h), and the catalogs that justified it go into the exhibit
 *  store.
 *
 *  DEDUPLICATION. Identical content is stored only once: three identical copies
 *  of msedge.dll (Edge, EdgeCore, WebView2: 332 MB each) took 996 MB. The other
 *  paths are declared in the manifest as exhibits sharing that content (see
 *  ExhibitStoreAddDuplicate).
 *
 *  Since reading is raw, collecting costs NO more trace than hashing: only space
 *  on the collection medium. When space runs short, the file is hashed without
 *  being copied, and that is recorded.
 */
#pragma once
#include <windows.h>
#include <string>
#include "json.h"

/*! Fingerprints of a cited file, and what was done with it. */
struct BinaryFingerprint {
    std::wstring path;     //!< normalised path ("X:\…"), empty if undeterminable
    std::wstring md5;        //!< empty if the file could not be read
    std::wstring sha1;       //!< empty if the file could not be read
    std::wstring sha256;     //!< empty if the file could not be read
    /*! Authenticode SHA-256 of a PE: the digest the signature and the catalogs
     *  cover. The only digest of an authentic Microsoft binary that --collect
     *  fingerprinted without copying it (no MD5, SHA-1, SHA-256 then). */
    std::wstring authenticodeSha256;
    HRESULT result = E_FAIL;   //!< outcome of the raw read
    /*! Microsoft authenticity verified (Windows catalog or embedded signature):
     *  the binary is not collected. Empty otherwise. See authenticode.h. */
    std::wstring signature;
};

/*! Summary of the phase, for the investigation log. */
struct BinarySummary {
    size_t files = 0;                     //!< distinct cited files
    size_t read = 0;                          //!< read, hence fingerprinted
    size_t collectedCount = 0;                     //!< copied into the exhibit store
    size_t sansPlace = 0;                    //!< hashed only, medium full
    size_t duplicates = 0;                     //!< identical content already collected
    unsigned long long collectedBytes = 0;   //!< bytes written to the medium
    unsigned long long avoidedBytes = 0;     //!< bytes saved by the three rules above
    size_t authenticated = 0;                 //!< authentic Microsoft binaries, not collected
    size_t thirdPartyCleared = 0;             //!< third-party binaries cleared by their chain (trust set), not collected
    unsigned long long authenticatedBytes = 0;  //!< bytes saved by those two rules alone
    size_t catalogsRead = 0;                //!< CatRoot catalogs parsed
    size_t catalogsUsed = 0;           //!< among them, those that authenticated a file
};

/*! Fingerprints of the file an artefact points to.
 *
 *  The path is normalised by `normalizeFilePath`; a path that does not
 *  designate a determinable local file gives an empty result. Each file is read
 *  only ONCE for the whole collection, however many artefacts cite it.
 *
 *  Without `--binary`, returns an empty result without reading anything.
 */
const BinaryFingerprint& FingerprintFile(const std::wstring& rawPath);

/*! Adds the three fingerprints to a JSON object, under the keys
 *  `<prefix>Md5<suffix>`, `<prefix>Sha1<suffix>`, `<prefix>Sha256<suffix>`.
 *  A missing fingerprint is not emitted: an empty field would read as a
 *  software defect. */
void addFingerprints(Json& o, const BinaryFingerprint& e,
                       const std::wstring& prefix = L"", const std::wstring& suffix = L"");

/*! Summary, for the investigation log. */
BinarySummary BinariesSummary();

/*! --collect --binary: collects EVERY executable, library, driver, script
 *  and macro document of the system volume, and every signature catalog.
 *
 *  WHY ALL OF THEM. Which files the artefacts cite is only known once they
 *  are converted — on the analysis workstation, from the exhibit store. The
 *  collection must therefore take everything the conversion may ask for, and
 *  the catalogs that let it verify the Microsoft signatures there (see
 *  authenticode.h). Hard links (WinSxS) are read once, identical contents
 *  stored once. When the medium runs short, the walk stops and says so.
 *  @return ERROR_SUCCESS, S_FALSE if directories were unreadable,
 *          ERROR_DISK_FULL (as HRESULT) if the medium ran short */
HRESULT BinariesCollectAll();

/*! Stores in the exhibit store the signature catalogs that justified not
 *  collecting a file, then closes the volumes kept open. To be called once no
 *  artefact cites files any more, BEFORE the copy to the working directory and
 *  the sealing. */
void BinariesFinish();
