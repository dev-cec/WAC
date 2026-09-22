/*  binaires.h — fingerprinting and collection of the files cited by artefacts.
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
 *  ConsigneAjouterDoublon).
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
struct EmpreinteBinaire {
    std::wstring chemin;     //!< normalised path ("X:\…"), empty if undeterminable
    std::wstring md5;        //!< empty if the file could not be read
    std::wstring sha1;
    std::wstring sha256;
    HRESULT resultat = E_FAIL;
    bool preleve = false;    //!< copied into the exhibit store
    /*! Microsoft authenticity verified (Windows catalog or embedded signature):
     *  the binary is not collected. Empty otherwise. See authenticode.h. */
    std::wstring signature;
};

/*! Summary of the phase, for the investigation log. */
struct BilanBinaires {
    size_t fichiers = 0, lus = 0, preleves = 0, sansPlace = 0, doublons = 0;
    unsigned long long octetsPreleves = 0, octetsEvites = 0;
    size_t authentifies = 0;                 //!< authentic Microsoft binaries, not collected
    unsigned long long octetsAuthentifies = 0;
    size_t cataloguesLus = 0, cataloguesUtilises = 0;
};

/*! Fingerprints of the file an artefact points to.
 *
 *  The path is normalised by `normaliserCheminFichier`; a path that does not
 *  designate a determinable local file gives an empty result. Each file is read
 *  only ONCE for the whole collection, however many artefacts cite it.
 *
 *  Without `--binary`, returns an empty result without reading anything.
 */
const EmpreinteBinaire& EmpreinteFichier(const std::wstring& cheminBrut);

/*! Adds the three fingerprints to a JSON object, under the keys
 *  `<prefixe>Md5<suffixe>`, `<prefixe>Sha1<suffixe>`, `<prefixe>Sha256<suffixe>`.
 *  A missing fingerprint is not emitted: an empty field would read as a
 *  software defect. */
void ajouterEmpreintes(Json& o, const EmpreinteBinaire& e,
                       const std::wstring& prefixe = L"", const std::wstring& suffixe = L"");

/*! Summary, for the investigation log. */
BilanBinaires BinairesBilan();

/*! Stores in the exhibit store the signature catalogs that justified not
 *  collecting a file, then closes the volumes kept open. To be called once no
 *  artefact cites files any more, BEFORE the copy to the working directory and
 *  the sealing. */
void BinairesTerminer();
