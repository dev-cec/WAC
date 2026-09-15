/*  raw_hive.h — Extraction de fichiers par lecture brute NTFS (sans VSS).
 *
 *  Ouvre le volume en lecture seule (\\.\C:), parse le VBR + $MFT, résout un
 *  chemin via les index de répertoires, puis extrait l'attribut $DATA du fichier
 *  cible vers un fichier de sortie — SANS passer par l'ouverture de fichier du
 *  système (pas de verrou, pas de VSS, pas de symlink, aucune écriture sur la
 *  cible). Voir docs/MIGRATION-VSS-vers-lecture-brute.md.
 *
 *  Dépendances : Win32 (CreateFileW/ReadFile) et quickdigest5 (empreinte MD5
 *  calculée au fil de l'écriture, pour ne pas relire la copie depuis le support
 *  de collecte). Aucune bibliothèque tierce, aucun lien avec le reste de WAC :
 *  le module reste testable isolément (raw_hive_test).
 *  Privilèges : administrateur requis (accès volume brut).
 */
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <utility>

/*! Active des messages de diagnostic sur stderr (par défaut : silencieux). */
void RawHiveSetVerbose(bool on);

/*! Signature d'un rapporteur de progression.
 *  @param item  ce qui est en cours d'extraction (chemin sur le volume)
 *  @param fait  octets déjà écrits
 *  @param total octets attendus
 */
using RawHiveProgressFn = void (*)(const wchar_t* item, unsigned long long fait,
                                   unsigned long long total);

/*! Installe un rapporteur de progression, appelé pendant l'extraction.
 *
 *  Passé par callback plutôt qu'en appelant directement l'affichage : ce module
 *  ne dépend que de Win32, ce qui le garde testable isolément (raw_hive_test).
 *  Passer nullptr désactive le rapport.
 */
void RawHiveSetProgress(RawHiveProgressFn fn);

/*! Extrait un fichier du volume par lecture brute NTFS.
 *  @param volumeLetter   lettre du volume, ex. L"C"
 *  @param filePathOnVolume chemin relatif au volume, ex.
 *         L"\\Windows\\System32\\config\\SYSTEM"
 *  @param outFile        chemin de sortie local (écrasé s'il existe)
 *  @return ERROR_SUCCESS, ou un code d'erreur Win32/applicatif
 */
HRESULT ExtractFileRaw(const std::wstring& volumeLetter,
                       const std::wstring& filePathOnVolume,
                       const std::wstring& outFile);

/*! Extrait plusieurs fichiers en UNE seule ouverture de volume (efficace).
 *  @param items  paires {chemin sur volume, fichier de sortie}
 *  @param perItem (optionnel) reçoit le HRESULT de chaque item, dans l'ordre
 *  @param md5PerItem (optionnel) reçoit l'empreinte MD5 de chaque item, calculée
 *         PENDANT l'écriture. Évite de relire la copie depuis le support de
 *         collecte — sur clé USB, cette relecture coûtait près de la moitié du
 *         temps d'extraction. Empreinte vide si l'item a échoué.
 *  @return S_OK si tout réussit, S_FALSE si au moins un item échoue,
 *          ou un code d'erreur si l'ouverture du volume échoue.
 * @param volumeLetter lettre du volume a lire, sans les deux-points (ex. L"C")
*/
HRESULT ExtractFilesRaw(const std::wstring& volumeLetter,
                        const std::vector<std::pair<std::wstring, std::wstring>>& items,
                        std::vector<HRESULT>* perItem = nullptr,
                        std::vector<std::wstring>* md5PerItem = nullptr);

/*! Une entrée de répertoire lue dans l'index NTFS. */
struct RawDirEntry {
    std::wstring name;          //!< nom du fichier ou du répertoire (sans chemin)
    uint64_t mftIndex = 0;      //!< index de son enregistrement dans la $MFT
    uint64_t size = 0;          //!< taille réelle en octets (0 pour un répertoire)
    bool isDirectory = false;   //!< vrai si l'entrée est un répertoire
};

/*! Énumère le contenu d'un répertoire par lecture brute NTFS.
 *  Les noms courts 8.3 sont écartés : NTFS enregistre souvent deux entrées pour
 *  un même fichier (espace de noms DOS et Win32), ce qui produirait des doublons.
 *  @param volumeLetter lettre du volume, ex. L"C"
 *  @param dirPathOnVolume chemin du répertoire, ex. L"\\Windows\\Prefetch"
 *  @param out reçoit les entrées trouvées (vidé au préalable)
 *  @return ERROR_SUCCESS, ou un code d'erreur Win32/applicatif
 */
HRESULT ListDirectoryRaw(const std::wstring& volumeLetter,
                         const std::wstring& dirPathOnVolume,
                         std::vector<RawDirEntry>& out);

/*! Extrait les fichiers d'un répertoire par lecture brute NTFS.
 *
 *  Un répertoire absent n'est PAS une erreur : c'est le cas nominal en collecte
 *  (tous les profils n'ont pas tous les dossiers). Il rend alors 0 fichier.
 *
 *  @param volumeLetter lettre du volume, ex. L"C"
 *  @param dirPathOnVolume chemin du répertoire sur le volume
 *  @param outDir répertoire de sortie local (créé si absent)
 *  @param extensions extensions à retenir, point compris et casse indifférente
 *         (ex. { L".pf" }) ; liste vide = tous les fichiers
 *  @param extracted (optionnel) reçoit le nombre de fichiers effectivement extraits
 *  @param diagnostic (optionnel) reçoit un état lisible de l'énumération :
 *         « absent », « vide », « N entrée(s), M retenue(s) ». Sans lui, un
 *         décompte à 0 ne dit pas si le répertoire manque, s'il est vide, ou si
 *         le filtre d'extension a tout écarté — trois causes très différentes.
 *  @return ERROR_SUCCESS si le répertoire a pu être énuméré (même vide),
 *          S_FALSE si au moins un fichier n'a pas pu être extrait,
 *          un code d'erreur si le volume est inaccessible
 */
HRESULT ExtractDirectoryRaw(const std::wstring& volumeLetter,
                            const std::wstring& dirPathOnVolume,
                            const std::wstring& outDir,
                            const std::vector<std::wstring>& extensions = {},
                            size_t* extracted = nullptr,
                            std::wstring* diagnostic = nullptr);

/*! Comme ExtractDirectoryRaw, mais descend dans les sous-répertoires.
 *
 *  Nécessaire pour `\\Windows\\System32\\Tasks\`, qui est une arborescence : les
 *  tâches planifiées y sont rangées par dossier (Microsoft\\Windows\...), et le
 *  chemin relatif fait partie de l'identité de la tâche. L'arborescence est
 *  reproduite à l'identique dans `outDir`.
 *
 *  @param volumeLetter lettre du volume à lire, sans les deux-points (ex. L"C")
 *  @param dirPathOnVolume chemin du répertoire sur le volume
 *  @param outDir répertoire de destination ; l'arborescence y est reproduite
 *  @param extensions extensions à extraire (vide = toutes)
 *  @param extracted reçoit le nombre de fichiers extraits
 *  @param profondeurMax garde-fou contre une arborescence cyclique ou anormale
 *         (un index NTFS corrompu pourrait boucler) ; 0 = pas de descente
 *  @return ERROR_SUCCESS si l'énumération a abouti (même sans fichier),
 *          S_FALSE si au moins un fichier a échoué,
 *          un code d'erreur si le volume est inaccessible
 */
HRESULT ExtractDirectoryTreeRaw(const std::wstring& volumeLetter,
                                const std::wstring& dirPathOnVolume,
                                const std::wstring& outDir,
                                const std::vector<std::wstring>& extensions = {},
                                size_t* extracted = nullptr,
                                unsigned profondeurMax = 8);
