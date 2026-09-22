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
#include <cstdint>
#include <memory>

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

/*! Ce qui est relevé d'un fichier au moment où il est extrait.
 *
 *  Tout est recueilli PENDANT l'extraction, sur les octets qui transitent déjà
 *  en mémoire : relire la copie depuis le support de collecte coûtait près de la
 *  moitié du temps d'extraction sur clé USB, et une relecture ne prouve pas ce
 *  qui a été lu du volume — seulement ce qui se trouve dans la copie.
 *
 *  TROIS EMPREINTES et non une. MD5 ne suffit plus à identifier une pièce sans
 *  discussion (collisions produites à volonté depuis 2008), SHA-1 non plus
 *  depuis 2017 ; SHA-256 reste incontesté. Les trois ensemble ferment le débat.
 *
 *  Les horodatages et le numéro d'enregistrement $MFT décrivent le fichier
 *  SOURCE : ils identifient la pièce sur le volume indépendamment de son nom, et
 *  attestent que la lecture brute n'a modifié aucune date de la cible.
 */
struct RawHiveEmpreintes {
    std::wstring md5;            //!< empreinte MD5, hexadécimal majuscule
    std::wstring sha1;           //!< empreinte SHA-1
    std::wstring sha256;         //!< empreinte SHA-256
    uint64_t octets = 0;         //!< taille réellement extraite
    uint64_t tailleAnnoncee = 0; //!< taille déclarée par l'attribut $DATA
    /*! Longueur des données valides de l'attribut non résident. Au-delà, le
     *  contenu est nul par définition et n'est PAS lu sur le disque. Égale à
     *  `tailleAnnoncee` pour un fichier ordinaire ; inférieure pour un fichier
     *  préalloué (journaux d'événements). */
    uint64_t tailleValide = 0;
    uint64_t mftEntry = 0;       //!< numéro d'enregistrement dans la $MFT
    bool     resident = false;   //!< donnée contenue dans l'enregistrement $MFT
    // $STANDARD_INFORMATION du fichier source, en FILETIME (UTC, 0 si absent).
    uint64_t creeUtc = 0;        //!< date de création
    uint64_t modifieUtc = 0;     //!< dernière modification du contenu
    uint64_t mftModifieUtc = 0;  //!< dernière modification de l'enregistrement
    uint64_t accedeUtc = 0;      //!< dernier accès
    uint64_t extraitUtc = 0;     //!< instant de l'extraction de CETTE pièce (FILETIME UTC)
};

/*! Un fichier extrait, tel qu'il sera consigné au manifeste. */
struct RawHiveExtrait {
    std::wstring cheminVolume;   //!< chemin sur le volume source
    std::wstring cheminSortie;   //!< fichier écrit sur le support de collecte
    HRESULT      resultat = E_FAIL;   //!< issue de l'extraction
    RawHiveEmpreintes empreintes;     //!< vide si l'extraction a échoué
};

/*! Extrait plusieurs fichiers en UNE seule ouverture de volume (efficace).
 *  @param volumeLetter lettre du volume a lire, sans les deux-points (ex. L"C")
 *  @param items  paires {chemin sur volume, fichier de sortie}
 *  @param perItem (optionnel) reçoit le HRESULT de chaque item, dans l'ordre
 *  @param releve (optionnel) reçoit un relevé par item, empreintes comprises.
 *         C'est la source du manifeste de consigne : sans lui, une pièce est
 *         copiée sans rien qui l'identifie.
 *  @return S_OK si tout réussit, S_FALSE si au moins un item échoue,
 *          ou un code d'erreur si l'ouverture du volume échoue.
*/
HRESULT ExtractFilesRaw(const std::wstring& volumeLetter,
                        const std::vector<std::pair<std::wstring, std::wstring>>& items,
                        std::vector<HRESULT>* perItem = nullptr,
                        std::vector<RawHiveExtrait>* releve = nullptr);

/*! Lecteur brut PERSISTANT, pour lire des milliers de fichiers épars.
 *
 *  `ExtractFilesRaw` ouvre le volume, amorce la $MFT et reparcourt chaque
 *  répertoire depuis la racine à chaque appel. Pour les binaires cités par les
 *  artefacts (plusieurs milliers, dispersés), ce serait autant d'ouvertures de
 *  volume — la seule opération de WAC qu'un audit d'accès aux objets peut
 *  journaliser — et autant de relectures des 4 659 entrées de System32.
 *  Le LecteurBrut garde chaque volume ouvert UNE fois pour toute sa durée de
 *  vie, et met en cache l'index des répertoires traversés.
 */
class LecteurBrut {
public:
    LecteurBrut();
    ~LecteurBrut();
    LecteurBrut(const LecteurBrut&) = delete;
    LecteurBrut& operator=(const LecteurBrut&) = delete;

    /*! Lit un fichier par son chemin absolu (« X:\\… »).
     *  @param sortie fichier à écrire ; VIDE pour ne calculer que les empreintes
     *         — rien n'est alors écrit nulle part
     *  @param ligne  reçoit le relevé, empreintes et horodatages compris
     *  @return le résultat, également porté par `ligne.resultat` */
    HRESULT lire(const std::wstring& cheminAbsolu, const std::wstring& sortie,
                 RawHiveExtrait& ligne);

    //! Nombre de volumes effectivement ouverts (un handle chacun).
    unsigned volumesOuverts() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/*! Un attribut d'un enregistrement $MFT, tel qu'il est écrit sur le disque. */
struct RawAttribut {
    uint32_t type = 0;          //!< 0x10 $STANDARD_INFORMATION, 0x80 $DATA, 0xC0 $REPARSE_POINT…
    std::wstring nom;           //!< nom de l'attribut, vide pour l'attribut sans nom
    bool     resident = true;   //!< contenu dans l'enregistrement
    uint64_t tailleReelle = 0;  //!< taille des données
    /*! Non résident seulement : longueur des données VALIDES (« valid data
     *  length »). Au-delà, NTFS rend des zéros, quel que soit le contenu des
     *  grappes — qui peuvent porter les restes d'anciens fichiers. */
    uint64_t tailleInitialisee = 0;
    uint16_t drapeaux = 0;      //!< 0x0001 compressé, 0x4000 chiffré, 0x8000 creux
    uint32_t tagReparse = 0;    //!< pour 0xC0 : l'étiquette du point de reparse
    std::vector<uint8_t> apercu; //!< premiers octets du contenu, si résident
};

/*! Énumère les attributs d'un fichier, tels qu'ils figurent dans la $MFT.
 *
 *  POURQUOI CETTE FONCTION EXISTE. Ce que l'API de Windows montre d'un fichier
 *  et ce que le disque contient peuvent différer radicalement : un binaire
 *  « Compact OS » se présente comme un fichier ordinaire — attributs normaux,
 *  un seul flux — alors qu'il porte en réalité un point de reparse, un `$DATA`
 *  creux et un flux nommé qui contient tout. Le filtre du système masque cette
 *  structure à toute interrogation classique. Sans un regard direct sur la
 *  $MFT, un fichier extrait entièrement à zéro reste inexplicable.
 *
 *  @param volumeLetter lettre du volume, ex. L"C"
 *  @param cheminSurVolume chemin du fichier sur ce volume
 *  @param out reçoit les attributs trouvés (vidé au préalable)
 *  @return ERROR_SUCCESS, ou un code d'erreur
 */
HRESULT ListAttributesRaw(const std::wstring& volumeLetter,
                          const std::wstring& cheminSurVolume,
                          std::vector<RawAttribut>& out);

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
 *  @param releve (optionnel) reçoit un relevé par fichier, empreintes comprises,
 *         y compris pour les fichiers dont l'extraction a échoué : c'est la
 *         source du manifeste de consigne
 *  @return ERROR_SUCCESS si le répertoire a pu être énuméré (même vide),
 *          S_FALSE si au moins un fichier n'a pas pu être extrait,
 *          un code d'erreur si le volume est inaccessible
 */
HRESULT ExtractDirectoryRaw(const std::wstring& volumeLetter,
                            const std::wstring& dirPathOnVolume,
                            const std::wstring& outDir,
                            const std::vector<std::wstring>& extensions = {},
                            size_t* extracted = nullptr,
                            std::wstring* diagnostic = nullptr,
                            std::vector<RawHiveExtrait>* releve = nullptr);

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
 *  @param releve (optionnel) reçoit un relevé par fichier, empreintes comprises :
 *         c'est la source du manifeste de consigne
 *  @return ERROR_SUCCESS si l'énumération a abouti (même sans fichier),
 *          S_FALSE si au moins un fichier a échoué,
 *          un code d'erreur si le volume est inaccessible
 */
HRESULT ExtractDirectoryTreeRaw(const std::wstring& volumeLetter,
                                const std::wstring& dirPathOnVolume,
                                const std::wstring& outDir,
                                const std::vector<std::wstring>& extensions = {},
                                size_t* extracted = nullptr,
                                unsigned profondeurMax = 8,
                                std::vector<RawHiveExtrait>* releve = nullptr);
