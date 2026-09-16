/*  hive_recover.h — rend exploitable une ruche copiée à chaud (« dirty »).
 *
 *  PROBLÈME. Une copie brute d'une ruche d'un système en fonctionnement est
 *  toujours marquée « dirty » : dans son bloc de base (`regf`), le numéro de
 *  séquence primaire diffère du secondaire. `offreg` (OROpenHive) refuse alors
 *  la ruche avec ERROR_BADDB (1009), quel que soit le mode — mesuré sur
 *  Windows 11 25H2. VSS masquait ce problème : le snapshot déclenchait le
 *  *registry writer*, qui flushait les ruches.
 *
 *  DEUX NIVEAUX DE REMISE EN ÉTAT, du plus complet au plus minimal :
 *
 *    1. ReplayHiveLogs() applique les journaux de transaction. C'est ce que fait
 *       Windows au démarrage : les `.LOG1/.LOG2` contiennent les pages modifiées
 *       depuis la dernière écriture complète de la ruche, et les appliquer donne
 *       l'état réel de la machine au moment de la copie. Mesuré sur une machine
 *       réelle : 452 Kio pour SYSTEM, 1 172 Kio pour SOFTWARE, 600 Kio pour un
 *       ntuser.dat — et trois clés de `MountPoints2` que la copie brute seule ne
 *       contenait pas. La ruche reconstituée est propre par construction, donc
 *       aucun patch n'est nécessaire ensuite.
 *
 *    2. MakeHiveLoadable() ne sert plus que de recours : pas de journal, journal
 *       vide, ou chaîne d'entrées inutilisable. Il aligne secondaire := primaire
 *       et recalcule le checksum du bloc de base, ce que font les outils du
 *       domaine pour « charger une ruche dirty ». Les modifications restées dans
 *       les journaux ne sont alors PAS appliquées.
 *
 *  DÉONTOLOGIE. Les deux opérations écrivent dans la COPIE, jamais dans
 *  l'original — qui n'est de toute façon jamais ouvert en écriture. Et la copie
 *  brute reste reconstructible à l'octet : le patch ne porte que sur 8 octets,
 *  entièrement consignés, et le rejeu écrit à côté de la ruche un journal
 *  d'annulation contenant le contenu d'ORIGINE de chaque page remplacée
 *  (cf. ReplayHiveLogs). Les `.LOG1/.LOG2` sont extraits dans tous les cas : ils
 *  sont des artefacts en eux-mêmes et la trace de ce qui a été appliqué.
 */
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

/*! Résultat de la mise en état d'une ruche. */
struct HiveFixInfo {
    bool     ok            = false; //!< bloc de base lu et traité sans erreur
    bool     wasDirty      = false; //!< séquences primaire/secondaire différentes
    bool     patched       = false; //!< le patch a été appliqué
    uint32_t primarySeq    = 0;     //!< séquence primaire (inchangée)
    uint32_t secondarySeq  = 0;     //!< séquence secondaire AVANT patch
    uint32_t oldChecksum   = 0;     //!< checksum avant patch
    uint32_t newChecksum   = 0;     //!< checksum recalculé
    std::wstring hiveName;          //!< nom interne de la ruche (offset 0x30)
    std::wstring error;             //!< message si ok == false
};

/*! Rend la ruche exploitable par offreg, en place, si elle est « dirty ».
 *  Ne touche rien si la ruche est déjà propre (primaire == secondaire).
 *  @param hive chemin de la ruche extraite (modifiée en place si dirty)
 *  @return détail de l'opération, à consigner dans le rapport
 */
HiveFixInfo MakeHiveLoadable(const std::filesystem::path& hive);

/*! Rend le détail lisible pour le log/rapport (une ligne). */
std::wstring HiveFixInfoToString(const HiveFixInfo& i);

/*! Une entrée de journal de transaction, retenue ou écartée. */
struct HiveLogEntry {
    uint32_t sequence = 0;      //!< numéro de séquence de l'entrée
    uint32_t pages    = 0;      //!< nombre de pages modifiées
    uint64_t octets   = 0;      //!< volume de ces pages
    bool     applique = false;  //!< vrai si elle a été écrite dans la ruche
    std::wstring motif;         //!< pourquoi elle a été écartée, le cas échéant
};

/*! Résultat du rejeu des journaux de transaction. */
struct HiveReplayInfo {
    bool ok       = false;      //!< opération menée sans erreur d'entrée/sortie
    bool journaux = false;      //!< au moins un `.LOG1/.LOG2` exploitable trouvé
    bool applique = false;      //!< au moins une entrée écrite dans la ruche
    uint32_t sequenceRuche   = 0;  //!< séquence de la ruche avant rejeu
    uint32_t sequenceFinale  = 0;  //!< séquence après rejeu
    unsigned entreesRetenues = 0;  //!< entrées de la chaîne appliquées
    unsigned entreesEcartees = 0;  //!< entrées invalides (empreinte, bornes)
    unsigned entreesResidu   = 0;  //!< entrées hors chaîne (génération antérieure)
    unsigned pages           = 0;  //!< pages écrites
    uint64_t octets          = 0;  //!< octets écrits
    std::wstring journalAnnulation; //!< chemin du journal d'annulation produit
    std::wstring error;             //!< message si ok == false
    std::vector<HiveLogEntry> entrees; //!< détail, pour le rapport
};

/*! Applique les journaux de transaction à une ruche extraite.
*
*  DEUX PIÈGES, tous deux rencontrés sur des données réelles et tous deux
*  déterminants pour l'exactitude du rapport :
*
*  - **L'ORDRE DU FICHIER, PAS L'ORDRE DES SÉQUENCES.** Un journal est réutilisé
*    sur place : les entrées d'une génération antérieure survivent APRÈS la fin
*    de la chaîne courante. Les trier par numéro de séquence fait remonter en
*    tête une entrée périmée, dont les pages sont PLUS ANCIENNES que la ruche.
*    Mesuré : les horodatages BAM — de la preuve d'exécution — reculaient de
*    quinze minutes. On suit donc chaque journal dans l'ordre du fichier et on
*    s'arrête à la première rupture de séquence, comme le fait la récupération de
*    Windows ; ce qui suit est du résidu.
*
*  - **CHAQUE ENTRÉE EST VÉRIFIÉE AVANT D'ÊTRE APPLIQUÉE.** Les deux empreintes
*    Marvin32 de l'en-tête couvrent l'entête (32 premiers octets) et le corps
*    (de l'offset 40 à la fin). Vérifiées conformes sur 60 entrées de 11 journaux
*    d'une machine réelle. Une entrée qui échoue termine la chaîne : appliquer
*    des pages douteuses à une preuve serait pire que ne rien appliquer.
*
*  Un journal d'annulation `<ruche>.undo` est écrit à côté de la ruche, contenant
*  le contenu d'ORIGINE de chaque page remplacée. Format, volontairement trivial
*  pour qu'un tiers puisse refaire l'opération en sens inverse :
*
*      0   8   « WACUNDO1 »
*      8  32   empreinte MD5 de la ruche AVANT rejeu, en ASCII hexadécimal
*     40   4   nombre de pages
*     44   8   taille de la ruche avant rejeu
*     52   4   réservé (0)
*     56  12×N table des pages : offset (8 octets), taille (4 octets)
*     ...      contenu d'origine des pages, dans l'ordre de la table
*
*  @param hive chemin de la ruche extraite (modifiée en place si le rejeu aboutit)
*  @param md5Avant empreinte de la ruche avant rejeu, consignée dans le journal
*         d'annulation ; l'appelant l'a déjà calculée pendant l'extraction
*  @return détail de l'opération, à consigner dans le rapport
*/
HiveReplayInfo ReplayHiveLogs(const std::filesystem::path& hive,
                              const std::wstring& md5Avant);

/*! Rend le détail lisible pour le log/rapport (une ligne). */
std::wstring HiveReplayInfoToString(const HiveReplayInfo& i);
