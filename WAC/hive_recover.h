/*  hive_recover.h — rend exploitable une ruche copiée à chaud (« dirty »).
 *
 *  PROBLÈME. Une copie brute d'une ruche d'un système en fonctionnement est
 *  toujours marquée « dirty » : dans son bloc de base (`regf`), le numéro de
 *  séquence primaire diffère du secondaire. `offreg` (OROpenHive) refuse alors
 *  la ruche avec ERROR_BADDB (1009), quel que soit le mode — mesuré sur
 *  Windows 11 25H2. VSS masquait ce problème : le snapshot déclenchait le
 *  *registry writer*, qui flushait les ruches.
 *
 *  POURQUOI PAS LE REJEU DES JOURNAUX. Les `.LOG1/.LOG2` ne contiennent que les
 *  entrées depuis le dernier flush, alors que le bloc de base sur disque est bien
 *  plus ancien (mesuré : ruche à 0x6e2/0x6e3, journaux couvrant 0x720→0x730).
 *  L'écart rend le rejeu impossible sur une copie à chaud.
 *
 *  SOLUTION. Aligner secondaire := primaire et recalculer le checksum du bloc de
 *  base, ce que font les outils du domaine pour « charger une ruche dirty ».
 *  Vérifié : la ruche s'ouvre alors et les données sont cohérentes (17 sous-clés
 *  racine attendues, Select\Current=1, 739 services).
 *
 *  DÉONTOLOGIE. Le patch ne porte que sur 8 octets du bloc de base et il est
 *  entièrement consigné (hash avant patch, séquences d'origine, checksum) : la
 *  copie brute d'origine reste reconstructible à l'octet. Les modifications en
 *  attente qui résidaient dans les journaux ne sont PAS appliquées — les journaux
 *  sont donc extraits à côté, comme artefacts et comme trace de ce qui manque.
 */
#pragma once
#include <cstdint>
#include <filesystem>
#include <string>

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
