/*  raw_collect.h — orchestration de l'extraction offline des artefacts (WAC).
 *
 *  Remplace la collecte VSS : extrait par lecture brute NTFS (raw_hive) les
 *  ruches et les fichiers nécessaires vers un sous-répertoire du dossier de
 *  sortie, sur la clé USB — AUCUNE écriture sur l'hôte, aucun point de montage,
 *  aucun snapshot.
 *
 *  conf.mountpoint est réutilisé comme simple préfixe de chemin vers ce
 *  répertoire d'extraction (sur l'USB). Les fichiers y sont rangés sous LEUR
 *  chemin d'origine relatif au volume, si bien que tout le pipeline en aval
 *  (OROpenHive, listFilesByExtension) reste inchangé.
 */
#pragma once
#include <windows.h>

/*  POURQUOI L'EXTRACTION DES RUCHES SE FAIT EN DEUX PASSES.
 *
 *  Les ruches par utilisateur (`ntuser.dat`, `usrClass.dat`) vivent dans le
 *  dossier de profil : il faut donc connaître l'emplacement des profils avant de
 *  pouvoir les extraire. Cette liste était lue dans le registre VIVANT, à
 *  `HKLM\SOFTWARE\...\ProfileList` — la dernière lecture que WAC faisait encore
 *  sur le registre de la machine examinée.
 *
 *  Elle se lit désormais dans la ruche SOFTWARE extraite, ce qui impose l'ordre
 *  suivant, et explique que ce qui était une seule fonction en soit devenu deux :
 *
 *    1. ExtractSystemHivesRaw()   — SYSTEM, SOFTWARE, SAM, Amcache
 *    2. OROpenHive(SOFTWARE)      — sur la copie de travail
 *    3. loadProfileList()         — hors ligne, dans cette copie
 *    4. ExtractUserHivesRaw()     — les ruches des profils ainsi relevés
 *    5. ExtractFileArtefactsRaw() — Prefetch, jumplists, documents récents
 *
 *  Le coût est une seconde passe de lecture de la $MFT du volume ; le gain est
 *  qu'aucune clé du registre de la machine examinée n'est plus ouverte.
 */

/*! Extrait les ruches de la MACHINE (+ journaux .LOG1/.LOG2) vers
 *  `_outputDir`\\consigne, en fait la copie de travail et la rend exploitable
 *  par offreg.
 *
 *  Les journaux de transaction sont extraits car ils sont des artefacts en
 *  eux-mêmes, et documentent les modifications en attente que la copie à chaud
 *  ne contient pas.
 *
 *  Une copie brute d'une ruche d'un système vivant est toujours « dirty » et
 *  refusée par offreg : chaque ruche passe donc par un rejeu des journaux, puis
 *  par MakeHiveLoadable() en recours (cf. hive_recover.h).
 *
 *  @return S_OK si tout réussit, S_FALSE si certains fichiers manquent ou si une
 *          ruche reste inexploitable, ou un code d'erreur si le volume ne peut
 *          être ouvert.
 */
HRESULT ExtractSystemHivesRaw();

/*! Extrait les ruches de chaque PROFIL utilisateur relevé dans `conf.profiles`,
 *  selon les mêmes règles que `ExtractSystemHivesRaw`.
 *
 *  À appeler APRÈS `loadProfileList()`, qui renseigne `conf.profiles` depuis la
 *  ruche SOFTWARE extraite par la passe précédente.
 *
 *  @return S_OK si tout réussit, S_FALSE si aucun profil n'a été relevé ou si
 *          certains fichiers manquent, ou un code d'erreur si le volume ne peut
 *          être ouvert.
 */
HRESULT ExtractUserHivesRaw();

/*! Extrait les artefacts sur fichiers : Prefetch, jumplists et documents
 *  récents, vers `_outputDir`\\hives sous leur chemin d'origine.
 *
 *  Sans cette extraction, les collecteurs correspondants ne rendent AUCUNE
 *  donnée — et « 0 entrée » est, à l'analyse, indiscernable de « aucune trace
 *  sur la machine ». Le décompte par répertoire est donc journalisé, pour que le
 *  rapport distingue un dossier vide d'un dossier non collecté.
 *
 *  @return S_OK si tout réussit, S_FALSE si au moins un fichier a échoué, ou un
 *          code d'erreur si le volume ne peut être ouvert.
 */
HRESULT ExtractFileArtefactsRaw();
