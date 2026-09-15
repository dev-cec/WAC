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

/*! Extrait les ruches (+ journaux .LOG1/.LOG2) vers `_outputDir`\\hives et les
 *  rend exploitables par offreg.
 *
 *  Les journaux de transaction sont extraits car ils sont des artefacts en
 *  eux-mêmes, et documentent les modifications en attente que la copie à chaud
 *  ne contient pas.
 *
 *  Une copie brute d'une ruche d'un système vivant est toujours « dirty » et
 *  refusée par offreg : chaque ruche passe donc par MakeHiveLoadable(), qui
 *  aligne les numéros de séquence et consigne l'opération (cf. hive_recover.h).
 *
 *  @return S_OK si tout réussit, S_FALSE si certains fichiers manquent ou si une
 *          ruche reste inexploitable, ou un code d'erreur si le volume ne peut
 *          être ouvert.
 */
HRESULT ExtractHivesRaw();

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
