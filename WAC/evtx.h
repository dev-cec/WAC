#pragma once

/*  evtx.h — LECTURE DES JOURNAUX D'ÉVÉNEMENTS WINDOWS (.evtx), HORS LIGNE.
 *
 *  POURQUOI CE PARSEUR EXISTE. `events` était le dernier collecteur à passer par
 *  une API du système examiné : `wevtapi` sollicite le service EventLog, lequel
 *  peut inscrire ses propres entrées PENDANT qu'on le lit. Or les journaux sont
 *  de simples fichiers, sous `\Windows\System32\winevt\Logs\*.evtx` : les
 *  extraire en brut comme les ruches et les analyser ici supprime la dernière
 *  sollicitation évitable.
 *
 *  Trois bénéfices se cumulent, ce qui est rare :
 *    - l'empreinte : plus aucun service du système examiné n'est sollicité ;
 *    - le temps : l'API met une vingtaine de minutes sous Windows 11, contre
 *      deux sous Windows 10, pour la même machine ;
 *    - la mémoire : la lecture par l'API construisait tous les enregistrements
 *      avant écriture, jusqu'à 1,4 Gio de jeu de travail — assez pour provoquer
 *      de la pagination, donc des écritures dans `pagefile.sys`, sur le disque
 *      qu'on cherche justement à ne pas modifier.
 *
 *  STRUCTURE DU FORMAT (spécification libevtx de libyal)
 *
 *    en-tête de fichier   4096 octets, signature « ElfFile\0 »
 *    chunk                64 Kio : en-tête de 512 octets (« ElfChnk\0 ») puis
 *                         une suite d'enregistrements
 *    enregistrement       signature 0x2a2a0000, taille, identifiant, FILETIME,
 *                         puis le corps en BinXML
 *
 *  BinXML est un XML binarisé : des jetons décrivent éléments, attributs et
 *  valeurs. Sa difficulté tient à deux mécanismes :
 *
 *    - LES NOMS SONT PARTAGÉS. Un nom d'élément n'est pas écrit à sa place mais
 *      désigné par un décalage relatif au DÉBUT DU CHUNK ; plusieurs
 *      enregistrements pointent le même nom. D'où la nécessité de garder le
 *      chunk entier sous la main pendant le décodage d'un enregistrement.
 *
 *    - LES TEMPLATES. Un enregistrement ne contient en général pas son XML mais
 *      une référence vers une définition placée ailleurs dans le chunk, plus un
 *      tableau de valeurs typées à y substituer. C'est ce qui rend le format
 *      compact — et ce qui fait qu'un parseur naïf ne rend rien d'exploitable.
 *
 *  CE QUE CE PARSEUR REND : le XML de chaque enregistrement, sous forme de
 *  texte. `events` l'analyse ensuite avec `xml_light` — déjà écrit pour les
 *  tâches planifiées — plutôt qu'avec un second décodeur spécifique.
 *
 *  ROBUSTESSE. Les données viennent de la machine examinée : tailles, décalages
 *  et compteurs sont donc à traiter comme non fiables. Chaque lecture est bornée
 *  par la taille réelle du tampon, la récursion par une profondeur maximale, et
 *  un enregistrement illisible n'interrompt ni son chunk ni son fichier — il est
 *  signalé et la lecture continue. Un journal partiellement corrompu est un cas
 *  courant en investigation, pas une exception.
 */

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

//! Un enregistrement d'événement, tel que lu dans le fichier.
struct EvtxEnregistrement {
	unsigned long long identifiant = 0;   //!< numéro d'enregistrement
	FILETIME ecritUtc = { 0, 0 };         //!< instant d'écriture (UTC)
	std::wstring xml;                     //!< corps de l'événement, en XML
};

/*! Résultat de la lecture d'un fichier .evtx : de quoi distinguer, dans le
*  rapport, un journal vide d'un journal illisible.
*/
struct EvtxBilan {
	unsigned long long chunks = 0;        //!< chunks parcourus
	unsigned long long lus = 0;           //!< enregistrements décodés
	unsigned long long illisibles = 0;    //!< enregistrements écartés
	unsigned long long chunksIgnores = 0; //!< chunks abîmés sautés (sans signature)
	bool enteteValide = false;            //!< signature « ElfFile\0 » trouvée
	bool sale = false;                    //!< journal marqué « dirty »
	std::wstring diagnostic;              //!< phrase pour le journal d'audit
};

/*! Lit un fichier .evtx et remet chaque enregistrement au rappel fourni.
*
*  Le rappel est appelé au fil de la lecture, enregistrement par
*  enregistrement : rien n'est accumulé ici. C'est délibéré — c'est ce qui
*  permet à l'appelant d'écrire sa sortie en flux au lieu de garder cent mille
*  événements en mémoire, le défaut de la lecture par l'API.
*
*  @param chemin chemin du fichier .evtx (la copie extraite, jamais l'original)
*  @param surEnregistrement rappel invoqué pour chaque enregistrement décodé ;
*         rendre false interrompt la lecture
*  @param bilan reçoit le décompte et le diagnostic (facultatif)
*  @return ERROR_SUCCESS si le fichier a été parcouru, un code d'erreur s'il est
*          inaccessible ; S_FALSE si des enregistrements ont été écartés
*/
HRESULT EvtxLireFichier(const std::wstring& chemin,
                        const std::function<bool(const EvtxEnregistrement&)>& surEnregistrement,
                        EvtxBilan* bilan = nullptr);

/*! Nom du canal d'après le nom de fichier du journal.
*
*  Windows encode le canal dans le nom : « Microsoft-Windows-Kernel-Boot%4Operational.evtx »
*  désigne le canal « Microsoft-Windows-Kernel-Boot/Operational ». Le « %4 » est
*  une barre oblique échappée, le caractère étant interdit dans un nom de
*  fichier.
*
*  @param nomFichier nom du fichier, avec ou sans chemin
*  @return le nom du canal
*/
std::wstring EvtxCanalDepuisNomFichier(const std::wstring& nomFichier);
