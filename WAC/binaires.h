/*  binaires.h — empreinte et prélèvement des fichiers cités par les artefacts.
 *
 *  POURQUOI CE MODULE. Avec `--binary`, WAC relève l'empreinte de chaque fichier
 *  qu'un artefact désigne : exécutable d'un processus, d'un service, d'une tâche
 *  planifiée, fichiers chargés par un programme (Prefetch), entrées de Shimcache
 *  et d'Amcache, cible d'un raccourci. Ces empreintes étaient calculées en
 *  OUVRANT chaque fichier par l'API : la seule lecture de fichier que WAC
 *  faisait encore sur la machine examinée, et qui met à jour la date de dernier
 *  accès là où Windows la tient à jour. Elles sont désormais calculées par
 *  lecture brute du volume : aucun fichier n'est ouvert.
 *
 *  PRÉLÈVEMENT. L'empreinte suffit à interroger une base publique sans rien lui
 *  envoyer, mais elle ne dit rien d'un binaire que personne ne connaît — le cas
 *  qui intéresse l'enquête — et un binaire non prélevé peut avoir disparu quand
 *  la détection arrive. Les exécutables, bibliothèques, pilotes, scripts et
 *  documents Office capables de porter des macros qui sont cités sont donc
 *  COPIÉS dans la consigne, avec leurs trois empreintes, comme toute autre
 *  pièce. Les autres fichiers cités (documents sans macros, données) ne sont
 *  que hachés : ce ne sont pas des charges, et les copier ferait de la collecte
 *  une copie des documents de l'utilisateur.
 *
 *  DÉDOUBLONNAGE. Un même contenu n'est consigné qu'une fois : trois copies
 *  identiques de msedge.dll (Edge, EdgeCore, WebView2 : 332 Mo chacune)
 *  occupaient 996 Mo. Les autres chemins sont déclarés au manifeste comme
 *  pièces partageant ce contenu (cf. ConsigneAjouterDoublon).
 *
 *  La lecture étant brute, prélever ne coûte AUCUNE trace de plus que hacher :
 *  seulement de la place sur le support de collecte. Quand elle vient à manquer,
 *  le fichier est haché sans être copié, et c'est consigné.
 */
#pragma once
#include <windows.h>
#include <string>
#include "json.h"

/*! Empreintes d'un fichier cité, et ce qu'il en a été fait. */
struct EmpreinteBinaire {
    std::wstring chemin;     //!< chemin normalisé (« X:\… »), vide si indéterminable
    std::wstring md5;        //!< vides si le fichier n'a pas pu être lu
    std::wstring sha1;
    std::wstring sha256;
    HRESULT resultat = E_FAIL;
    bool preleve = false;    //!< copié dans la consigne
};

/*! Empreintes du fichier désigné par un artefact.
 *
 *  Le chemin est normalisé par `normaliserCheminFichier` ; un chemin qui ne
 *  désigne pas un fichier local déterminable rend un résultat vide. Chaque
 *  fichier n'est lu qu'UNE fois pour toute la collecte, quel que soit le nombre
 *  d'artefacts qui le citent.
 *
 *  Sans `--binary`, rend un résultat vide sans rien lire.
 */
const EmpreinteBinaire& EmpreinteFichier(const std::wstring& cheminBrut);

/*! Ajoute à un objet JSON les trois empreintes, sous les clés
 *  `<prefixe>Md5<suffixe>`, `<prefixe>Sha1<suffixe>`, `<prefixe>Sha256<suffixe>`.
 *  Une empreinte absente n'est pas émise : un champ vide se lirait comme un
 *  défaut du logiciel. */
void ajouterEmpreintes(Json& o, const EmpreinteBinaire& e,
                       const std::wstring& prefixe = L"", const std::wstring& suffixe = L"");

/*! Bilan, pour le journal d'investigation. */
void BinairesBilan(size_t* fichiers, size_t* lus, size_t* preleves,
                   unsigned long long* octetsPreleves, size_t* sansPlace,
                   size_t* doublons, unsigned long long* octetsEvites);

/*! Ferme les volumes gardés ouverts. À appeler quand plus aucun artefact ne
 *  cite de fichier. */
void BinairesTerminer();
