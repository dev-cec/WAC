#pragma once

/*  pe_resource.h — LECTURE DES RESSOURCES D'UN BINAIRE PE, HORS LIGNE.
 *
 *  POURQUOI. Le message en clair d'un événement n'est PAS dans le journal : le
 *  journal ne contient que l'identifiant de l'événement et ses données. Le texte
 *  vit dans le fichier de ressources du fournisseur, et c'est `EvtFormatMessage`
 *  qui les réunissait — au prix d'un appel au système examiné. Mesuré sur une
 *  collecte réelle : 14 046 événements sur 102 627 portaient un message, dont
 *  97 % venaient de fournisseurs modernes.
 *
 *  Deux ressources sont nécessaires, et elles vivent dans le même binaire :
 *
 *    MESSAGETABLE   la table des textes, indexée par identifiant de message.
 *                   Sur un système localisé elle n'est pas dans la DLL mais dans
 *                   son fichier satellite `<langue>\<nom>.mui`.
 *    WEVT_TEMPLATE  les métadonnées du fournisseur, qui font le lien entre un
 *                   identifiant d'ÉVÉNEMENT et un identifiant de MESSAGE. Sans
 *                   elle, on ne sait pas quel texte va avec quel événement.
 *
 *  Ce module ne fait qu'une chose : rendre le contenu brut d'une ressource
 *  donnée. Son interprétation appartient à message_table.h et wevt.h.
 *
 *  CE QUI REND LA LECTURE D'UN PE DÉLICATE ICI. Les adresses dans le répertoire
 *  de ressources sont des adresses VIRTUELLES (RVA), pas des positions dans le
 *  fichier. Il faut donc traduire chaque RVA par la table des sections — et
 *  cette traduction est le seul endroit où une implémentation se trompe
 *  silencieusement, en lisant des octets pris ailleurs dans le binaire.
 *
 *  Les fichiers viennent de la machine examinée : chaque en-tête, chaque
 *  décalage et chaque compteur est borné par la taille réelle du fichier, et un
 *  binaire malformé rend une ressource vide plutôt que de faire lire hors zone.
 *
 *  C++ portable, aucune dépendance : vérifiable hors Windows (cf. pe_resource_test).
 */

#include <cstdint>
#include <string>
#include <vector>

//! Types de ressources utiles ici. RT_MESSAGETABLE est standard (11) ;
//! WEVT_TEMPLATE est un type NOMMÉ, propre aux fournisseurs d'événements.
const uint32_t PE_RT_MESSAGETABLE = 11;

/*! Charge un binaire PE en mémoire et donne accès à ses ressources. */
class PeResource {
public:
	/*! Ouvre le fichier et valide ses en-têtes.
	*  @param chemin binaire à lire (une copie extraite, jamais l'original)
	*  @return vrai si le fichier est un PE dont le répertoire de ressources est
	*          exploitable */
	bool ouvrir(const std::wstring& chemin);

	//! Vrai si `ouvrir` a abouti.
	bool ouvert() const { return ouvert_; }

	//! Message d'erreur si `ouvrir` a échoué.
	const std::wstring& erreur() const { return erreur_; }

	/*! Contenu d'une ressource désignée par un type NUMÉRIQUE.
	*  @param type par exemple PE_RT_MESSAGETABLE
	*  @param langue identifiant de langue voulu, ou 0 pour la première trouvée
	*  @return les octets de la ressource, vide si absente */
	std::vector<uint8_t> ressource(uint32_t type, uint32_t langue = 0) const;

	/*! Contenu d'une ressource désignée par un type NOMMÉ.
	*  @param nomType par exemple L"WEVT_TEMPLATE" (comparaison sans casse)
	*  @param langue identifiant de langue voulu, ou 0 pour la première trouvée
	*  @return les octets de la ressource, vide si absente */
	std::vector<uint8_t> ressourceNommee(const std::wstring& nomType,
	                                     uint32_t langue = 0) const;

	/*! Types de ressources présents, pour diagnostic.
	*  @return libellés « 11 » pour les types numériques, le nom pour les autres */
	std::vector<std::wstring> typesPresents() const;

private:
	std::vector<uint8_t> fichier_;
	bool ouvert_ = false;
	std::wstring erreur_;
	uint32_t rvaRessources_ = 0;     //!< RVA du répertoire de ressources
	uint32_t tailleRessources_ = 0;
	size_t   offsetRessources_ = 0;  //!< sa position DANS LE FICHIER

	//! Traduit une adresse virtuelle en position dans le fichier, 0 si hors zone.
	size_t offsetDeRva(uint32_t rva) const;
	struct Section { uint32_t rva, tailleVirtuelle, offsetFichier, tailleBrute; };
	std::vector<Section> sections_;

	//! Parcourt un niveau du répertoire de ressources.
	std::vector<uint8_t> chercher(uint32_t type, const std::wstring& nomType,
	                             uint32_t langue) const;
};
