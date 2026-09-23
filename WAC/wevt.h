#pragma once

/*  wevt.h — MESSAGE EN CLAIR D'UN ÉVÉNEMENT, RECONSTITUÉ HORS LIGNE.
 *
 *  LE PROBLÈME. Un journal d'événements ne contient pas de phrases : il contient
 *  un identifiant d'événement et des données. Le texte vit dans le fichier de
 *  ressources du fournisseur, et c'est `EvtFormatMessage` qui faisait la
 *  jonction — au prix d'un appel au système examiné. Mesuré sur une collecte
 *  réelle : 14 046 événements sur 102 627 portaient un message, et 97 % d'entre
 *  eux venaient de fournisseurs modernes.
 *
 *  LA CHAÎNE À REMONTER, et pourquoi il faut DEUX ressources :
 *
 *      événement (identifiant + version)
 *          │   WEVT_TEMPLATE, dans la DLL du fournisseur
 *          ▼
 *      identifiant de message
 *          │   MESSAGETABLE, dans le satellite <langue>\<nom>.mui
 *          ▼
 *      modèle de phrase, avec des marques %1 %2 …
 *          │   données de l'événement, lues dans le journal
 *          ▼
 *      message en clair
 *
 *  Aucun des deux maillons ne suffit seul : la table de messages ne dit pas quel
 *  texte va avec quel événement, et les métadonnées ne contiennent aucun texte.
 *
 *  LES FORMATS
 *
 *  MESSAGETABLE : un compte de blocs, puis des blocs { premier identifiant,
 *  dernier identifiant, décalage }, puis des entrées consécutives
 *  { longueur, drapeaux, texte }. Le drapeau de poids faible dit si le texte est
 *  en UTF-16 ou dans une page de code — s'y tromper rend un octet sur deux.
 *
 *  WEVT_TEMPLATE : un en-tête « CRIM », une table de fournisseurs par GUID, et
 *  pour chaque fournisseur des blocs typés par signature — « EVNT » pour les
 *  événements, « CHAN » pour les canaux, « TTBL » pour les modèles. Seul EVNT
 *  nous intéresse : il donne, par événement, l'identifiant de message.
 *
 *  Les fichiers viennent de la machine examinée : toutes les bornes sont
 *  vérifiées, et une ressource malformée rend un résultat vide plutôt que de
 *  faire lire hors zone.
 *
 *  C++ portable, aucune dépendance (cf. wevt_test).
 */

#include <cstdint>
#include <map>
#include <string>
#include <vector>

/*! Table des messages d'un binaire, indexée par identifiant. */
class TableMessages {
public:
	/*! Analyse une ressource MESSAGETABLE.
	*  @param donnees contenu brut de la ressource
	*  @return nombre de messages lus */
	size_t analyse(const std::vector<uint8_t>& data);

	/*! Texte d'un identifiant de message.
	*  @return le modèle avec ses marques %1 %2…, ou chaîne vide si absent */
	std::wstring text(uint32_t id) const;

	//! Nombre de messages connus.
	size_t size() const { return messages_.size(); }

private:
	std::map<uint32_t, std::wstring> messages_;
};

/*! Métadonnées d'événements d'un fournisseur (ressource WEVT_TEMPLATE). */
class WevtMetadata {
public:
	/*! Analyse une ressource WEVT_TEMPLATE.
	*  @param donnees contenu brut de la ressource
	*  @param guidFournisseur GUID du fournisseur cherché, sous la forme
	*         « {aea1b4fa-97d1-45f2-a64c-4d69fffd92c9} » ; vide pour prendre le
	*         premier fournisseur décrit
	*  @return nombre d'événements décrits */
	size_t analyse(const std::vector<uint8_t>& data,
	                const std::wstring& providerGuid = std::wstring());

	/*! Identifiant de message d'un événement.
	*
	*  La version est essayée d'abord, puis l'identifiant seul : un fournisseur
	*  peut décrire plusieurs versions d'un même événement, mais le journal ne
	*  porte pas toujours celle qui a servi.
	*
	*  @return l'identifiant de message, ou 0 si l'événement n'est pas décrit */
	uint32_t messageId(uint16_t eventId, uint8_t version) const;

	//! Nombre d'événements décrits.
	size_t size() const { return parIdEtVersion_.size(); }

private:
	std::map<uint32_t, uint32_t> parIdEtVersion_;   //!< (id << 8 | version) -> message
	std::map<uint16_t, uint32_t> parId_;            //!< id -> message (première version vue)
};

/*! Remplace les marques %1 %2 … par les données de l'événement.
*
*  Windows écrit ses modèles avec des marques positionnelles, et parfois des
*  séquences d'échappement de mise en page (`%n`, `%t`, `%%`). Une marque sans
*  donnée correspondante est laissée telle quelle : l'effacer ferait croire à une
*  phrase complète alors qu'il manque une valeur.
*
*  @param modele texte issu de la table des messages
*  @param valeurs données de l'événement, dans l'ordre (%1 est la première)
*  @return la phrase, ou une chaîne vide si le modèle est vide
*/
std::wstring formatMessage(const std::wstring& messageTemplate,
                             const std::vector<std::wstring>& values);
