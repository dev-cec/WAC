/*  xml_light.h — lecteur XML minimal, sans dépendance.
 *
 *  POURQUOI PAS MSXML. Lire les définitions de tâches planifiées hors ligne n'a
 *  d'intérêt que si l'on supprime la trace d'exécution COM (cf. doc §9.4) ;
 *  passer par MSXML, qui est un composant COM, annulerait précisément ce
 *  bénéfice. D'où ce lecteur autonome.
 *
 *  PÉRIMÈTRE ASSUMÉ. Ce n'est PAS un analyseur XML conforme : il ne gère ni les
 *  namespaces déclarés dynamiquement, ni les DTD, ni les entités autres que les
 *  cinq prédéfinies, ni les sections CDATA imbriquées. Il traite le sous-ensemble
 *  effectivement produit par le planificateur de tâches Windows, dont le schéma
 *  est étroit et stable (`<RegistrationInfo>`, `<Triggers>`, `<Actions>`,
 *  `<Principals>`, `<Settings>`).
 *
 *  Les fichiers analysés provenant d'une machine suspecte, l'analyse est
 *  défensive : aucune récursion non bornée, aucun accès hors tampon, et tout
 *  document mal formé rend un arbre vide plutôt que de lever une exception.
 */
#pragma once
#include <string>
#include <vector>
#include <memory>

/*! Un élément XML : nom, attributs, texte, enfants. */
struct XmlNode {
	std::wstring nom;                                  //!< nom local, sans préfixe de namespace
	std::wstring texte;                                //!< contenu textuel direct, espaces des bords retirés
	std::vector<std::pair<std::wstring, std::wstring>> attributs;
	std::vector<std::unique_ptr<XmlNode>> enfants;

	/*! Premier enfant portant ce nom, ou nullptr. */
	const XmlNode* enfant(const std::wstring& nomEnfant) const;

	/*! Texte du premier enfant portant ce nom, ou chaîne vide.
	 *  @param chemin nom simple, ou chemin séparé par '/' (ex. L"Actions/Exec/Command") */
	std::wstring texteDe(const std::wstring& chemin) const;

	/*! Valeur d'un attribut, ou chaîne vide. */
	std::wstring attribut(const std::wstring& nomAttribut) const;

	/*! Tous les descendants portant ce nom, à n'importe quelle profondeur.
	 *  Utile pour collecter les déclencheurs ou les actions sans connaître leur
	 *  niveau exact d'imbrication. */
	std::vector<const XmlNode*> descendants(const std::wstring& nomRecherche) const;
};

/*! Analyse un document XML en mémoire.
 *  @param contenu document complet (UTF-16 ; l'appelant gère le décodage)
 *  @return racine, ou nullptr si le document est mal formé ou vide
 */
std::unique_ptr<XmlNode> xmlAnalyser(const std::wstring& contenu);

/*! Lit un fichier XML encodé en UTF-8 ou UTF-16 et l'analyse.
 *  L'encodage est déduit de la marque d'ordre des octets, à défaut UTF-8 :
 *  le planificateur écrit ses tâches en UTF-16LE avec BOM.
 *  @return racine, ou nullptr si le fichier est illisible ou mal formé
 */
std::unique_ptr<XmlNode> xmlLireFichier(const std::wstring& chemin);
