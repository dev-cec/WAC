/*  authenticode.h — authenticité Microsoft d'un binaire, vérifiée sans API.
 *
 *  À QUOI ÇA SERT. Avec --binary, WAC prélève les exécutables cités par les
 *  artefacts. La plupart sont des composants de Windows ou des logiciels
 *  Microsoft, identiques sur toute machine de la même version : les copier ne
 *  sert pas l'enquête, et pèse des gigaoctets. Ces fichiers portent une preuve
 *  d'origine vérifiable SUR LA MACHINE ELLE-MÊME, sans liste embarquée :
 *    - les CATALOGUES de Windows (System32\CatRoot\{F750E6C3…}\*.cat), signés par
 *      Microsoft, qui listent l'empreinte de chaque fichier du système ;
 *    - la SIGNATURE INTÉGRÉE des binaires signés individuellement (Edge,
 *      OneDrive, Office…).
 *  Un fichier dont l'empreinte Authenticode figure dans un catalogue à
 *  signature Microsoft valide, ou dont la signature intégrée est une signature
 *  Microsoft valide, est haché sans être prélevé. Tout le reste l'est. Un
 *  binaire de System32 remplacé par un attaquant n'a plus l'empreinte du
 *  catalogue : il est prélevé.
 *
 *  AUCUNE TRACE. WinVerifyTrust et CryptCATAdmin sollicitent le service
 *  CryptSvc et sa base de catalogues, lisent les magasins de certificats dans le
 *  registre vivant, et contrôlent la révocation par le réseau — ce qui écrit
 *  dans CryptnetUrlCache. Rien de cela ici : catalogues et binaires sont lus par
 *  lecture brute du volume, et la vérification — ASN.1, X.509, PKCS#7, RSA —
 *  se fait en mémoire, jusqu'à des racines Microsoft EMBARQUÉES
 *  (racines_microsoft.h), sans consulter le magasin de la machine.
 *
 *  CE QUI N'EST PAS VÉRIFIÉ, et pourquoi c'est acceptable ici : la révocation
 *  et les dates de validité. La question posée n'est pas « faut-il faire
 *  confiance à ce code aujourd'hui » mais « ce fichier est-il celui que
 *  Microsoft a publié » ; une signature Microsoft authentique y répond. Dans le
 *  doute — algorithme non pris en charge, structure inattendue — la réponse est
 *  « non vérifié », et le fichier est prélevé.
 *
 *  SIGNATAIRES ACCEPTÉS. Tous les certificats rattachés à une racine Microsoft
 *  ne signent pas du code Microsoft : « Microsoft Windows Hardware
 *  Compatibility Publisher » signe les pilotes TIERS certifiés WHQL, et « Early
 *  Launch Anti-malware Publisher » les pilotes ELAM des antivirus tiers — le
 *  terrain classique des pilotes vulnérables détournés. Ne sont acceptés que les
 *  signataires dont l'organisation est « Microsoft Corporation » et le nom
 *  « Microsoft Windows », « Microsoft Corporation » ou « Microsoft Windows
 *  Publisher ».
 */
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <streambuf>
#include <unordered_map>
#include "sha.h"

/*! Analyse d'un fichier PE fourni en flux : empreintes Authenticode et table
 *  de certificats, calculées au fil de la lecture, sans relire le fichier.
 *
 *  L'empreinte Authenticode couvre tout le fichier SAUF le champ CheckSum de
 *  l'en-tête optionnel, l'entrée « table de certificats » du répertoire de
 *  données, et la table de certificats elle-même. */
class AnalyseurPe : public std::streambuf {
public:
	/*! Termine le calcul (à appeler une fois tout le fichier reçu). */
	void terminer();
	bool estPe() const { return estPe_; }
	//! Empreintes Authenticode (valides après terminer(), si estPe()).
	const uint8_t* sha1() const { return sha1_; }
	const uint8_t* sha256() const { return sha256_; }
	//! Mêmes empreintes, fichier complété de zéros jusqu'à un multiple de 8.
	const uint8_t* sha1Complete() const { return sha1c_; }
	const uint8_t* sha256Complete() const { return sha256c_; }
	//! Contenu de la table de certificats (WIN_CERTIFICATE…), vide si absente.
	const std::vector<uint8_t>& tableCertificats() const { return certificats_; }

protected:
	int overflow(int c) override;
	std::streamsize xsputn(const char* s, std::streamsize n) override;

private:
	void recevoir(const uint8_t* p, size_t n);
	void traiter(const uint8_t* p, size_t n);   // après analyse des en-têtes
	bool analyserEntetes();

	std::vector<uint8_t> tete_;         // en-têtes, tant que non analysés
	bool decide_ = false, estPe_ = false, termine_ = false;
	uint64_t position_ = 0;             // octets déjà traités
	uint64_t checksum_ = 0, entreeCert_ = 0, debutCert_ = 0, finCert_ = 0;
	Sha1Stream h1_;
	Sha256Stream h256_;
	std::vector<uint8_t> certificats_;
	uint8_t sha1_[20] = {}, sha256_[32] = {}, sha1c_[20] = {}, sha256c_[32] = {};
};

/*! Résultat de la vérification d'une signature PKCS#7. */
struct SignatureVerifiee {
	bool valide = false;          //!< signature et chaîne vérifiées jusqu'à une racine Microsoft
	bool signataireAccepte = false; //!< et signataire conforme à la règle (cf. en-tête)
	std::wstring signataire;      //!< nom (CN) du certificat signataire
	std::string motif;            //!< raison d'un refus, pour le journal
	std::string oidContenu;       //!< type du contenu signé (octets DER de l'OID)
	const uint8_t* contenu = nullptr; //!< contenu signé (valeur, sans en-tête)
	size_t tailleContenu = 0;
};

/*! Vérifie un SignedData PKCS#7 (catalogue ou signature intégrée) : empreinte
 *  du contenu, signature du signataire, chaîne jusqu'à une racine Microsoft
 *  embarquée. Les pointeurs rendus désignent `donnees`. */
SignatureVerifiee VerifierPkcs7(const uint8_t* donnees, size_t taille);

/*! Index des empreintes Authenticode listées par les catalogues Microsoft
 *  valides de la machine. */
class IndexCatalogues {
public:
	/*! Vérifie un catalogue et, s'il est signé par un signataire accepté, indexe
	 *  ses empreintes. @return true si le catalogue a été retenu. */
	bool ajouter(const std::wstring& nom, const uint8_t* octets, size_t taille);
	/*! Nom du catalogue listant cette empreinte, ou nullptr. */
	const std::wstring* chercher(const uint8_t* empreinte, size_t taille) const;
	size_t catalogues() const { return noms_.size(); }
	size_t empreintes() const { return index_.size(); }
	size_t refuses() const { return refuses_; }
private:
	std::vector<std::wstring> noms_;
	std::unordered_map<std::string, uint32_t> index_;   // empreinte brute -> catalogue
	size_t refuses_ = 0;
};

/*! Verdict d'authenticité Microsoft sur un PE analysé. */
struct VerdictMicrosoft {
	bool microsoft = false;       //!< authentique : hacher sans prélever
	std::wstring source;          //!< « catalogue <nom> » ou « signature intégrée »
	std::wstring signataire;      //!< CN du signataire (signature intégrée)
	std::string motif;            //!< pourquoi non, pour le journal
};

/*! Décide si un PE est un binaire Microsoft authentique. */
VerdictMicrosoft EvaluerPe(const AnalyseurPe& pe, const IndexCatalogues& catalogues);
