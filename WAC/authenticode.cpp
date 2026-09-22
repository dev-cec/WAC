/*  authenticode.cpp — voir authenticode.h.
 *
 *  Références de format : RFC 2315 (PKCS#7), RFC 5280 (X.509), « Windows
 *  Authenticode Portable Executable Signature Format » (Microsoft), et la
 *  structure CTL des catalogues (Certificate Trust List, OID 1.3.6.1.4.1.311.10.1).
 */
#include "authenticode.h"
#include "rsa.h"
#include "racines_microsoft.h"
#include <cstring>
#include <map>
#include <set>
#include <mutex>

namespace {

// ============================================================ DER

struct Tlv {
	uint8_t tag = 0;
	const uint8_t* debut = nullptr;   //!< premier octet (étiquette)
	size_t total = 0;                 //!< étiquette + longueur + valeur
	const uint8_t* val = nullptr;     //!< valeur
	size_t len = 0;
};

//! Lit un élément DER à `p` (au plus `n` octets). Longueur définie uniquement.
bool lireTlv(const uint8_t* p, size_t n, Tlv& t) {
	if (n < 2 || (p[0] & 0x1F) == 0x1F) return false;         // étiquette longue : non
	size_t i = 1, len = 0;
	const uint8_t b = p[i++];
	if (b < 0x80) len = b;
	else {
		const size_t nb = b & 0x7F;
		if (nb == 0 || nb > 4 || i + nb > n) return false;     // indéfinie ou démesurée
		for (size_t k = 0; k < nb; ++k) len = (len << 8) | p[i++];
	}
	if (len > n - i) return false;
	t.tag = p[0]; t.debut = p; t.val = p + i; t.len = len; t.total = i + len;
	return true;
}

//! Éléments contenus dans un élément construit.
std::vector<Tlv> enfants(const Tlv& t) {
	std::vector<Tlv> r;
	size_t pos = 0;
	while (pos < t.len) {
		Tlv e;
		if (!lireTlv(t.val + pos, t.len - pos, e)) break;
		r.push_back(e);
		pos += e.total;
	}
	return r;
}

bool estOid(const Tlv& t, const uint8_t* oid, size_t n) {
	return t.tag == 0x06 && t.len == n && std::memcmp(t.val, oid, n) == 0;
}
#define OID(nom, ...) const uint8_t nom[] = { __VA_ARGS__ }
OID(OID_SIGNED_DATA,  0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x07,0x02);
OID(OID_RSA,          0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01);
OID(OID_SHA1_RSA,     0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x05);
OID(OID_SHA256_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B);
OID(OID_SHA1,         0x2B,0x0E,0x03,0x02,0x1A);
OID(OID_SHA256,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01);
OID(OID_SHA384,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02);
OID(OID_SHA512,       0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03);
OID(OID_SHA384_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0C);
OID(OID_SHA512_RSA,   0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0D);
OID(OID_MESSAGE_DIGEST, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x04);
OID(OID_CN,           0x55,0x04,0x03);
OID(OID_O,            0x55,0x04,0x0A);
OID(OID_SPC_INDIRECT, 0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x01,0x04);
OID(OID_CTL,          0x2B,0x06,0x01,0x04,0x01,0x82,0x37,0x0A,0x01);
#define EST(t, o) estOid((t), (o), sizeof(o))

//! Algorithme d'empreinte d'un AlgorithmIdentifier (empreinte seule ou RSA+empreinte).
AlgoEmpreinte algoDe(const Tlv& algId) {
	const std::vector<Tlv> e = enfants(algId);
	if (e.empty()) return AlgoEmpreinte::Inconnu;
	if (EST(e[0], OID_SHA1) || EST(e[0], OID_SHA1_RSA)) return AlgoEmpreinte::Sha1;
	if (EST(e[0], OID_SHA256) || EST(e[0], OID_SHA256_RSA)) return AlgoEmpreinte::Sha256;
	if (EST(e[0], OID_SHA384) || EST(e[0], OID_SHA384_RSA)) return AlgoEmpreinte::Sha384;
	if (EST(e[0], OID_SHA512) || EST(e[0], OID_SHA512_RSA)) return AlgoEmpreinte::Sha512;
	return AlgoEmpreinte::Inconnu;
}

size_t empreinte(AlgoEmpreinte a, const uint8_t* p, size_t n, uint8_t sortie[64]) {
	if (a == AlgoEmpreinte::Sha1)   { sha1Octets(p, n, sortie);   return 20; }
	if (a == AlgoEmpreinte::Sha256) { sha256Octets(p, n, sortie); return 32; }
	if (a == AlgoEmpreinte::Sha384) { sha384Octets(p, n, sortie); return 48; }
	if (a == AlgoEmpreinte::Sha512) { sha512Octets(p, n, sortie); return 64; }
	return 0;
}

//! Chaîne d'un attribut de nom (PrintableString, UTF8String, BMPString…).
std::wstring texte(const Tlv& v) {
	std::wstring r;
	if (v.tag == 0x1E) {                                       // BMPString : UTF-16BE
		for (size_t i = 0; i + 1 < v.len; i += 2) r += (wchar_t)((v.val[i] << 8) | v.val[i + 1]);
		return r;
	}
	for (size_t i = 0; i < v.len; ++i) {                       // UTF-8 (ASCII compris)
		const uint8_t c = v.val[i];
		if (c < 0x80) r += (wchar_t)c;
		else if ((c & 0xE0) == 0xC0 && i + 1 < v.len) { r += (wchar_t)(((c & 0x1F) << 6) | (v.val[i + 1] & 0x3F)); ++i; }
		else if ((c & 0xF0) == 0xE0 && i + 2 < v.len) { r += (wchar_t)(((c & 0x0F) << 12) | ((v.val[i + 1] & 0x3F) << 6) | (v.val[i + 2] & 0x3F)); i += 2; }
		else r += L'?';
	}
	return r;
}

//! Valeur d'un attribut (CN, O…) dans un Name.
std::wstring attributNom(const Tlv& nom, const uint8_t* oid, size_t n) {
	for (const Tlv& rdn : enfants(nom))
		for (const Tlv& atv : enfants(rdn)) {
			const std::vector<Tlv> e = enfants(atv);
			if (e.size() >= 2 && estOid(e[0], oid, n)) return texte(e[1]);
		}
	return std::wstring();
}

bool memeOctets(const Tlv& a, const Tlv& b) {
	return a.total == b.total && std::memcmp(a.debut, b.debut, a.total) == 0;
}

// ============================================================ X.509

struct Certificat {
	Tlv entier, tbs, emetteur, sujet, serie;
	Tlv module, exposant;          // clé RSA
	AlgoEmpreinte algoSignature = AlgoEmpreinte::Inconnu;
	const uint8_t* signature = nullptr;
	size_t tailleSignature = 0;
	bool rsa = false;
};

bool analyserCertificat(const Tlv& c, Certificat& r) {
	const std::vector<Tlv> e = enfants(c);
	if (c.tag != 0x30 || e.size() < 3 || e[0].tag != 0x30 || e[2].tag != 0x03 || e[2].len < 2) return false;
	r.entier = c;
	r.tbs = e[0];
	r.algoSignature = algoDe(e[1]);
	r.signature = e[2].val + 1;                               // octet des bits inutilisés
	r.tailleSignature = e[2].len - 1;
	std::vector<Tlv> t = enfants(e[0]);
	size_t i = 0;
	if (i < t.size() && t[i].tag == 0xA0) ++i;                // version
	if (i + 6 > t.size()) return false;
	r.serie = t[i];                                           // serialNumber
	r.emetteur = t[i + 2];                                    // issuer
	r.sujet = t[i + 4];                                       // subject
	const std::vector<Tlv> spki = enfants(t[i + 5]);
	if (spki.size() < 2 || spki[1].tag != 0x03 || spki[1].len < 2) return true;
	const std::vector<Tlv> alg = enfants(spki[0]);
	if (alg.empty() || !EST(alg[0], OID_RSA)) return true;    // clé non RSA : non vérifiable
	Tlv cle;
	if (!lireTlv(spki[1].val + 1, spki[1].len - 1, cle)) return true;
	const std::vector<Tlv> ne = enfants(cle);
	if (ne.size() < 2 || ne[0].tag != 0x02 || ne[1].tag != 0x02) return true;
	r.module = ne[0];
	r.exposant = ne[1];
	r.rsa = true;
	return true;
}

//! La signature de `c` a-t-elle été produite par la clé de `emetteur` ?
bool signePar(const Certificat& c, const Certificat& emetteur) {
	if (!emetteur.rsa || c.algoSignature == AlgoEmpreinte::Inconnu) return false;
	uint8_t h[64];
	const size_t lh = empreinte(c.algoSignature, c.tbs.debut, c.tbs.total, h);
	return RsaVerifierPkcs1(emetteur.module.val, emetteur.module.len,
	                        emetteur.exposant.val, emetteur.exposant.len,
	                        c.signature, c.tailleSignature, c.algoSignature, h, lh);
}

//! Racines embarquées, analysées une fois.
const std::vector<Certificat>& racines() {
	static std::vector<Certificat> r;
	static std::once_flag fait;
	std::call_once(fait, [] {
		for (const RacineMicrosoft& m : RACINES_MICROSOFT) {
			Tlv t; Certificat c;
			if (lireTlv(m.der, m.taille, t) && analyserCertificat(t, c) && c.rsa) r.push_back(c);
		}
	});
	return r;
}

/*! Certificats déjà rattachés à une racine, par empreinte SHA-256 de leur DER.
 *  Les 5 308 catalogues d'une machine sont signés par une poignée de
 *  certificats : sans ce cache, la même chaîne serait revérifiée à chaque fois,
 *  racine RSA-4096 comprise. */
std::set<std::string>& chainesValides() { static std::set<std::string> s; return s; }

std::string cleCert(const Certificat& c) {
	uint8_t h[32];
	sha256Octets(c.entier.debut, c.entier.total, h);
	return std::string((const char*)h, 32);
}

/*! Rattache `feuille` à une racine Microsoft embarquée, par les certificats
 *  fournis avec la signature. Au plus 6 niveaux. */
bool rattacher(const Certificat& feuille, const std::vector<Certificat>& pool) {
	const Certificat* courant = &feuille;
	std::vector<std::string> parcourus;
	for (int niveau = 0; niveau < 6; ++niveau) {
		const std::string cle = cleCert(*courant);
		if (chainesValides().count(cle)) {
			for (const std::string& p : parcourus) chainesValides().insert(p);
			return true;
		}
		parcourus.push_back(cle);
		// Émis par une racine embarquée ?
		for (const Certificat& r : racines()) {
			if (!memeOctets(courant->emetteur, r.sujet)) continue;
			// Le certificat EST la racine (même clé) : rien de plus à vérifier.
			if (courant->rsa && courant->module.len == r.module.len
			    && std::memcmp(courant->module.val, r.module.val, r.module.len) == 0) {
				for (const std::string& p : parcourus) chainesValides().insert(p);
				return true;
			}
			if (signePar(*courant, r)) {
				for (const std::string& p : parcourus) chainesValides().insert(p);
				return true;
			}
		}
		// Sinon, un intermédiaire fourni avec la signature.
		const Certificat* suivant = nullptr;
		for (const Certificat& c : pool) {
			if (&c == courant || !memeOctets(courant->emetteur, c.sujet)) continue;
			if (signePar(*courant, c)) { suivant = &c; break; }
		}
		if (!suivant) return false;
		courant = suivant;
	}
	return false;
}

bool signataireAccepte(const std::wstring& cn, const std::wstring& o) {
	if (o != L"Microsoft Corporation") return false;
	return cn == L"Microsoft Windows" || cn == L"Microsoft Corporation"
	    || cn == L"Microsoft Windows Publisher";
}

} // namespace

// ============================================================ PKCS#7

SignatureVerifiee VerifierPkcs7(const uint8_t* donnees, size_t taille) {
	SignatureVerifiee r;
	Tlv ci;
	if (!lireTlv(donnees, taille, ci) || ci.tag != 0x30) { r.motif = "ContentInfo illisible"; return r; }
	std::vector<Tlv> e = enfants(ci);
	if (e.size() < 2 || !EST(e[0], OID_SIGNED_DATA) || e[1].tag != 0xA0) { r.motif = "pas un SignedData"; return r; }
	std::vector<Tlv> w = enfants(e[1]);
	if (w.empty() || w[0].tag != 0x30) { r.motif = "SignedData illisible"; return r; }
	const std::vector<Tlv> sd = enfants(w[0]);
	// version, digestAlgorithms, encapContentInfo, [0] certificats, [1] crls, signerInfos
	if (sd.size() < 4) { r.motif = "SignedData incomplet"; return r; }
	const std::vector<Tlv> eci = enfants(sd[2]);
	if (eci.size() < 2 || eci[0].tag != 0x06 || eci[1].tag != 0xA0) { r.motif = "contenu absent"; return r; }
	r.oidContenu.assign((const char*)eci[0].val, eci[0].len);
	const std::vector<Tlv> cc = enfants(eci[1]);
	if (cc.empty()) { r.motif = "contenu vide"; return r; }
	r.contenu = cc[0].val;
	r.tailleContenu = cc[0].len;

	std::vector<Certificat> pool;
	const Tlv* infos = nullptr;
	for (size_t i = 3; i < sd.size(); ++i) {
		if (sd[i].tag == 0xA0)
			for (const Tlv& c : enfants(sd[i])) { Certificat x; if (analyserCertificat(c, x)) pool.push_back(x); }
		else if (sd[i].tag == 0x31) infos = &sd[i];
	}
	if (!infos) { r.motif = "aucun signataire"; return r; }
	const std::vector<Tlv> signataires = enfants(*infos);
	if (signataires.empty()) { r.motif = "aucun signataire"; return r; }
	const std::vector<Tlv> si = enfants(signataires[0]);
	// version, issuerAndSerialNumber, digestAlgorithm, [0] attributs, digestEncryptionAlgorithm, encryptedDigest
	if (si.size() < 5) { r.motif = "SignerInfo incomplet"; return r; }
	const std::vector<Tlv> ias = enfants(si[1]);
	if (ias.size() < 2) { r.motif = "émetteur du signataire illisible"; return r; }
	const AlgoEmpreinte algo = algoDe(si[2]);
	if (algo == AlgoEmpreinte::Inconnu) { r.motif = "algorithme d'empreinte non pris en charge"; return r; }
	size_t k = 3;
	const Tlv* attributs = nullptr;
	if (si[k].tag == 0xA0) attributs = &si[k++];
	if (k + 1 >= si.size() || si[k + 1].tag != 0x04) { r.motif = "signature absente"; return r; }
	const Tlv& signature = si[k + 1];
	if (!attributs) { r.motif = "attributs authentifiés absents"; return r; }

	// 1. L'empreinte du contenu doit être celle annoncée dans les attributs.
	uint8_t hc[64];
	const size_t lhc = empreinte(algo, r.contenu, r.tailleContenu, hc);
	bool empreinteOk = false;
	for (const Tlv& a : enfants(*attributs)) {
		const std::vector<Tlv> av = enfants(a);
		if (av.size() < 2 || !EST(av[0], OID_MESSAGE_DIGEST)) continue;
		const std::vector<Tlv> vals = enfants(av[1]);
		if (!vals.empty() && vals[0].tag == 0x04 && vals[0].len == lhc
		    && std::memcmp(vals[0].val, hc, lhc) == 0) empreinteOk = true;
	}
	if (!empreinteOk) { r.motif = "empreinte du contenu non conforme"; return r; }

	// 2. La signature porte sur les attributs, réencodés en SET (0x31).
	std::vector<uint8_t> signes(attributs->debut, attributs->debut + attributs->total);
	signes[0] = 0x31;
	uint8_t ha[64];
	const size_t lha = empreinte(algo, signes.data(), signes.size(), ha);

	const Certificat* signataire = nullptr;
	for (const Certificat& c : pool)
		if (memeOctets(c.emetteur, ias[0]) && memeOctets(c.serie, ias[1])) { signataire = &c; break; }
	if (!signataire || !signataire->rsa) { r.motif = "certificat signataire absent ou non RSA"; return r; }
	if (!RsaVerifierPkcs1(signataire->module.val, signataire->module.len,
	                      signataire->exposant.val, signataire->exposant.len,
	                      signature.val, signature.len, algo, ha, lha)) {
		r.motif = "signature RSA invalide"; return r;
	}
	// 3. La chaîne jusqu'à une racine Microsoft embarquée.
	if (!rattacher(*signataire, pool)) { r.motif = "chaîne non rattachée à une racine Microsoft"; return r; }

	r.valide = true;
	r.signataire = attributNom(signataire->sujet, OID_CN, sizeof(OID_CN));
	const std::wstring o = attributNom(signataire->sujet, OID_O, sizeof(OID_O));
	r.signataireAccepte = signataireAccepte(r.signataire, o);
	if (!r.signataireAccepte) r.motif = "signataire non retenu";
	return r;
}

// ============================================================ catalogues

namespace {

/*! Empreinte portée par un SpcIndirectDataContent : SEQUENCE { data,
 *  messageDigest DigestInfo SEQUENCE { AlgorithmIdentifier, OCTET STRING } }. */
bool empreinteIndirecte(const Tlv& spc, std::string& sortie) {
	const std::vector<Tlv> e = enfants(spc);
	if (e.size() < 2) return false;
	const std::vector<Tlv> di = enfants(e[1]);
	if (di.size() < 2 || di[1].tag != 0x04 || (di[1].len != 20 && di[1].len != 32)) return false;
	sortie.assign((const char*)di[1].val, di[1].len);
	return true;
}

} // namespace

bool IndexCatalogues::ajouter(const std::wstring& nom, const uint8_t* octets, size_t taille) {
	const SignatureVerifiee s = VerifierPkcs7(octets, taille);
	if (!s.valide || !s.signataireAccepte
	    || s.oidContenu != std::string((const char*)OID_CTL, sizeof(OID_CTL))) {
		++refuses_;
		return false;
	}
	// CertificateTrustList : on cherche la liste des sujets — une SEQUENCE dont
	// les éléments sont des SEQUENCE { OCTET STRING, SET }.
	Tlv ctl;
	ctl.tag = 0x30; ctl.val = s.contenu; ctl.len = s.tailleContenu;
	const uint32_t rang = (uint32_t)noms_.size();
	size_t indexees = 0;
	for (const Tlv& champ : enfants(ctl)) {
		if (champ.tag != 0x30) continue;
		for (const Tlv& sujet : enfants(champ)) {
			const std::vector<Tlv> se = enfants(sujet);
			if (se.size() < 2 || se[0].tag != 0x04 || se[1].tag != 0x31) continue;
			for (const Tlv& attribut : enfants(se[1])) {
				const std::vector<Tlv> av = enfants(attribut);
				if (av.size() < 2 || !EST(av[0], OID_SPC_INDIRECT)) continue;
				for (const Tlv& v : enfants(av[1])) {
					std::string h;
					if (empreinteIndirecte(v, h)) { index_.emplace(h, rang); ++indexees; }
				}
			}
		}
	}
	if (indexees == 0) { ++refuses_; return false; }
	noms_.push_back(nom);
	return true;
}

const std::wstring* IndexCatalogues::chercher(const uint8_t* e, size_t n) const {
	const auto it = index_.find(std::string((const char*)e, n));
	return it == index_.end() ? nullptr : &noms_[it->second];
}

// ============================================================ PE en flux

namespace {
inline uint16_t lu16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t lu32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
const size_t TETE = 64 * 1024;                  // en-têtes attendus dans les 64 premiers Kio
const size_t CERTIFICATS_MAX = 4 * 1024 * 1024; // table de certificats : 4 Mio au plus
}

int AnalyseurPe::overflow(int c) {
	if (c != traits_type::eof()) { const uint8_t o = (uint8_t)c; recevoir(&o, 1); }
	return traits_type::not_eof(c);
}

std::streamsize AnalyseurPe::xsputn(const char* s, std::streamsize n) {
	recevoir(reinterpret_cast<const uint8_t*>(s), (size_t)n);
	return n;
}

void AnalyseurPe::recevoir(const uint8_t* p, size_t n) {
	if (termine_ || n == 0) return;
	if (!decide_) {
		const size_t prendre = std::min(n, TETE - tete_.size());
		tete_.insert(tete_.end(), p, p + prendre);
		p += prendre; n -= prendre;
		if (tete_.size() < TETE) return;
		decide_ = true;
		estPe_ = analyserEntetes();
		if (estPe_) traiter(tete_.data(), tete_.size());
		tete_.clear(); tete_.shrink_to_fit();
	}
	if (estPe_ && n) traiter(p, n);
}

bool AnalyseurPe::analyserEntetes() {
	const uint8_t* t = tete_.data();
	const size_t n = tete_.size();
	if (n < 0x40 || t[0] != 'M' || t[1] != 'Z') return false;
	const uint32_t pe = lu32(t + 0x3C);
	if (pe > n - 24 || std::memcmp(t + pe, "PE\0\0", 4) != 0) return false;
	const uint32_t opt = pe + 24;
	const uint16_t tailleOpt = lu16(t + pe + 20);
	if (opt + tailleOpt > n || tailleOpt < 2) return false;
	const uint16_t magic = lu16(t + opt);
	size_t repertoires;
	if (magic == 0x10B) repertoires = opt + 96;         // PE32
	else if (magic == 0x20B) repertoires = opt + 112;   // PE32+
	else return false;
	if (repertoires > opt + tailleOpt) return false;
	const uint32_t nbRep = lu32(t + repertoires - 4);   // NumberOfRvaAndSizes
	checksum_ = opt + 64;
	entreeCert_ = repertoires + 4 * 8;                  // entrée 4 : table de certificats
	if (nbRep <= 4 || entreeCert_ + 8 > opt + tailleOpt) { entreeCert_ = 0; return true; }
	debutCert_ = lu32(t + entreeCert_);                 // position dans le FICHIER
	finCert_ = debutCert_ + lu32(t + entreeCert_ + 4);
	if (finCert_ == debutCert_) debutCert_ = finCert_ = 0;
	return true;
}

void AnalyseurPe::traiter(const uint8_t* p, size_t n) {
	// Découpe [position_, position_ + n) selon les trois zones exclues.
	while (n) {
		const uint64_t pos = position_;
		uint64_t jusque = pos + n;
		bool exclu = false;
		auto zone = [&](uint64_t debut, uint64_t fin) {
			if (fin <= debut) return;
			if (pos >= debut && pos < fin) { exclu = true; jusque = std::min(jusque, fin); }
			else if (pos < debut) jusque = std::min(jusque, debut);
		};
		zone(checksum_, checksum_ + 4);
		if (entreeCert_) zone(entreeCert_, entreeCert_ + 8);
		const bool dansCert = debutCert_ && pos >= debutCert_ && pos < finCert_;
		zone(debutCert_, finCert_);
		const size_t m = (size_t)(jusque - pos);
		if (!exclu) { h1_.update(p, m); h256_.update(p, m); }
		else if (dansCert && certificats_.size() + m <= CERTIFICATS_MAX)
			certificats_.insert(certificats_.end(), p, p + m);
		p += m; n -= m; position_ += m;
	}
}

void AnalyseurPe::terminer() {
	if (termine_) return;
	if (!decide_) {                                     // fichier de moins de 64 Kio
		decide_ = true;
		estPe_ = analyserEntetes();
		if (estPe_) traiter(tete_.data(), tete_.size());
		tete_.clear();
	}
	termine_ = true;
	if (!estPe_) return;
	// Deux variantes : telle quelle, et complétée de zéros à un multiple de 8
	// (règle de certaines implémentations pour un fichier non signé).
	Sha1Stream c1 = h1_;
	Sha256Stream c256 = h256_;
	const uint64_t hache = position_ - (finCert_ - debutCert_);
	static const uint8_t zeros[8] = { 0 };
	const size_t complement = (size_t)((8 - (hache % 8)) % 8);
	c1.update(zeros, complement);
	c256.update(zeros, complement);
	h1_.digest(sha1_);
	h256_.digest(sha256_);
	c1.digest(sha1c_);
	c256.digest(sha256c_);
}

// ============================================================ verdict

VerdictMicrosoft EvaluerPe(const AnalyseurPe& pe, const IndexCatalogues& catalogues) {
	VerdictMicrosoft v;
	if (!pe.estPe()) { v.motif = "pas un PE"; return v; }

	// 1. Catalogues : l'empreinte, sous l'une de ses formes, y figure-t-elle ?
	for (const auto& e : { std::make_pair(pe.sha256(), 32), std::make_pair(pe.sha1(), 20),
	                       std::make_pair(pe.sha256Complete(), 32), std::make_pair(pe.sha1Complete(), 20) }) {
		if (const std::wstring* cat = catalogues.chercher(e.first, (size_t)e.second)) {
			v.microsoft = true;
			v.source = L"catalogue " + *cat;
			return v;
		}
	}

	// 2. Signature intégrée : WIN_CERTIFICATE { dwLength, wRevision, wCertificateType, bCertificate }.
	const std::vector<uint8_t>& t = pe.tableCertificats();
	if (t.size() < 8) { v.motif = "non signé (ni catalogue, ni signature intégrée)"; return v; }
	const uint32_t longueur = lu32(t.data());
	const uint16_t type = lu16(t.data() + 6);
	if (type != 0x0002 || longueur < 8 || longueur > t.size()) { v.motif = "table de certificats inattendue"; return v; }
	const SignatureVerifiee s = VerifierPkcs7(t.data() + 8, longueur - 8);
	if (!s.valide) { v.motif = s.motif; return v; }
	if (s.oidContenu != std::string((const char*)OID_SPC_INDIRECT, sizeof(OID_SPC_INDIRECT))) {
		v.motif = "contenu signé inattendu"; return v;
	}
	// Le contenu signé porte l'empreinte Authenticode du fichier : elle doit
	// être celle calculée ici, faute de quoi la signature est authentique mais
	// porte sur un AUTRE fichier.
	Tlv spc;
	spc.tag = 0x30; spc.val = s.contenu; spc.len = s.tailleContenu;
	std::string annoncee;
	if (!empreinteIndirecte(spc, annoncee)) { v.motif = "empreinte signée illisible"; return v; }
	const bool conforme =
		(annoncee.size() == 32 && std::memcmp(annoncee.data(), pe.sha256(), 32) == 0)
	 || (annoncee.size() == 20 && std::memcmp(annoncee.data(), pe.sha1(), 20) == 0);
	if (!conforme) { v.motif = "fichier modifié depuis sa signature"; return v; }
	v.signataire = s.signataire;
	if (!s.signataireAccepte) { v.motif = "signataire non retenu : " + std::string(s.signataire.begin(), s.signataire.end()); return v; }
	v.microsoft = true;
	v.source = L"signature intégrée";
	return v;
}
