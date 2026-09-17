#include "xpress.h"
#include <cstring>

/*  xpress.cpp — voir xpress.h. Les commentaires ici ne redisent pas le format :
 *  ils marquent les deux endroits où une implémentation se trompe sans erreur.
 */

namespace {

const size_t TAILLE_TABLE = 256;   //!< 512 longueurs de code sur 4 bits
const int    SYMBOLES     = 512;
const int    LONGUEUR_MAX = 15;

/*! Train de bits du format : mots de 16 bits en petit boutien, bits consommés
 *  du plus significatif au moins significatif.
 *
 *  Le curseur d'octets est PARTAGÉ avec la lecture des longueurs étendues : les
 *  deux avancent dans le même flux, et c'est voulu par le format.
 */
class TrainDeBits {
public:
	TrainDeBits(const uint8_t* d, size_t taille, size_t depart)
		: d_(d), taille_(taille), octet_(depart) {}

	//! Garantit au moins `n` bits disponibles, en complétant de zéros en fin de flux.
	void remplir(unsigned n) {
		while (bits_ < n) {
			if (taille_ < 2 || octet_ > taille_ - 2) {
				// Fin du flux : on complète de zéros plutôt que de lire dehors.
				tampon_ <<= 16;
				bits_ += 16;
			}
			else {
				/*  Le mot est en PETIT BOUTIEN : l'octet de poids fort du mot est
				    d_[octet_+1]. Il entre d'abord dans le tampon, de sorte que la
				    consommation par le haut rende les bits dans le bon ordre. */
				tampon_ = (tampon_ << 8) | d_[octet_ + 1];
				tampon_ = (tampon_ << 8) | d_[octet_];
				bits_ += 16;
				octet_ += 2;
			}
		}
	}

	//! Prend les `n` bits de poids fort du tampon.
	uint32_t valeur(unsigned n) {
		if (n == 0) return 0;
		if (n > 32) return 0;
		remplir(n);
		uint32_t v = tampon_;
		if (n < 32) v >>= (bits_ - n);
		bits_ -= n;
		if (bits_ == 0) tampon_ = 0;
		else            tampon_ &= 0xFFFFFFFFu >> (32 - bits_);
		return v;
	}

	//! Octet suivant du flux, sur le curseur partagé.
	bool octetSuivant(uint8_t* v) {
		if (octet_ >= taille_) return false;
		*v = d_[octet_++];
		return true;
	}
	bool mot16(uint32_t* v) {
		if (taille_ < 2 || octet_ > taille_ - 2) return false;
		*v = (uint32_t)(d_[octet_] | (d_[octet_ + 1] << 8));
		octet_ += 2;
		return true;
	}
	bool mot32(uint32_t* v) {
		if (taille_ < 4 || octet_ > taille_ - 4) return false;
		*v = (uint32_t)d_[octet_] | ((uint32_t)d_[octet_ + 1] << 8)
		   | ((uint32_t)d_[octet_ + 2] << 16) | ((uint32_t)d_[octet_ + 3] << 24);
		octet_ += 4;
		return true;
	}
	unsigned disponibles() const { return bits_; }

private:
	const uint8_t* d_;
	size_t   taille_;
	size_t   octet_;
	uint32_t tampon_ = 0;
	unsigned bits_ = 0;
};

/*! Arbre de Huffman canonique, construit à partir des longueurs de code.
 *
 *  Les codes sont attribués par longueur croissante puis par numéro de symbole
 *  croissant : c'est la convention du format, et la seule qui rende le flux
 *  décodable.
 */
class Huffman {
public:
	bool construire(const uint8_t* longueurs) {
		std::memset(nb_, 0, sizeof(nb_));
		int utilises = 0;
		for (int s = 0; s < SYMBOLES; ++s) {
			const uint8_t l = longueurs[s];
			if (l > LONGUEUR_MAX) return false;
			if (l) { ++nb_[l]; ++utilises; }
		}
		if (utilises == 0) return false;

		int code = 0, decalage = 0;
		for (int l = 1; l <= LONGUEUR_MAX; ++l) {
			premier_[l] = code;
			debut_[l] = decalage;
			code = (code + nb_[l]) << 1;
			decalage += nb_[l];
		}
		// Symboles triés par (longueur, numéro).
		int curseur[LONGUEUR_MAX + 1];
		for (int l = 0; l <= LONGUEUR_MAX; ++l) curseur[l] = debut_[l];
		for (int s = 0; s < SYMBOLES; ++s) {
			const uint8_t l = longueurs[s];
			if (l) symboles_[curseur[l]++] = (uint16_t)s;
		}
		return true;
	}

	//! Décode un symbole, ou -1 si aucun code ne correspond.
	int decoder(TrainDeBits& bits) const {
		int code = 0;
		for (int l = 1; l <= LONGUEUR_MAX; ++l) {
			code = (code << 1) | (int)bits.valeur(1);
			if (nb_[l] && (code - premier_[l]) < nb_[l] && (code - premier_[l]) >= 0)
				return symboles_[debut_[l] + (code - premier_[l])];
		}
		return -1;
	}

private:
	int      nb_[LONGUEUR_MAX + 1] = { 0 };
	int      premier_[LONGUEUR_MAX + 1] = { 0 };
	int      debut_[LONGUEUR_MAX + 1] = { 0 };
	uint16_t symboles_[SYMBOLES] = { 0 };
};

} // namespace

size_t XpressHuffmanDetendre(const uint8_t* compresse, size_t tailleCompressee,
                             uint8_t* sortie, size_t tailleSortie) {
	if (!compresse || !sortie || tailleSortie == 0) return 0;
	// La table seule fait 256 octets ; en dessous, il n'y a pas de morceau.
	if (tailleCompressee <= TAILLE_TABLE) return 0;

	uint8_t longueurs[SYMBOLES];
	for (size_t i = 0; i < TAILLE_TABLE; ++i) {
		longueurs[2 * i]     = (uint8_t)(compresse[i] & 0x0F);
		longueurs[2 * i + 1] = (uint8_t)(compresse[i] >> 4);
	}
	Huffman arbre;
	if (!arbre.construire(longueurs)) return 0;

	TrainDeBits bits(compresse, tailleCompressee, TAILLE_TABLE);
	bits.remplir(32);                       // amorçage, comme le format l'exige

	size_t ecrits = 0;
	while (ecrits < tailleSortie) {
		const int symbole = arbre.decoder(bits);
		if (symbole < 0) break;             // code inconnu : flux incohérent

		if (symbole < 256) sortie[ecrits++] = (uint8_t)symbole;

		/*  COMPLÉMENT À 16 BITS APRÈS CHAQUE SYMBOLE, littéraux compris, et
		    AVANT la lecture d'une référence arrière. Ce n'est pas une
		    optimisation : le complément fait avancer le curseur d'octets de
		    deux, et ce curseur est celui où se lisent les longueurs étendues.
		    Ne compléter qu'après les références désynchronise le morceau —
		    mesuré : 16 morceaux conformes sur 137, les autres faux sans erreur. */
		if (bits.disponibles() < 16) bits.remplir(16);

		if (symbole < 256) continue;

		const int reste = symbole - 256;
		uint32_t longueur = (uint32_t)(reste & 0x0F);
		const unsigned bitsDistance = (unsigned)(reste >> 4);

		// La distance se lit AVANT la longueur étendue : l'ordre est imposé.
		uint32_t distance = bits.valeur(bitsDistance);
		distance = (1u << bitsDistance) | distance;

		if (longueur == 15) {
			/*  LONGUEUR ÉTENDUE, lue en OCTETS sur le curseur du train de bits.
			    Trois paliers : un octet, puis un mot de 16 bits, puis un mot de
			    32 bits. Un curseur séparé désynchroniserait tout le morceau. */
			uint8_t oct = 0;
			if (!bits.octetSuivant(&oct)) break;
			longueur = (uint32_t)oct + 15;
			if (longueur == 270) {
				uint32_t m = 0;
				if (!bits.mot16(&m)) break;
				longueur = m;
				if (longueur == 0) {
					if (!bits.mot32(&longueur)) break;
				}
			}
		}
		longueur += 3;

		if (distance > ecrits) break;       // avant le début : flux faux
		if (longueur > tailleSortie - ecrits)
			longueur = (uint32_t)(tailleSortie - ecrits);

		/*  Copie octet par octet : les zones se RECOUVRENT dès que la distance
		    est inférieure à la longueur, ce qui est le cas normal — c'est ainsi
		    que le format encode une répétition. */
		size_t source = ecrits - distance;
		while (longueur-- > 0) sortie[ecrits++] = sortie[source++];
	}
	return ecrits;
}
