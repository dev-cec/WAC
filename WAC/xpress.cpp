#include "xpress.h"
#include <cstring>

/*  xpress.cpp — see xpress.h. The comments here do not restate the format: they
 *  mark the two places where an implementation goes wrong without an error.
 */

namespace {

const size_t TAILLE_TABLE = 256;   //!< 512 code lengths on 4 bits
const int    SYMBOLES     = 512;
const int    LONGUEUR_MAX = 15;

/*! The format's bit stream: 16-bit little-endian words, bits consumed from
 *  most to least significant.
 *
 *  The byte cursor is SHARED with the reading of extended lengths: both move
 *  through the same stream, as the format intends.
 */
class TrainDeBits {
public:
	TrainDeBits(const uint8_t* d, size_t taille, size_t depart)
		: d_(d), taille_(taille), octet_(depart) {}

	//! Ensures at least `n` bits are available, padding with zeros at the end of the stream.
	void remplir(unsigned n) {
		while (bits_ < n) {
			if (taille_ < 2 || octet_ > taille_ - 2) {
				// End of stream: pad with zeros rather than reading outside.
				tampon_ <<= 16;
				bits_ += 16;
			}
			else {
				/*  The word is LITTLE-ENDIAN: its most significant byte is d_[octet_+1].
				    It goes into the buffer first, so that consuming from the top returns the
				    bits in the right order. */
				tampon_ = (tampon_ << 8) | d_[octet_ + 1];
				tampon_ = (tampon_ << 8) | d_[octet_];
				bits_ += 16;
				octet_ += 2;
			}
		}
	}

	//! Takes the `n` most significant bits of the buffer.
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

	//! Next byte of the stream, on the shared cursor.
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

/*! Canonical Huffman tree, built from the code lengths.
 *
 *  Codes are assigned by increasing length, then by increasing symbol number:
 *  that is the format's convention, and the only one that makes the stream
 *  decodable.
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
		// Symbols sorted by (length, number).
		int curseur[LONGUEUR_MAX + 1];
		for (int l = 0; l <= LONGUEUR_MAX; ++l) curseur[l] = debut_[l];
		for (int s = 0; s < SYMBOLES; ++s) {
			const uint8_t l = longueurs[s];
			if (l) symboles_[curseur[l]++] = (uint16_t)s;
		}
		return true;
	}

	//! Decodes a symbol, or -1 if no code matches.
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
	// The table alone takes 256 bytes; below that there is no chunk.
	if (tailleCompressee <= TAILLE_TABLE) return 0;

	uint8_t longueurs[SYMBOLES];
	for (size_t i = 0; i < TAILLE_TABLE; ++i) {
		longueurs[2 * i]     = (uint8_t)(compresse[i] & 0x0F);
		longueurs[2 * i + 1] = (uint8_t)(compresse[i] >> 4);
	}
	Huffman arbre;
	if (!arbre.construire(longueurs)) return 0;

	TrainDeBits bits(compresse, tailleCompressee, TAILLE_TABLE);
	bits.remplir(32);                       // priming, as the format requires

	size_t ecrits = 0;
	while (ecrits < tailleSortie) {
		const int symbole = arbre.decoder(bits);
		if (symbole < 0) break;             // unknown code: inconsistent stream

		if (symbole < 256) sortie[ecrits++] = (uint8_t)symbole;

		/*  TOP UP TO 16 BITS AFTER EVERY SYMBOL, literals included, and BEFORE
		    reading a back-reference. This is not an optimisation: the top-up
		    advances the byte cursor by two, and that cursor is the one extended
		    lengths are read from. Topping up only after back-references
		    desynchronises the chunk — measured: 16 chunks correct out of 137, the
		    others wrong without any error. */
		if (bits.disponibles() < 16) bits.remplir(16);

		if (symbole < 256) continue;

		const int reste = symbole - 256;
		uint32_t longueur = (uint32_t)(reste & 0x0F);
		const unsigned bitsDistance = (unsigned)(reste >> 4);

		// The distance is read BEFORE the extended length: the order is imposed.
		uint32_t distance = bits.valeur(bitsDistance);
		distance = (1u << bitsDistance) | distance;

		if (longueur == 15) {
			/*  EXTENDED LENGTH, read as BYTES on the bit stream's cursor. Three
			    levels: one byte, then a 16-bit word, then a 32-bit word. A separate
			    cursor would desynchronise the whole chunk. */
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

		if (distance > ecrits) break;       // before the start: corrupt stream
		if (longueur > tailleSortie - ecrits)
			longueur = (uint32_t)(tailleSortie - ecrits);

		/*  Byte-by-byte copy: the ranges OVERLAP as soon as the distance is
		    smaller than the length, which is the normal case — it is how the format
		    encodes a repetition. */
		size_t source = ecrits - distance;
		while (longueur-- > 0) sortie[ecrits++] = sortie[source++];
	}
	return ecrits;
}
