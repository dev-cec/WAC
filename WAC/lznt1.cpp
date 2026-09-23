#include "lznt1.h"
#include <cstring>

/*  lznt1.cpp — see lznt1.h. Algorithm consistent with libyal's reference
 *  implementation (libfwnt); the comments do not restate the format, they mark
 *  its two traps: the variable split of back-references, and overlapping
 *  copies.
 */

namespace {

//! One compressed chunk: at most 4096 expanded bytes.
const size_t TAILLE_MORCEAU = 4096;

/*! Expands one compressed chunk.
 *  @param pos position in `compresse`, updated
 *  @return bytes written to `sortie`
 */
size_t detendreMorceau(const uint8_t* compresse, size_t tailleCompressee, size_t& pos,
                       size_t tailleMorceau, uint8_t* sortie, size_t tailleSortie) {
	size_t ecrits = 0;

	/*  VARIABLE SPLIT. As long as the chunk's output does not exceed the
	 *  threshold, the distance takes 4 bits and the length 12. Each time the
	 *  threshold is crossed, the distance gains a bit and the length loses one.
	 *  Fixing these values produces wrong data without any error. */
	unsigned decalage = 12;          // position of the distance field
	uint16_t masqueTaille = 0x0fff;  // length field
	size_t   seuil = 16;

	while (tailleMorceau > 0) {
		if (pos >= tailleCompressee) break;
		uint8_t drapeaux = compresse[pos++];
		tailleMorceau -= 1;

		for (int bit = 0; bit < 8; ++bit) {
			if (drapeaux & 0x01) {
				// Back-reference: 2 bytes, little-endian.
				if (pos + 1 >= tailleCompressee) return ecrits;
				if (tailleMorceau < 2) return ecrits;
				const uint16_t tuple = (uint16_t)(compresse[pos] | (compresse[pos + 1] << 8));
				pos += 2;
				tailleMorceau -= 2;

				const size_t distance = (size_t)(tuple >> decalage) + 1;
				size_t longueur      = (size_t)(tuple & masqueTaille) + 3;
				if (distance > ecrits) return ecrits;       // before the start: corrupt stream

				/*  BYTE-BY-BYTE COPY, not memcpy: the ranges OVERLAP as soon as the
				 *  distance is smaller than the length, and that is the normal case —
				 *  it is how the format encodes a repetition. memcpy would return
				 *  something else. */
				size_t source = ecrits - distance;
				while (longueur-- > 0) {
					if (ecrits >= tailleSortie) return ecrits;
					sortie[ecrits++] = sortie[source++];
				}
			}
			else {
				if (pos >= tailleCompressee || tailleMorceau == 0) return ecrits;
				if (ecrits >= tailleSortie) return ecrits;
				sortie[ecrits++] = compresse[pos++];
				tailleMorceau -= 1;
			}
			drapeaux >>= 1;
			if (tailleMorceau == 0) break;

			// Re-evaluate the split after EACH item.
			while (ecrits > seuil) {
				if (decalage == 0) return ecrits;          // inconsistent stream
				--decalage;
				masqueTaille >>= 1;
				seuil <<= 1;
			}
		}
	}
	return ecrits;
}

} // namespace

size_t Lznt1Detendre(const uint8_t* compresse, size_t tailleCompressee,
                     uint8_t* sortie, size_t tailleSortie) {
	if (!compresse || !sortie || tailleCompressee < 2 || tailleSortie == 0) return 0;

	size_t pos = 0, ecrits = 0;
	while (pos < tailleCompressee && ecrits < tailleSortie) {
		if (pos + 1 >= tailleCompressee) break;
		const uint16_t entete = (uint16_t)(compresse[pos] | (compresse[pos + 1] << 8));
		pos += 2;
		if (entete == 0) break;                 // end of stream

		const size_t taille = (size_t)(entete & 0x0fff) + 1;

		if (entete & 0x8000) {
			ecrits += detendreMorceau(compresse, tailleCompressee, pos, taille,
			                          sortie + ecrits, tailleSortie - ecrits);
		}
		else {
			// Chunk stored as is: compression had gained nothing.
			const size_t n = (taille < tailleCompressee - pos) ? taille : (tailleCompressee - pos);
			const size_t m = (n < tailleSortie - ecrits) ? n : (tailleSortie - ecrits);
			std::memcpy(sortie + ecrits, compresse + pos, m);
			pos    += n;
			ecrits += m;
		}
		// A chunk yields at most 4096 bytes; beyond that, the stream is inconsistent.
		if (ecrits > tailleSortie) return tailleSortie;
	}
	return ecrits;
}
