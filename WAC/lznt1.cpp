#include "lznt1.h"
#include <cstring>

/*  lznt1.cpp — voir lznt1.h. Algorithme conforme à l'implémentation de
 *  référence de libyal (libfwnt) ; les commentaires ne redisent pas le format,
 *  ils marquent les deux pièges : le découpage variable des références
 *  arrière, et le recouvrement des copies.
 */

namespace {

//! Un morceau compressé : au plus 4096 octets détendus.
const size_t TAILLE_MORCEAU = 4096;

/*! Détend un morceau compressé.
 *  @param pos avancée dans `compresse`, mise à jour
 *  @return octets écrits dans `sortie`
 */
size_t detendreMorceau(const uint8_t* compresse, size_t tailleCompressee, size_t& pos,
                       size_t tailleMorceau, uint8_t* sortie, size_t tailleSortie) {
	size_t ecrits = 0;

	/*  DÉCOUPAGE VARIABLE. Tant que la sortie du morceau ne dépasse pas le
	 *  seuil, la distance tient sur 4 bits et la longueur sur 12. À chaque
	 *  franchissement du seuil, la distance gagne un bit et la longueur en perd
	 *  un. Figer ces valeurs produit des données fausses sans aucune erreur. */
	unsigned decalage = 12;          // position du champ de distance
	uint16_t masqueTaille = 0x0fff;  // champ de longueur
	size_t   seuil = 16;

	while (tailleMorceau > 0) {
		if (pos >= tailleCompressee) break;
		uint8_t drapeaux = compresse[pos++];
		tailleMorceau -= 1;

		for (int bit = 0; bit < 8; ++bit) {
			if (drapeaux & 0x01) {
				// Référence arrière : 2 octets, petit boutien.
				if (pos + 1 >= tailleCompressee) return ecrits;
				if (tailleMorceau < 2) return ecrits;
				const uint16_t tuple = (uint16_t)(compresse[pos] | (compresse[pos + 1] << 8));
				pos += 2;
				tailleMorceau -= 2;

				const size_t distance = (size_t)(tuple >> decalage) + 1;
				size_t longueur      = (size_t)(tuple & masqueTaille) + 3;
				if (distance > ecrits) return ecrits;       // avant le début : flux faux

				/*  COPIE OCTET PAR OCTET, et non memcpy : les zones se
				 *  RECOUVRENT dès que la distance est inférieure à la longueur,
				 *  et c'est le cas normal — c'est ainsi que le format encode une
				 *  répétition. Un memcpy rendrait autre chose. */
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

			// Réévaluation du découpage après CHAQUE élément.
			while (ecrits > seuil) {
				if (decalage == 0) return ecrits;          // flux incohérent
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
		if (entete == 0) break;                 // fin du flux

		const size_t taille = (size_t)(entete & 0x0fff) + 1;

		if (entete & 0x8000) {
			ecrits += detendreMorceau(compresse, tailleCompressee, pos, taille,
			                          sortie + ecrits, tailleSortie - ecrits);
		}
		else {
			// Morceau stocké tel quel : la compression n'avait rien gagné.
			const size_t n = (taille < tailleCompressee - pos) ? taille : (tailleCompressee - pos);
			const size_t m = (n < tailleSortie - ecrits) ? n : (tailleSortie - ecrits);
			std::memcpy(sortie + ecrits, compresse + pos, m);
			pos    += n;
			ecrits += m;
		}
		// Un morceau rend au plus 4096 octets ; au-delà, le flux est incohérent.
		if (ecrits > tailleSortie) return tailleSortie;
	}
	return ecrits;
}
