#include "sha.h"
#include <fstream>
#include <cstring>
#include <vector>
#include <filesystem>

/*  sha.cpp — voir sha.h. Les deux algorithmes suivent FIPS 180-4 ; les
 *  commentaires ne redisent pas la norme, ils signalent les seuls endroits où
 *  une implémentation se trompe : le remplissage final et la longueur en bits,
 *  écrite en GROS boutien alors que tout le reste du projet lit du petit
 *  boutien.
 */

namespace {

inline uint32_t rotl(uint32_t v, int n){ return (uint32_t)((v << n) | (v >> (32 - n))); }
inline uint32_t rotr(uint32_t v, int n){ return (uint32_t)((v >> n) | (v << (32 - n))); }

//! Mot de 32 bits en gros boutien, l'ordre des deux algorithmes.
inline uint32_t be32(const uint8_t* p){
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
	     | ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

const uint32_t K256[64] = {
	0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
	0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
	0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
	0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
	0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
	0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
	0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
	0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

//! Empreinte en hexadécimal majuscule, convention du projet (cf. Md5Stream).
std::wstring enHexa(const uint8_t* octets, size_t n){
	static const wchar_t* d = L"0123456789ABCDEF";
	std::wstring r;
	r.reserve(n * 2);
	for (size_t i = 0; i < n; ++i){
		r.push_back(d[octets[i] >> 4]);
		r.push_back(d[octets[i] & 0x0F]);
	}
	return r;
}

/*! Remplissage commun aux deux algorithmes : un octet 0x80, des zéros, puis la
 *  longueur du message EN BITS sur 8 octets gros boutien.
 *  @param dansBloc octets déjà dans le bloc courant
 *  @param bloc bloc de travail de 64 octets
 *  @param octets longueur totale du message, en octets
 *  @param comprimer fonction de compression d'un bloc
 */
template <typename F>
void terminer(size_t& dansBloc, uint8_t* bloc, uint64_t octets, F comprimer){
	bloc[dansBloc++] = 0x80;
	// La longueur occupe les 8 derniers octets : s'il n'y a plus la place, on
	// clôt ce bloc et la longueur part dans le suivant.
	if (dansBloc > 56){
		std::memset(bloc + dansBloc, 0, 64 - dansBloc);
		comprimer(bloc);
		dansBloc = 0;
	}
	std::memset(bloc + dansBloc, 0, 56 - dansBloc);
	const uint64_t bits = octets * 8;
	for (int i = 0; i < 8; ++i) bloc[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
	comprimer(bloc);
}

/*! Accumulation par blocs de 64 octets, commune aux deux algorithmes. */
template <typename F>
void ajouter(const uint8_t* data, size_t length, uint8_t* bloc, size_t& dansBloc,
             uint64_t& octets, F comprimer){
	if (!data) return;
	octets += length;
	while (length){
		const size_t place = 64 - dansBloc;
		const size_t n = length < place ? length : place;
		std::memcpy(bloc + dansBloc, data, n);
		dansBloc += n; data += n; length -= n;
		if (dansBloc == 64){ comprimer(bloc); dansBloc = 0; }
	}
}

} // namespace

// ---------------------------------------------------------------------------
//  SHA-1
// ---------------------------------------------------------------------------

void Sha1Stream::comprimer(const uint8_t* bloc){
	uint32_t w[80];
	for (int i = 0; i < 16; ++i) w[i] = be32(bloc + 4 * i);
	for (int i = 16; i < 80; ++i) w[i] = rotl(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);

	uint32_t a = etat_[0], b = etat_[1], c = etat_[2], d = etat_[3], e = etat_[4];
	for (int i = 0; i < 80; ++i){
		uint32_t f, k;
		if      (i < 20){ f = (b & c) | (~b & d);            k = 0x5A827999u; }
		else if (i < 40){ f = b ^ c ^ d;                     k = 0x6ED9EBA1u; }
		else if (i < 60){ f = (b & c) | (b & d) | (c & d);    k = 0x8F1BBCDCu; }
		else            { f = b ^ c ^ d;                     k = 0xCA62C1D6u; }
		const uint32_t t = rotl(a, 5) + f + e + k + w[i];
		e = d; d = c; c = rotl(b, 30); b = a; a = t;
	}
	etat_[0] += a; etat_[1] += b; etat_[2] += c; etat_[3] += d; etat_[4] += e;
}

void Sha1Stream::update(const uint8_t* data, size_t length){
	ajouter(data, length, bloc_, dansBloc_, octets_,
	        [this](const uint8_t* b){ comprimer(b); });
}

std::wstring Sha1Stream::hexDigest(){
	terminer(dansBloc_, bloc_, octets_, [this](const uint8_t* b){ comprimer(b); });
	uint8_t d[20];
	for (int i = 0; i < 5; ++i)
		for (int j = 0; j < 4; ++j) d[4 * i + j] = (uint8_t)(etat_[i] >> (24 - 8 * j));
	return enHexa(d, 20);
}

// ---------------------------------------------------------------------------
//  SHA-256
// ---------------------------------------------------------------------------

void Sha256Stream::comprimer(const uint8_t* bloc){
	uint32_t w[64];
	for (int i = 0; i < 16; ++i) w[i] = be32(bloc + 4 * i);
	for (int i = 16; i < 64; ++i){
		const uint32_t s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		const uint32_t s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19)  ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	uint32_t a = etat_[0], b = etat_[1], c = etat_[2], d = etat_[3];
	uint32_t e = etat_[4], f = etat_[5], g = etat_[6], h = etat_[7];
	for (int i = 0; i < 64; ++i){
		const uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
		const uint32_t ch = (e & f) ^ (~e & g);
		const uint32_t t1 = h + S1 + ch + K256[i] + w[i];
		const uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
		const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
		const uint32_t t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	etat_[0] += a; etat_[1] += b; etat_[2] += c; etat_[3] += d;
	etat_[4] += e; etat_[5] += f; etat_[6] += g; etat_[7] += h;
}

void Sha256Stream::update(const uint8_t* data, size_t length){
	ajouter(data, length, bloc_, dansBloc_, octets_,
	        [this](const uint8_t* b){ comprimer(b); });
}

std::wstring Sha256Stream::hexDigest(){
	terminer(dansBloc_, bloc_, octets_, [this](const uint8_t* b){ comprimer(b); });
	uint8_t d[32];
	for (int i = 0; i < 8; ++i)
		for (int j = 0; j < 4; ++j) d[4 * i + j] = (uint8_t)(etat_[i] >> (24 - 8 * j));
	return enHexa(d, 32);
}

std::wstring sha256Fichier(const std::wstring& chemin){
	std::ifstream f(std::filesystem::path(chemin), std::ios::binary);
	if (!f) return L"";
	Sha256Stream flux;
	std::vector<char> tampon(1 << 16);
	while (f.read(tampon.data(), (std::streamsize)tampon.size()) || f.gcount())
		flux.update(reinterpret_cast<const uint8_t*>(tampon.data()), (size_t)f.gcount());
	return flux.hexDigest();
}
