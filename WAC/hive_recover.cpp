/*  hive_recover.cpp — voir hive_recover.h.
 *  C++ portable (aucune dépendance Windows) : testable aussi sous Linux.
 */
#include "hive_recover.h"
#include <fstream>
#include <vector>
#include <cstring>

namespace {

constexpr size_t BASE_BLOCK = 4096;   // taille du bloc de base d'une ruche
constexpr size_t OFF_PRIMARY   = 0x04;
constexpr size_t OFF_SECONDARY = 0x08;
constexpr size_t OFF_FILETYPE  = 0x1C;  // 0 = ruche primaire, 6 = journal
constexpr size_t OFF_NAME      = 0x30;  // nom interne, UTF-16, 64 octets
constexpr size_t OFF_CHECKSUM  = 508;   // XOR des 127 premiers uint32

inline uint32_t rd32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline void wr32(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Checksum du bloc de base : XOR des 127 premiers uint32.
   0 et 0xFFFFFFFF sont interdits et remplacés (spécification du format). */
uint32_t baseBlockChecksum(const uint8_t* bb){
    uint32_t x = 0;
    for (int i = 0; i < 127; ++i) x ^= rd32(bb + i * 4);
    if (x == 0)          return 1;
    if (x == 0xFFFFFFFF) return 0xFFFFFFFE;
    return x;
}

} // namespace

HiveFixInfo MakeHiveLoadable(const std::filesystem::path& hive){
    HiveFixInfo r;
    std::fstream f(hive, std::ios::in | std::ios::out | std::ios::binary);
    if (!f){ r.error = L"ouverture impossible"; return r; }

    std::vector<uint8_t> bb(BASE_BLOCK);
    f.read(reinterpret_cast<char*>(bb.data()), BASE_BLOCK);
    if (f.gcount() != (std::streamsize)BASE_BLOCK){ r.error = L"bloc de base tronqué"; return r; }

    if (std::memcmp(bb.data(), "regf", 4) != 0){ r.error = L"signature regf absente"; return r; }
    if (rd32(bb.data() + OFF_FILETYPE) != 0){ r.error = L"n'est pas une ruche primaire"; return r; }

    r.primarySeq   = rd32(bb.data() + OFF_PRIMARY);
    r.secondarySeq = rd32(bb.data() + OFF_SECONDARY);
    r.oldChecksum  = rd32(bb.data() + OFF_CHECKSUM);

    // nom interne (UTF-16, terminé ou plein)
    for (size_t i = 0; i < 32; ++i){
        wchar_t c = (wchar_t)(bb[OFF_NAME + i * 2] | (bb[OFF_NAME + i * 2 + 1] << 8));
        if (!c) break;
        r.hiveName.push_back(c);
    }

    r.wasDirty = (r.primarySeq != r.secondarySeq);
    if (!r.wasDirty){ r.ok = true; r.newChecksum = r.oldChecksum; return r; }

    // Aligner secondaire := primaire, puis recalculer le checksum.
    wr32(bb.data() + OFF_SECONDARY, r.primarySeq);
    r.newChecksum = baseBlockChecksum(bb.data());
    wr32(bb.data() + OFF_CHECKSUM, r.newChecksum);

    f.seekp(0, std::ios::beg);
    f.write(reinterpret_cast<const char*>(bb.data()), BASE_BLOCK);
    f.flush();
    if (!f){ r.error = L"écriture du bloc de base impossible"; return r; }

    r.patched = true; r.ok = true;
    return r;
}

std::wstring HiveFixInfoToString(const HiveFixInfo& i){
    auto hex = [](uint32_t v){
        wchar_t b[16];
        const wchar_t* d = L"0123456789abcdef";
        b[0] = L'0'; b[1] = L'x';
        for (int k = 0; k < 8; ++k) b[2 + k] = d[(v >> ((7 - k) * 4)) & 0xF];
        b[10] = 0; return std::wstring(b);
    };
    if (!i.ok) return L"ECHEC (" + i.error + L")";
    if (!i.wasDirty) return i.hiveName + L" : déjà propre (séq " + hex(i.primarySeq) + L")";
    return i.hiveName + L" : dirty séq " + hex(i.primarySeq) + L"/" + hex(i.secondarySeq)
         + L" -> aligné " + hex(i.primarySeq) + L", checksum " + hex(i.oldChecksum)
         + L" -> " + hex(i.newChecksum)
         + (i.patched ? L" [patch appliqué]" : L" [NON appliqué]");
}
