/*  hive_recover.cpp — see hive_recover.h.
 *  Portable C++ (no Windows dependency): testable on Linux too.
 */
#include "hive_recover.h"
#include <fstream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iterator>

namespace {

constexpr size_t BASE_BLOCK = 4096;   // size of a hive's base block
constexpr size_t OFF_PRIMARY   = 0x04;
constexpr size_t OFF_SECONDARY = 0x08;
constexpr size_t OFF_FILETYPE  = 0x1C;  // 0 = ruche primaire, 6 = journal
constexpr size_t OFF_NAME      = 0x30;  // nom interne, UTF-16, 64 octets
constexpr size_t OFF_CHECKSUM  = 508;   // XOR of the first 127 uint32

inline uint32_t rd32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline void wr32(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

/* Base block checksum: XOR of the first 127 uint32.
   0 and 0xFFFFFFFF are forbidden and replaced (format specification). */
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

    // internal name (UTF-16, terminated or full)
    for (size_t i = 0; i < 32; ++i){
        wchar_t c = (wchar_t)(bb[OFF_NAME + i * 2] | (bb[OFF_NAME + i * 2 + 1] << 8));
        if (!c) break;
        r.hiveName.push_back(c);
    }

    r.wasDirty = (r.primarySeq != r.secondarySeq);
    if (!r.wasDirty){ r.ok = true; r.newChecksum = r.oldChecksum; return r; }

    // Set secondary := primary, then recompute the checksum.
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

// ---------------------------------------------------------------------------
//  Replaying the transaction logs
// ---------------------------------------------------------------------------
/*  See hive_recover.h for the approach and the two traps. Here, the format.
 *
 *  Log (.LOG1/.LOG2): 512-byte base block of type "regf", then a sequence of
 *  contiguous entries.
 *
 *  Entry ("HvLE"):
 *      0   4   signature "HvLE"
 *      4   4   size of the entry
 *      8   4   flags
 *     12   4   sequence number
 *     16   4   size of the bins data AFTER this entry
 *     20   4   number of modified pages
 *     24   8   Marvin32 of the body (offset 40 → end of the entry)
 *     32   8   Marvin32 of the header (first 32 bytes)
 *     40  8×N  page references: offset (4), size (4)
 *    ...       page content, in the order of the references
 *
 *  Page offsets are relative to the START OF THE BINS DATA, i.e. to offset
 *  4096 of the hive file.
 */
namespace {

constexpr size_t LOG_ENTETE      = 512;        // bloc de base d'un journal
constexpr size_t ENTREE_ENTETE   = 40;         // before the page references
constexpr uint64_t MARVIN_GRAINE = 0x82EF4D887A4E55C5ULL;

inline uint32_t rotl32(uint32_t v, int n){ return (uint32_t)((v << n) | (v >> (32 - n))); }

/*  Marvin32, as the format uses it. The result is returned on 8 bytes: the
 *  low half then the high half, little-endian. */
uint64_t marvin32(const uint8_t* data, size_t taille){
    uint32_t lo = (uint32_t)MARVIN_GRAINE;
    uint32_t hi = (uint32_t)(MARVIN_GRAINE >> 32);
    auto mix = [&](){
        hi ^= lo; lo = rotl32(lo, 20); lo += hi;
        hi = rotl32(hi, 9);  hi ^= lo; lo = rotl32(lo, 27); lo += hi;
        hi = rotl32(hi, 19);
    };
    size_t i = 0;
    for (; taille - i >= 4; i += 4){ lo += rd32(data + i); mix(); }
    // Finalisation: the remaining bytes followed by a 0x80.
    uint32_t reste = 0;
    size_t k = 0;
    for (; i + k < taille; ++k) reste |= (uint32_t)data[i + k] << (8 * k);
    reste |= (uint32_t)0x80 << (8 * k);
    lo += reste; mix(); mix();
    return ((uint64_t)hi << 32) | lo;
}

inline uint64_t rd64(const uint8_t* p){
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}
inline void wr64(uint8_t* p, uint64_t v){ wr32(p, (uint32_t)v); wr32(p + 4, (uint32_t)(v >> 32)); }

//! An entry read from a log, with its position and its verdict.
struct EntreeLue {
    uint32_t sequence = 0;
    uint32_t nbPages  = 0;
    uint64_t octets   = 0;
    uint32_t tailleBins = 0;
    std::vector<std::pair<uint32_t, uint32_t>> pages; //!< offset, taille
    std::vector<uint8_t> corps;                       //!< the whole entry
    size_t   debutDonnees = 0;                        //!< within `corps`
    std::wstring motif;                               //!< empty if valid
};

/*! Entries of a log, IN FILE ORDER, up to the first break.
 *
 *  The chain stops at the first entry that is invalid or whose sequence does
 *  not follow: what comes after is leftover from an earlier generation of the
 *  log, and applying it would move the data backwards (see hive_recover.h).
 */
std::vector<EntreeLue> lireChaine(const std::filesystem::path& journal,
                                  unsigned* residu){
    std::vector<EntreeLue> chaine;
    std::error_code ec;
    if (!std::filesystem::exists(journal, ec)) return chaine;
    std::ifstream f(journal, std::ios::binary);
    if (!f) return chaine;
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
    if (d.size() < LOG_ENTETE || std::memcmp(d.data(), "regf", 4) != 0) return chaine;

    size_t off = LOG_ENTETE;
    bool rompue = false;
    uint32_t attendue = 0;
    bool premiere = true;
    while (off + ENTREE_ENTETE <= d.size()){
        if (std::memcmp(d.data() + off, "HvLE", 4) != 0) break;
        const uint32_t taille = rd32(d.data() + off + 4);
        if (taille < LOG_ENTETE || off + taille > d.size()) break;

        if (rompue){ ++*residu; off += taille; continue; }

        EntreeLue e;
        e.sequence   = rd32(d.data() + off + 12);
        e.tailleBins = rd32(d.data() + off + 16);
        e.nbPages    = rd32(d.data() + off + 20);
        const uint64_t h1 = rd64(d.data() + off + 24);
        const uint64_t h2 = rd64(d.data() + off + 32);

        // Bounds BEFORE any other read: nbPages comes from the examined file.
        if (e.nbPages > (taille - ENTREE_ENTETE) / 8) e.motif = L"nombre de pages incoherent";
        else if (marvin32(d.data() + off, 32) != h2)  e.motif = L"empreinte d'entete";
        else if (marvin32(d.data() + off + ENTREE_ENTETE, taille - ENTREE_ENTETE) != h1)
                                                      e.motif = L"empreinte de corps";
        else {
            uint64_t somme = 0;
            for (uint32_t i = 0; i < e.nbPages; ++i){
                const uint32_t o = rd32(d.data() + off + ENTREE_ENTETE + 8 * i);
                const uint32_t t = rd32(d.data() + off + ENTREE_ENTETE + 8 * i + 4);
                e.pages.emplace_back(o, t);
                somme += t;
            }
            if (ENTREE_ENTETE + 8ULL * e.nbPages + somme > taille)
                e.motif = L"pages hors de l'entree";
            else e.octets = somme;
        }

        if (e.motif.empty() && !premiere && e.sequence != attendue)
            e.motif = L"rupture de sequence (residu)";

        if (!e.motif.empty()){
            rompue = true;
            // A broken entry is not counted as leftover if it is invalid in
            // itself: the caller tells the two cases apart.
            if (e.motif == L"rupture de sequence (residu)") ++*residu;
            else chaine.push_back(std::move(e));   // kept for the report
            off += taille;
            continue;
        }

        e.corps.assign(d.begin() + off, d.begin() + off + taille);
        e.debutDonnees = ENTREE_ENTETE + 8ULL * e.nbPages;
        attendue = e.sequence + 1;
        premiere = false;
        chaine.push_back(std::move(e));
        off += taille;
    }
    return chaine;
}

} // namespace

HiveReplayInfo ReplayHiveLogs(const std::filesystem::path& hive,
                              const std::wstring& md5Avant){
    HiveReplayInfo r;

    std::fstream f(hive, std::ios::in | std::ios::out | std::ios::binary);
    if (!f){ r.error = L"ouverture impossible"; return r; }

    std::vector<uint8_t> bb(BASE_BLOCK);
    f.read(reinterpret_cast<char*>(bb.data()), BASE_BLOCK);
    if (f.gcount() != (std::streamsize)BASE_BLOCK){ r.error = L"bloc de base tronqué"; return r; }
    if (std::memcmp(bb.data(), "regf", 4) != 0){ r.error = L"signature regf absente"; return r; }
    if (rd32(bb.data() + OFF_FILETYPE) != 0){ r.error = L"n'est pas une ruche primaire"; return r; }

    const uint32_t seqPrimaire   = rd32(bb.data() + OFF_PRIMARY);
    const uint32_t seqSecondaire = rd32(bb.data() + OFF_SECONDARY);
    r.sequenceRuche  = seqPrimaire;
    r.sequenceFinale = seqPrimaire;

    unsigned residu = 0;
    std::vector<EntreeLue> chaine = lireChaine(hive.wstring() + L".LOG1", &residu);
    for (EntreeLue& e : lireChaine(hive.wstring() + L".LOG2", &residu))
        chaine.push_back(std::move(e));
    r.entreesResidu = residu;
    if (chaine.empty()){ r.ok = true; return r; }   // no log: the nominal case
    r.journaux = true;

    // The two logs follow each other; sequence order joins them.
    std::sort(chaine.begin(), chaine.end(),
              [](const EntreeLue& a, const EntreeLue& b){ return a.sequence < b.sequence; });

    // Current file size, to bound the writes.
    f.seekg(0, std::ios::end);
    const uint64_t tailleRuche = (uint64_t)f.tellg();

    /*  Two passes. The first one decides and gathers the ORIGINAL content of
     *  the pages: the undo journal must be complete BEFORE the slightest write,
     *  otherwise an interruption would leave a modified hive that could no
     *  longer be rebuilt. */
    struct Page { uint64_t offset; uint32_t taille; std::vector<uint8_t> origine; };
    std::vector<Page> annulation;
    std::vector<const EntreeLue*> aAppliquer;
    uint32_t attendue = 0;
    bool premiere = true;

    for (EntreeLue& e : chaine){
        HiveLogEntry trace;
        trace.sequence = e.sequence;
        trace.pages    = e.nbPages;
        trace.octets   = e.octets;

        if (!e.motif.empty()){ trace.motif = e.motif; ++r.entreesEcartees; r.entrees.push_back(trace); continue; }
        if (e.sequence <= seqSecondaire){
            trace.motif = L"deja dans la ruche";
            r.entrees.push_back(trace);
            continue;
        }
        if (!premiere && e.sequence != attendue){
            // Gap between the two logs: stop there. Beyond, the state would be a
            // mix of generations, with no guarantee of consistency.
            trace.motif = L"trou dans la chaine";
            ++r.entreesEcartees;
            r.entrees.push_back(trace);
            break;
        }
        attendue = e.sequence + 1;
        premiere = false;

        bool bornesOk = true;
        for (const std::pair<uint32_t, uint32_t>& p : e.pages)
            if (BASE_BLOCK + (uint64_t)p.first + p.second > tailleRuche) bornesOk = false;
        if (!bornesOk){
            trace.motif = L"page hors de la ruche";
            ++r.entreesEcartees;
            r.entrees.push_back(trace);
            break;
        }

        for (const std::pair<uint32_t, uint32_t>& p : e.pages){
            Page pg{ BASE_BLOCK + (uint64_t)p.first, p.second, {} };
            pg.origine.resize(p.second);
            f.seekg((std::streamoff)pg.offset, std::ios::beg);
            f.read(reinterpret_cast<char*>(pg.origine.data()), p.second);
            if (f.gcount() != (std::streamsize)p.second){ bornesOk = false; break; }
            annulation.push_back(std::move(pg));
        }
        if (!bornesOk){
            trace.motif = L"lecture de la page d'origine impossible";
            ++r.entreesEcartees;
            r.entrees.push_back(trace);
            break;
        }

        trace.applique = true;
        aAppliquer.push_back(&e);
        r.entrees.push_back(trace);
        ++r.entreesRetenues;
        r.pages  += e.nbPages;
        r.octets += e.octets;
        r.sequenceFinale = e.sequence;
    }

    if (aAppliquer.empty()){ r.ok = true; return r; }

    /*  The base block is part of the undo: the replay rewrites the sequence
     *  numbers and the checksum in it. Without it, the raw copy could only be
     *  restored in its data area, and the "rebuildable to the byte" promise
     *  would be false by 4096 bytes. */
    annulation.insert(annulation.begin(), Page{ 0, (uint32_t)BASE_BLOCK,
                      std::vector<uint8_t>(bb.begin(), bb.end()) });

    // Undo journal, written BEFORE any change to the hive.
    const std::filesystem::path chemUndo = hive.wstring() + L".undo";
    {
        std::ofstream u(chemUndo, std::ios::binary | std::ios::trunc);
        if (!u){ r.error = L"journal d'annulation non écrit : rejeu abandonné"; return r; }
        std::vector<uint8_t> ent(56, 0);
        std::memcpy(ent.data(), "WACUNDO1", 8);
        for (size_t i = 0; i < 32; ++i)
            ent[8 + i] = (uint8_t)(i < md5Avant.size() ? (char)md5Avant[i] : ' ');
        wr32(ent.data() + 40, (uint32_t)annulation.size());
        wr64(ent.data() + 44, tailleRuche);
        u.write(reinterpret_cast<const char*>(ent.data()), (std::streamsize)ent.size());
        for (const Page& p : annulation){
            uint8_t ligne[12];
            wr64(ligne, p.offset);
            wr32(ligne + 8, p.taille);
            u.write(reinterpret_cast<const char*>(ligne), 12);
        }
        for (const Page& p : annulation)
            u.write(reinterpret_cast<const char*>(p.origine.data()), (std::streamsize)p.taille);
        u.flush();
        if (!u){ r.error = L"journal d'annulation incomplet : rejeu abandonné"; return r; }
    }
    r.journalAnnulation = chemUndo.wstring();

    // Apply the pages, then align the base block on the last applied
    // sequence: the hive becomes clean by construction.
    for (const EntreeLue* e : aAppliquer){
        size_t pos = e->debutDonnees;
        for (const std::pair<uint32_t, uint32_t>& p : e->pages){
            f.seekp((std::streamoff)(BASE_BLOCK + (uint64_t)p.first), std::ios::beg);
            f.write(reinterpret_cast<const char*>(e->corps.data() + pos), (std::streamsize)p.second);
            pos += p.second;
        }
    }
    wr32(bb.data() + OFF_PRIMARY,   r.sequenceFinale);
    wr32(bb.data() + OFF_SECONDARY, r.sequenceFinale);
    wr32(bb.data() + OFF_CHECKSUM,  baseBlockChecksum(bb.data()));
    f.seekp(0, std::ios::beg);
    f.write(reinterpret_cast<const char*>(bb.data()), BASE_BLOCK);
    f.flush();
    if (!f){ r.error = L"écriture de la ruche impossible"; return r; }

    r.applique = true;
    r.ok = true;
    return r;
}

std::wstring HiveReplayInfoToString(const HiveReplayInfo& i){
    auto hex = [](uint32_t v){
        wchar_t b[16];
        const wchar_t* d = L"0123456789abcdef";
        b[0] = L'0'; b[1] = L'x';
        for (int k = 0; k < 8; ++k) b[2 + k] = d[(v >> ((7 - k) * 4)) & 0xF];
        b[10] = 0; return std::wstring(b);
    };
    if (!i.ok) return L"rejeu : ECHEC (" + i.error + L")";
    if (!i.journaux) return L"rejeu : aucun journal de transaction exploitable";
    if (!i.applique) return L"rejeu : rien a appliquer (ruche a jour, seq "
                          + hex(i.sequenceRuche) + L")";
    std::wstring s = L"rejeu : " + std::to_wstring(i.entreesRetenues) + L" entree(s), "
                   + std::to_wstring(i.pages) + L" page(s), "
                   + std::to_wstring(i.octets / 1024) + L" Kio, seq "
                   + hex(i.sequenceRuche) + L" -> " + hex(i.sequenceFinale);
    if (i.entreesEcartees) s += L", " + std::to_wstring(i.entreesEcartees) + L" ecartee(s)";
    if (i.entreesResidu)   s += L", " + std::to_wstring(i.entreesResidu) + L" hors chaine";
    return s;
}
