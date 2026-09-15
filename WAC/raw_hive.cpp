/*  raw_hive.cpp — voir raw_hive.h.
 *  Parseur NTFS minimal : VBR, $MFT (fragmenté), attributs, data runs, index de
 *  répertoires ($INDEX_ROOT + $INDEX_ALLOCATION), extraction $DATA.
 *  Fait pour les ruches/EVTX/Tasks : fichiers non résidents de taille moyenne.
 */
#include "raw_hive.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include "quickdigest5.h"

namespace {

bool g_verbose = false;
#define RVLOG(...) do{ if(g_verbose) fwprintf(stderr, __VA_ARGS__); }while(0)

RawHiveProgressFn g_progress = nullptr;      // rapporteur de progression, optionnel

// --- lecture entiers little-endian ----------------------------------------
inline uint16_t rd16(const uint8_t* p){ return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
inline uint64_t rd64(const uint8_t* p){
    uint64_t v = 0; for (int i = 7; i >= 0; --i) v = (v << 8) | p[i]; return v;
}

// comparaison de noms insensible à la casse (ASCII/BMP suffit pour ces chemins)
bool iequals(const std::wstring& a, const std::wstring& b){
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (towlower(a[i]) != towlower(b[i])) return false;
    return true;
}

struct Run { int64_t lcn; uint64_t count; }; // lcn == -1 : run sparse (zéros)

// Décode une liste de data runs NTFS.
std::vector<Run> decodeRuns(const uint8_t* p, const uint8_t* end){
    std::vector<Run> runs; int64_t prev = 0;
    while (p < end) {
        uint8_t hdr = *p++; if (hdr == 0) break;
        int lenSz = hdr & 0x0F, offSz = (hdr >> 4) & 0x0F;
        if (p + lenSz + offSz > end) break;
        uint64_t count = 0;
        for (int i = 0; i < lenSz; ++i) count |= (uint64_t)p[i] << (8 * i);
        p += lenSz;
        Run r; r.count = count;
        if (offSz == 0) { r.lcn = -1; }                 // sparse
        else {
            int64_t off = 0;
            for (int i = 0; i < offSz; ++i) off |= (int64_t)p[i] << (8 * i);
            if (p[offSz - 1] & 0x80)                     // extension de signe
                for (int i = offSz; i < 8; ++i) off |= (int64_t)0xFF << (8 * i);
            prev += off; r.lcn = prev; p += offSz;
        }
        runs.push_back(r);
    }
    return runs;
}

class NtfsVolume {
public:
    ~NtfsVolume(){ close(); }

    HRESULT open(const std::wstring& volumeLetter){
        std::wstring path = L"\\\\.\\" + volumeLetter + L":";
        h_ = CreateFileW(path.c_str(), GENERIC_READ,
                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                         NULL, OPEN_EXISTING, 0, NULL);
        if (h_ == INVALID_HANDLE_VALUE){
            DWORD e = GetLastError();
            RVLOG(L"[raw] open %ls: erreur %lu (admin requis ?)\n", path.c_str(), e);
            return HRESULT_FROM_WIN32(e);
        }
        uint8_t vbr[512];
        if (!readBytes(0, vbr, 512)) return E_FAIL;
        if (memcmp(vbr + 3, "NTFS    ", 8) != 0){
            RVLOG(L"[raw] signature NTFS absente\n"); return E_FAIL;
        }
        bytesPerSector_    = rd16(vbr + 0x0B);
        sectorsPerCluster_ = vbr[0x0D];
        bytesPerCluster_   = bytesPerSector_ * sectorsPerCluster_;
        mftLcn_            = rd64(vbr + 0x30);
        int8_t cpr = (int8_t)vbr[0x40];   // clusters/record, ou 2^(-cpr) octets
        bytesPerRecord_ = (cpr >= 0) ? (uint32_t)cpr * bytesPerCluster_
                                     : (uint32_t)(1u << (-cpr));
        if (!bytesPerSector_ || !bytesPerCluster_ || !bytesPerRecord_) return E_FAIL;
        RVLOG(L"[raw] bps=%u spc=%u bpc=%u bpr=%u mftLcn=%llu\n",
              bytesPerSector_, sectorsPerCluster_, bytesPerCluster_,
              bytesPerRecord_, (unsigned long long)mftLcn_);
        return bootstrapMft() ? S_OK : E_FAIL;
    }

    void close(){ if (h_ != INVALID_HANDLE_VALUE){ CloseHandle(h_); h_ = INVALID_HANDLE_VALUE; } }

    // Résout un chemin (\a\b\c) en index d'enregistrement MFT.
    bool resolvePath(const std::wstring& path, uint64_t& outIndex){
        uint64_t cur = 5; // racine \ = MFT #5
        size_t i = 0;
        while (i < path.size()){
            while (i < path.size() && (path[i] == L'\\' || path[i] == L'/')) ++i;
            size_t j = i;
            while (j < path.size() && path[j] != L'\\' && path[j] != L'/') ++j;
            if (j == i) break;
            std::wstring comp = path.substr(i, j - i);
            i = j;
            RVLOG(L"[raw] recherche \"%ls\" dans MFT#%llu\n", comp.c_str(), (unsigned long long)cur);
            std::vector<RawDirEntry> entries;
            if (!listDir(cur, entries)) return false;
            bool found = false;
            for (const RawDirEntry& e : entries)
                if (iequals(e.name, comp)){ cur = e.mftIndex; found = true; break; }
            if (!found){ RVLOG(L"[raw] composant introuvable: %ls\n", comp.c_str()); return false; }
        }
        outIndex = cur; return true;
    }

    // Extrait l'attribut $DATA (non nommé) de l'enregistrement vers un fichier.
    /* Rassemble les data runs de $DATA quand l'attribut est ÉCLATÉ sur plusieurs
       enregistrements MFT, via $ATTRIBUTE_LIST (type 0x20).
       NTFS recourt à ce mécanisme quand un fichier est trop fragmenté pour que
       ses data runs tiennent dans un seul enregistrement — cas observé sur la
       ruche SOFTWARE d'un système réel, qui ne s'extrayait donc pas.

       Chaque entrée de la liste fait : type (4), longueur (2), longueur du nom
       (1), offset du nom (1), VCN de départ (8), référence MFT (8), id (2).
       On retient les entrées $DATA sans nom, on charge l'enregistrement
       référencé, et on concatène ses runs dans l'ordre des VCN.
       @param realSize reçoit la taille réelle, lue sur le fragment de VCN 0 */
    bool collectRunsFromAttributeList(const std::vector<uint8_t>& rec,
                                      std::vector<Run>& runs, uint64_t& realSize,
                                      uint32_t typeCherche = 0x80){
        const uint8_t* al = findAttr(rec, 0x20, false);
        if (!al) return false;

        // Contenu de la liste : résident, ou à lire via ses propres runs.
        std::vector<uint8_t> contenu;
        if (al[8] == 0){
            const uint32_t vlen = rd32(al + 0x10);
            const uint16_t voff = rd16(al + 0x14);
            contenu.assign(al + voff, al + voff + vlen);
        }
        else {
            const uint64_t taille = rd64(al + 0x30);
            const std::vector<Run> alRuns = decodeRuns(al + rd16(al + 0x20), al + rd32(al + 0x04));
            contenu.resize((size_t)taille);
            if (!readVirtual(alRuns, 0, (uint32_t)taille, contenu.data())) return false;
        }

        // VCN -> runs, pour réassembler dans l'ordre même si les entrées ne le sont pas.
        std::vector<std::pair<uint64_t, std::vector<Run>>> fragments;
        size_t pos = 0;
        while (pos + 0x1A <= contenu.size()){
            const uint32_t type = rd32(contenu.data() + pos);
            const uint16_t len  = rd16(contenu.data() + pos + 4);
            if (len < 0x1A || pos + len > contenu.size()) break;
            const uint8_t nameLen = contenu[pos + 6];
            /* Le nom est ignoré dans la comparaison : $INDEX_ALLOCATION porte
               toujours le nom "$I30", contrairement à $DATA qui est sans nom. */
            if (type == typeCherche && (typeCherche != 0x80 || nameLen == 0)){
                const uint64_t vcn = rd64(contenu.data() + pos + 8);
                const uint64_t ref = rd64(contenu.data() + pos + 0x10) & 0x0000FFFFFFFFFFFFULL;
                std::vector<uint8_t> frag;
                if (readMftRecord(ref, frag)){
                    // Le fragment porte l'attribut non résident couvrant ce VCN.
                    const uint8_t* d = findAttr(frag, typeCherche, typeCherche == 0x80);
                    if (d && d[8] != 0){
                        if (rd16(d + 0x0C) & 0x0001){
                            RVLOG(L"[raw] $DATA compresse NTFS dans un fragment : non supporte\n");
                            return false;
                        }
                        if (vcn == 0) realSize = rd64(d + 0x30);
                        fragments.emplace_back(vcn, decodeRuns(d + rd16(d + 0x20), d + rd32(d + 0x04)));
                    }
                }
                else RVLOG(L"[raw] fragment MFT #%llu illisible\n", (unsigned long long)ref);
            }
            pos += len;
        }
        if (fragments.empty() || realSize == 0) return false;

        std::sort(fragments.begin(), fragments.end(),
                  [](const auto& a, const auto& b){ return a.first < b.first; });
        for (auto& f : fragments)
            runs.insert(runs.end(), f.second.begin(), f.second.end());

        RVLOG(L"[raw] $ATTRIBUTE_LIST : %llu fragment(s), %llu run(s), taille %llu\n",
              (unsigned long long)fragments.size(), (unsigned long long)runs.size(),
              (unsigned long long)realSize);
        return true;
    }

    HRESULT extractData(uint64_t index, const std::wstring& outFile,
                        const std::wstring& libelle = std::wstring(),
                        std::wstring* md5 = nullptr){
        std::vector<uint8_t> rec;
        if (!readMftRecord(index, rec)) return E_FAIL;

        std::vector<Run> runs;
        uint64_t realSize = 0;
        bool resident = false;
        const uint8_t* residentData = nullptr;
        uint32_t residentLen = 0;

        const uint8_t* a = findAttr(rec, 0x80 /*$DATA*/);
        if (a){
            if (a[8] == 0){                       // résident : la donnée est dans l'enregistrement
                resident = true;
                residentLen  = rd32(a + 0x10);
                residentData = a + rd16(a + 0x14);
            }
            else {
                if (rd16(a + 0x0C) & 0x0001){     // compressé NTFS : non géré
                    RVLOG(L"[raw] $DATA compresse NTFS : non supporte\n");
                    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                }
                realSize = rd64(a + 0x30);
                runs = decodeRuns(a + rd16(a + 0x20), a + rd32(a + 0x04));
            }
        }
        else if (!collectRunsFromAttributeList(rec, runs, realSize)){
            RVLOG(L"[raw] pas d'attribut $DATA exploitable\n");
            return E_FAIL;
        }

        std::ofstream out(std::filesystem::path(outFile), std::ios::binary | std::ios::trunc);
        if (!out){ RVLOG(L"[raw] ouverture sortie impossible\n"); return E_FAIL; }

        if (resident){
            out.write((const char*)residentData, residentLen);
            if (md5){
                Md5Stream flux;
                flux.update(residentData, residentLen);
                *md5 = flux.hexDigest();
            }
            return S_OK;
        }

        std::vector<uint8_t> cl(bytesPerCluster_);
        uint64_t written = 0;
        uint64_t prochainRapport = 0;
        // Empreinte calculee sur les octets qui transitent deja en memoire :
        // evite de relire la copie depuis le support de collecte.
        Md5Stream flux;
        for (const Run& r : runs){
            for (uint64_t k = 0; k < r.count && written < realSize; ++k){
                if (r.lcn < 0) std::fill(cl.begin(), cl.end(), 0);          // sparse
                else if (!readCluster((uint64_t)r.lcn + k, cl.data())) return E_FAIL;
                uint64_t chunk = std::min<uint64_t>(bytesPerCluster_, realSize - written);
                out.write((const char*)cl.data(), (std::streamsize)chunk);
                if (md5) flux.update(cl.data(), (size_t)chunk);
                written += chunk;
                // Rapport tous les 1 Mio : assez fréquent pour montrer que ça
                // avance, assez rare pour ne pas coûter en affichage.
                if (g_progress && !libelle.empty() && written >= prochainRapport){
                    g_progress(libelle.c_str(), written, realSize);
                    prochainRapport = written + (1ULL << 20);
                }
            }
        }
        if (g_progress && !libelle.empty()) g_progress(libelle.c_str(), written, realSize);
        if (md5) *md5 = flux.hexDigest();
        RVLOG(L"[raw] extrait %llu octets\n", (unsigned long long)written);
        return (written == realSize) ? S_OK : S_FALSE;
    }

private:
    HANDLE   h_ = INVALID_HANDLE_VALUE;
    uint32_t bytesPerSector_ = 0, sectorsPerCluster_ = 0, bytesPerCluster_ = 0, bytesPerRecord_ = 0;
    uint64_t mftLcn_ = 0;
    std::vector<Run> mftRuns_;

    // lecture brute alignée secteur (les handles volume l'exigent)
    bool readBytes(uint64_t off, void* dst, uint32_t len){
        uint32_t sec = bytesPerSector_ ? bytesPerSector_ : 512;
        uint64_t start = off - (off % sec);
        uint64_t end   = off + len;
        if (end % sec) end += sec - (end % sec);
        uint32_t total = (uint32_t)(end - start);
        std::vector<uint8_t> tmp(total);
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)start;
        if (!SetFilePointerEx(h_, li, NULL, FILE_BEGIN)) return false;
        uint32_t done = 0;
        while (done < total){
            DWORD got = 0;
            if (!ReadFile(h_, tmp.data() + done, total - done, &got, NULL) || got == 0) return false;
            done += got;
        }
        memcpy(dst, tmp.data() + (off - start), len);
        return true;
    }
    bool readCluster(uint64_t lcn, void* dst){
        return readBytes(lcn * bytesPerCluster_, dst, bytesPerCluster_);
    }

    // Lit `len` octets à l'offset virtuel `fileOff` d'un fichier décrit par `runs`.
    bool readVirtual(const std::vector<Run>& runs, uint64_t fileOff, uint32_t len, uint8_t* dst){
        uint32_t got = 0;
        std::vector<uint8_t> cl(bytesPerCluster_);
        while (got < len){
            uint64_t cur   = fileOff + got;
            uint64_t vcn   = cur / bytesPerCluster_;
            uint32_t inClu = (uint32_t)(cur % bytesPerCluster_);
            uint64_t vbase = 0; int64_t lcn = -2;
            for (auto& r : runs){
                if (vcn < vbase + r.count){
                    lcn = (r.lcn < 0) ? -1 : (int64_t)((uint64_t)r.lcn + (vcn - vbase));
                    break;
                }
                vbase += r.count;
            }
            if (lcn == -2) return false; // hors runs
            uint32_t chunk = std::min<uint32_t>(len - got, bytesPerCluster_ - inClu);
            if (lcn < 0) memset(dst + got, 0, chunk);
            else { if (!readCluster((uint64_t)lcn, cl.data())) return false;
                   memcpy(dst + got, cl.data() + inClu, chunk); }
            got += chunk;
        }
        return true;
    }

    // Applique les fixups (Update Sequence Array) d'un enregistrement FILE/INDX.
    static void applyFixup(uint8_t* rec, uint32_t size, uint32_t sectorSize){
        uint16_t usaOff = rd16(rec + 4), usaCnt = rd16(rec + 6);
        if (usaOff + 2u * usaCnt > size) return;
        const uint8_t* usa = rec + usaOff;
        for (uint16_t i = 1; i < usaCnt; ++i){
            uint32_t secEnd = i * sectorSize;
            if (secEnd < 2 || secEnd > size) break;
            uint8_t* pos = rec + secEnd - 2;
            pos[0] = usa[2 * i]; pos[1] = usa[2 * i + 1];
        }
    }

    // Bootstrap : lit l'enregistrement #0 ($MFT) pour obtenir ses propres runs.
    bool bootstrapMft(){
        std::vector<uint8_t> rec(bytesPerRecord_);
        if (!readBytes(mftLcn_ * bytesPerCluster_, rec.data(), bytesPerRecord_)) return false;
        if (memcmp(rec.data(), "FILE", 4) != 0){ RVLOG(L"[raw] MFT#0: signature FILE absente\n"); return false; }
        applyFixup(rec.data(), bytesPerRecord_, bytesPerSector_);
        const uint8_t* a = findAttr(rec, 0x80);
        if (!a || a[8] == 0){ RVLOG(L"[raw] $MFT $DATA introuvable/résident\n"); return false; }
        uint16_t runsOff = rd16(a + 0x20);
        uint32_t attrLen = rd32(a + 0x04);
        mftRuns_ = decodeRuns(a + runsOff, a + attrLen);
        RVLOG(L"[raw] $MFT: %u runs, 1er lcn=%lld count=%llu\n", (unsigned)mftRuns_.size(),
              mftRuns_.empty()?0:(long long)mftRuns_[0].lcn, mftRuns_.empty()?0ULL:(unsigned long long)mftRuns_[0].count);
        return !mftRuns_.empty();
    }

    // Lit et défixe l'enregistrement MFT d'index donné.
    bool readMftRecord(uint64_t index, std::vector<uint8_t>& rec){
        rec.assign(bytesPerRecord_, 0);
        if (!readVirtual(mftRuns_, index * bytesPerRecord_, bytesPerRecord_, rec.data())){
            RVLOG(L"[raw] MFT#%llu: readVirtual echec\n", (unsigned long long)index); return false; }
        if (memcmp(rec.data(), "FILE", 4) != 0){
            RVLOG(L"[raw] MFT#%llu: magic FILE absent (%02x%02x%02x%02x)\n",
                  (unsigned long long)index, rec[0], rec[1], rec[2], rec[3]); return false; }
        applyFixup(rec.data(), bytesPerRecord_, bytesPerSector_);
        return true;
    }

    // Trouve le 1er attribut du type donné dans un enregistrement.
    // unnamedOnly : n'accepte que l'attribut SANS nom. Vrai pour $DATA (on veut
    // le flux principal, pas un ADS) mais FAUX pour les index de répertoires :
    // $INDEX_ROOT / $INDEX_ALLOCATION portent toujours le nom "$I30".
    static const uint8_t* findAttr(const std::vector<uint8_t>& rec, uint32_t type,
                                   bool unnamedOnly = true){
        uint16_t off = rd16(rec.data() + 0x14);
        const uint8_t* p = rec.data() + off;
        const uint8_t* end = rec.data() + rec.size();
        while (p + 8 <= end){
            uint32_t t = rd32(p);
            if (t == 0xFFFFFFFF) break;
            uint32_t len = rd32(p + 4);
            if (len < 8 || p + len > end) break;
            if (t == type && (!unnamedOnly || p[9] == 0)) return p;
            p += len;
        }
        return nullptr;
    }

    // Parse les entrées d'un noeud d'index (base = début du node header).
    /* Décode les entrées d'un nœud d'index de répertoire.
       Structure de la clé $FILE_NAME (fn = entrée + 0x10) : attributs en 0x38,
       taille réelle en 0x30, longueur du nom en 0x40, espace de noms en 0x41,
       puis le nom en UTF-16.
       L'espace de noms 2 est un nom court 8.3 : NTFS stocke souvent DEUX entrées
       pour un même fichier (une DOS, une Win32). On écarte les noms purement DOS,
       sinon chaque fichier serait extrait deux fois, sous deux noms. */
    static void parseIndexNode(const uint8_t* nodeHdr, const uint8_t* limit,
                               std::vector<RawDirEntry>& out){
        uint32_t firstOff = rd32(nodeHdr);
        const uint8_t* e = nodeHdr + firstOff;
        while (e + 0x10 <= limit){
            uint64_t ref   = rd64(e) & 0x0000FFFFFFFFFFFFULL;
            uint16_t eLen  = rd16(e + 8);
            uint16_t flags = rd16(e + 0x0C);
            if (!(flags & 0x02)){ // pas la dernière entrée -> possède une clé $FILE_NAME
                const uint8_t* fn = e + 0x10;
                if (fn + 0x42 <= limit){
                    uint32_t fileAttrs = rd32(fn + 0x38);
                    uint64_t realSize  = rd64(fn + 0x30);
                    uint8_t  nameLen   = fn[0x40];
                    uint8_t  nameSpace = fn[0x41];
                    const uint8_t* nm  = fn + 0x42;
                    if (nameSpace != 2 && nm + 2 * nameLen <= limit){   // 2 = nom court 8.3
                        RawDirEntry entry;
                        entry.name.resize(nameLen);
                        for (uint8_t k = 0; k < nameLen; ++k) entry.name[k] = (wchar_t)rd16(nm + 2 * k);
                        entry.mftIndex    = ref;
                        entry.isDirectory = (fileAttrs & 0x10000000u) != 0; // FILE_ATTRIBUTE_DIRECTORY
                        entry.size        = entry.isDirectory ? 0 : realSize;
                        out.push_back(std::move(entry));
                    }
                }
            }
            if (flags & 0x02) break;      // dernière entrée
            if (eLen == 0) break;
            e += eLen;
        }
    }

public:
    // Liste les entrées d'un répertoire (nom, index MFT, type, taille).
    // Public : sert aussi à ListDirectoryRaw / ExtractDirectoryRaw.
    bool listDir(uint64_t dirIndex, std::vector<RawDirEntry>& out){
        std::vector<uint8_t> rec;
        if (!readMftRecord(dirIndex, rec)){
            RVLOG(L"[raw] listDir(%llu): enregistrement illisible\n", (unsigned long long)dirIndex);
            return false; }

        // $INDEX_ROOT (0x90) — résident, toujours présent
        const uint8_t* ir = findAttr(rec, 0x90, false);   // "$I30"
        if (!ir){ RVLOG(L"[raw] listDir(%llu): $INDEX_ROOT absent\n", (unsigned long long)dirIndex); return false; }
        if (ir[8] != 0){ RVLOG(L"[raw] listDir(%llu): $INDEX_ROOT non resident\n", (unsigned long long)dirIndex); return false; }
        uint32_t irValLen = rd32(ir + 0x10); uint16_t irValOff = rd16(ir + 0x14);
        const uint8_t* val = ir + irValOff;
        uint32_t idxBlockSize = rd32(val + 8);
        const uint8_t* nodeHdr = val + 0x10;
        uint32_t usedSize = rd32(nodeHdr + 4);
        const uint8_t* irEnd = val + irValLen;
        const uint8_t* limit = nodeHdr + usedSize;
        if (limit > irEnd) limit = irEnd;
        parseIndexNode(nodeHdr, limit, out);
        const size_t depuisRoot = out.size();

        // $INDEX_ALLOCATION (0xA0) — non résident, présent si l'index déborde
        const uint8_t* ia = findAttr(rec, 0xA0, false);   // "$I30"

        /* Si l'attribut n'est pas dans l'enregistrement de base, il peut être
           ÉCLATÉ via $ATTRIBUTE_LIST — même mécanisme que pour le $DATA de la
           ruche SOFTWARE. Cas observé sur un dossier `Recent` très actif :
           l'index débordait mais $INDEX_ALLOCATION était introuvable ici, si
           bien que listDir rendait « 0 entrée » sur un dossier plein. */
        if (!ia && idxBlockSize){
            std::vector<Run> runsEclates;
            uint64_t tailleEclatee = 0;
            if (collectRunsFromAttributeList(rec, runsEclates, tailleEclatee, 0xA0)
                && !runsEclates.empty()){
                RVLOG(L"[raw] listDir(%llu): $INDEX_ALLOCATION via $ATTRIBUTE_LIST\n",
                      (unsigned long long)dirIndex);
                lireBlocsIndex(runsEclates, tailleEclatee, idxBlockSize, out);
                return true;
            }
        }
        /* Un répertoire volumineux ne garde dans $INDEX_ROOT qu'un nœud terminal
           pointant vers les blocs d'index : TOUTES ses entrées viennent alors de
           $INDEX_ALLOCATION. D'où la trace séparée des deux sources — sans elle,
           « 0 entrée » ne dit pas laquelle des deux a échoué. */
        RVLOG(L"[raw] listDir(%llu): %llu entree(s) depuis $INDEX_ROOT, "
              L"$INDEX_ALLOCATION %ls (blockSize=%u)\n",
              (unsigned long long)dirIndex, (unsigned long long)depuisRoot,
              ia ? (ia[8] != 0 ? L"non resident" : L"RESIDENT (inattendu)") : L"absent",
              idxBlockSize);
        if (ia && ia[8] != 0 && idxBlockSize){
            uint64_t realSize = rd64(ia + 0x30);
            std::vector<Run> runs = decodeRuns(ia + rd16(ia + 0x20), ia + rd32(ia + 0x04));
            lireBlocsIndex(runs, realSize, idxBlockSize, out);
        }
        return true;
    }

    /*! Parcourt les blocs d'index (INDX) décrits par `runs` et en extrait les
     *  entrées. Partagé par les deux chemins d'accès à $INDEX_ALLOCATION : depuis
     *  l'enregistrement de base, ou via $ATTRIBUTE_LIST quand il est éclaté. */
    void lireBlocsIndex(const std::vector<Run>& runs, uint64_t realSize,
                        uint32_t idxBlockSize, std::vector<RawDirEntry>& out){
        if (!idxBlockSize) return;
        std::vector<uint8_t> blk(idxBlockSize);
        uint64_t blocsLus = 0, blocsSansIndx = 0;
        for (uint64_t pos = 0; pos + idxBlockSize <= realSize; pos += idxBlockSize){
            ++blocsLus;
            if (!readVirtual(runs, pos, idxBlockSize, blk.data())){
                RVLOG(L"[raw] bloc d'index a l'offset %llu illisible\n",
                      (unsigned long long)pos);
                break;
            }
            if (memcmp(blk.data(), "INDX", 4) != 0){ ++blocsSansIndx; continue; }
            applyFixup(blk.data(), idxBlockSize, bytesPerSector_);
            const uint8_t* nh = blk.data() + 0x18;      // node header après l'en-tête INDX
            uint32_t used = rd32(nh + 4);
            const uint8_t* lim = nh + used;
            if (lim > blk.data() + idxBlockSize) lim = blk.data() + idxBlockSize;
            parseIndexNode(nh, lim, out);
        }
        RVLOG(L"[raw] blocs d'index: realSize=%llu, %llu lu(s), "
              L"%llu sans signature INDX, total %llu entree(s)\n",
              (unsigned long long)realSize, (unsigned long long)blocsLus,
              (unsigned long long)blocsSansIndx, (unsigned long long)out.size());
    }
};

} // namespace

void RawHiveSetVerbose(bool on){ g_verbose = on; }
void RawHiveSetProgress(RawHiveProgressFn fn){ g_progress = fn; }

HRESULT ExtractFilesRaw(const std::wstring& volumeLetter,
                        const std::vector<std::pair<std::wstring, std::wstring>>& items,
                        std::vector<HRESULT>* perItem,
                        std::vector<std::wstring>* md5PerItem){
    NtfsVolume vol;                       // volume ouvert UNE fois pour tous les items
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)){ if (perItem) perItem->assign(items.size(), hr); return hr; }
    HRESULT overall = S_OK;
    for (const auto& it : items){
        uint64_t index = 0; HRESULT h;
        std::wstring empreinte;
        if (!vol.resolvePath(it.first, index)) h = HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        else h = vol.extractData(index, it.second, it.first,
                                 md5PerItem ? &empreinte : nullptr);
        if (perItem) perItem->push_back(h);
        if (md5PerItem) md5PerItem->push_back(empreinte);
        if (FAILED(h)) overall = S_FALSE;
    }
    return overall;
}

HRESULT ExtractFileRaw(const std::wstring& volumeLetter,
                       const std::wstring& filePathOnVolume,
                       const std::wstring& outFile){
    std::vector<HRESULT> r;
    ExtractFilesRaw(volumeLetter, {{filePathOnVolume, outFile}}, &r);
    return r.empty() ? E_FAIL : r[0];
}

/* Compare deux extensions sans tenir compte de la casse (ASCII). */
static bool extensionMatches(const std::wstring& nom, const std::vector<std::wstring>& extensions){
    if (extensions.empty()) return true;              // pas de filtre : tout est retenu
    const size_t point = nom.rfind(L'.');
    if (point == std::wstring::npos) return false;
    const std::wstring ext = nom.substr(point);
    for (const std::wstring& attendue : extensions)
        if (iequals(ext, attendue)) return true;
    return false;
}

HRESULT ListDirectoryRaw(const std::wstring& volumeLetter,
                         const std::wstring& dirPathOnVolume,
                         std::vector<RawDirEntry>& out){
    out.clear();
    NtfsVolume vol;
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)) return hr;

    uint64_t index = 0;
    if (!vol.resolvePath(dirPathOnVolume, index))
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    if (!vol.listDir(index, out))
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    return ERROR_SUCCESS;
}

HRESULT ExtractDirectoryRaw(const std::wstring& volumeLetter,
                            const std::wstring& dirPathOnVolume,
                            const std::wstring& outDir,
                            const std::vector<std::wstring>& extensions,
                            size_t* extracted,
                            std::wstring* diagnostic){
    if (extracted) *extracted = 0;
    if (diagnostic) diagnostic->clear();

    NtfsVolume vol;                       // volume ouvert UNE fois pour tout le répertoire
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)){
        if (diagnostic) *diagnostic = L"volume inaccessible";
        return hr;
    }

    uint64_t dirIndex = 0;
    if (!vol.resolvePath(dirPathOnVolume, dirIndex)){
        // Répertoire absent : cas nominal en collecte, pas une erreur.
        RVLOG(L"[raw] repertoire absent: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"chemin non resolu (repertoire absent ?)";
        return ERROR_SUCCESS;
    }

    std::vector<RawDirEntry> entries;
    if (!vol.listDir(dirIndex, entries)){
        RVLOG(L"[raw] enumeration impossible: %ls\n", dirPathOnVolume.c_str());
        if (diagnostic) *diagnostic = L"enumeration de l'index impossible";
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outDir), ec);

    size_t fichiers = 0, retenus = 0, echecs = 0;
    HRESULT overall = ERROR_SUCCESS;
    for (const RawDirEntry& e : entries){
        if (e.isDirectory) continue;                       // non récursif
        if (e.name == L"." || e.name == L"..") continue;
        ++fichiers;
        if (!extensionMatches(e.name, extensions)) continue;
        ++retenus;

        const std::wstring cible = outDir + L"\\" + e.name;
        HRESULT h = vol.extractData(e.mftIndex, cible);
        if (FAILED(h)){
            RVLOG(L"[raw] extraction echouee: %ls\n", e.name.c_str());
            ++echecs;
            overall = S_FALSE;
        }
        else if (extracted) ++*extracted;
    }

    /* Le detail permet de distinguer trois causes d'un decompte a zero :
       index vide, filtre d'extension trop strict, ou echecs d'extraction. */
    if (diagnostic){
        *diagnostic = std::to_wstring(entries.size()) + L" entree(s), "
                    + std::to_wstring(fichiers) + L" fichier(s), "
                    + std::to_wstring(retenus) + L" retenu(s)";
        if (echecs) *diagnostic += L", " + std::to_wstring(echecs) + L" echec(s)";
    }
    return overall;
}

/* Extraction récursive : le volume est ouvert UNE fois pour toute l'arborescence,
   contrairement à un appel répété de ExtractDirectoryRaw qui le rouvrirait à
   chaque sous-répertoire. */
namespace {

HRESULT extraireArborescence(NtfsVolume& vol, uint64_t dirIndex,
                             const std::wstring& cheminVolume,
                             const std::wstring& outDir,
                             const std::vector<std::wstring>& extensions,
                             size_t* extracted, unsigned profondeurRestante){
    std::vector<RawDirEntry> entries;
    if (!vol.listDir(dirIndex, entries)){
        RVLOG(L"[raw] arbo: index illisible pour %ls\n", cheminVolume.c_str());
        return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND);
    }

    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(outDir), ec);

    HRESULT global = ERROR_SUCCESS;
    for (const RawDirEntry& e : entries){
        if (e.name == L"." || e.name == L"..") continue;

        if (e.isDirectory){
            if (profondeurRestante == 0){
                RVLOG(L"[raw] arbo: profondeur max atteinte a %ls\n", e.name.c_str());
                continue;
            }
            const HRESULT h = extraireArborescence(
                vol, e.mftIndex, cheminVolume + L"\\" + e.name,
                outDir + L"\\" + e.name, extensions, extracted, profondeurRestante - 1);
            if (h == S_FALSE) global = S_FALSE;
            continue;
        }
        if (!extensionMatches(e.name, extensions)) continue;

        std::wstring empreinte;   // non exploitée ici, mais évite une relecture
        if (FAILED(vol.extractData(e.mftIndex, outDir + L"\\" + e.name,
                                   cheminVolume + L"\\" + e.name, &empreinte))){
            RVLOG(L"[raw] arbo: extraction echouee %ls\n", e.name.c_str());
            global = S_FALSE;
        }
        else if (extracted) ++*extracted;
    }
    return global;
}

} // namespace

HRESULT ExtractDirectoryTreeRaw(const std::wstring& volumeLetter,
                                const std::wstring& dirPathOnVolume,
                                const std::wstring& outDir,
                                const std::vector<std::wstring>& extensions,
                                size_t* extracted,
                                unsigned profondeurMax){
    if (extracted) *extracted = 0;

    NtfsVolume vol;
    HRESULT hr = vol.open(volumeLetter);
    if (FAILED(hr)) return hr;

    uint64_t dirIndex = 0;
    if (!vol.resolvePath(dirPathOnVolume, dirIndex)){
        // Répertoire absent : cas nominal en collecte, pas une erreur.
        RVLOG(L"[raw] arbo: repertoire absent %ls\n", dirPathOnVolume.c_str());
        return ERROR_SUCCESS;
    }
    return extraireArborescence(vol, dirIndex, dirPathOnVolume, outDir,
                                extensions, extracted, profondeurMax);
}
