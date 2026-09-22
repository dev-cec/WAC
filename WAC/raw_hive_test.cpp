/* raw_hive_test.cpp — harnais de validation de la lecture brute NTFS.
 * À exécuter sur Windows, en administrateur (accès volume brut).
 *
 * Usage : raw_hive_test.exe [volume] [chemin] [sortie] [--fix] [--list] [--attrs]
 *   --fix    applique MakeHiveLoadable() sur la ruche extraite
 *   --list   énumère un répertoire au lieu d'extraire un fichier
 *   --attrs  énumère les ATTRIBUTS $MFT du fichier, sans rien interpréter
 *
 * POURQUOI --attrs. Ce que l'API de Windows montre d'un fichier et ce que le
 * disque contient peuvent différer du tout au tout : un binaire « Compact OS »
 * se présente comme un fichier ordinaire alors qu'il porte un point de reparse,
 * un $DATA creux et un flux nommé qui contient tout. Sans ce regard direct, un
 * fichier extrait entièrement à zéro reste inexplicable.
 *
 * POURQUOI --fix. Une ruche copiée à chaud est toujours « dirty » : sans patch,
 * `reg load` la refuse avec ERROR_BADDB. Le harnais doit donc tester les DEUX
 * sens — sans --fix le chargement doit échouer (ce qui prouve que le patch est
 * nécessaire), avec --fix il doit réussir. Un test qui échoue par construction
 * finit par être ignoré, ce qui est pire que son absence.
 */
#include "raw_hive.h"
#include "hive_recover.h"
#include <cstdio>
#include <string>
#include <vector>

int wmain(int argc, wchar_t** argv){
    RawHiveSetVerbose(true);

    bool fix = false, list = false, attrs = false;
    std::vector<const wchar_t*> positionnels;
    for (int i = 1; i < argc; ++i){
        if (wcscmp(argv[i], L"--fix") == 0)       fix = true;
        else if (wcscmp(argv[i], L"--list") == 0) list = true;
        else if (wcscmp(argv[i], L"--attrs") == 0) attrs = true;
        else positionnels.push_back(argv[i]);
    }
    const wchar_t* vol  = positionnels.size() > 0 ? positionnels[0] : L"C";
    const wchar_t* path = positionnels.size() > 1 ? positionnels[1]
                                                  : L"\\Windows\\System32\\config\\SYSTEM";
    const wchar_t* out  = positionnels.size() > 2 ? positionnels[2] : L"SYSTEM.hiv";

    if (attrs){
        std::vector<RawAttribut> liste;
        const HRESULT hr = ListAttributesRaw(vol, path, liste);
        if (FAILED(hr)){ wprintf(L"ECHEC ListAttributesRaw : 0x%08lx\n", (unsigned long)hr); return 1; }
        wprintf(L"%zu attribut(s) dans l'enregistrement $MFT de %ls\n", liste.size(), path);
        for (const RawAttribut& a : liste){
            wprintf(L"  type 0x%02X  %-18ls %-12ls taille %12llu  drapeaux 0x%04X",
                    a.type,
                    a.nom.empty() ? L"(sans nom)" : a.nom.c_str(),
                    a.resident ? L"resident" : L"non resident",
                    (unsigned long long)a.tailleReelle, a.drapeaux);
            if (a.drapeaux & 0x0001) wprintf(L" COMPRESSE");
            if (a.drapeaux & 0x8000) wprintf(L" CREUX");
            if (a.tagReparse)        wprintf(L"  reparse 0x%08lX", (unsigned long)a.tagReparse);
            if (!a.resident && a.tailleInitialisee != a.tailleReelle)
                wprintf(L"  valides %llu", (unsigned long long)a.tailleInitialisee);
            wprintf(L"\n");
            if (a.type == 0xC0 && !a.apercu.empty()){
                wprintf(L"      contenu :");
                for (size_t k = 0; k < a.apercu.size() && k < 24; ++k) wprintf(L" %02X", a.apercu[k]);
                wprintf(L"\n");
            }
        }
        return 0;
    }

    if (list){
        wprintf(L"Enumeration brute %ls:%ls\n", vol, path);
        std::vector<RawDirEntry> entries;
        HRESULT hr = ListDirectoryRaw(vol, path, entries);
        if (FAILED(hr)){
            wprintf(L"Resultat: 0x%08lX (ECHEC)\n", (unsigned long)hr);
            return 1;
        }
        // Le total est affiche D'ABORD : un probleme d'affichage sur la liste ne
        // doit pas empecher de lire le resultat du test.
        // msvcrt ne gere ni %zu ni les largeurs de champ sur %ls : on s'en tient
        // a %llu avec cast explicite et a %ls sans largeur.
        wprintf(L"Total: %llu entree(s)\n", (unsigned long long)entries.size());
        for (const RawDirEntry& e : entries)
            wprintf(L"  %ls %ls (%llu octets)\n", e.isDirectory ? L"[REP]" : L"     ",
                    e.name.c_str(), (unsigned long long)e.size);
        return 0;
    }

    wprintf(L"Extraction brute %ls:%ls -> %ls\n", vol, path, out);
    HRESULT hr = ExtractFileRaw(vol, path, out);
    wprintf(L"Extraction: 0x%08lX (%ls)\n", (unsigned long)hr, SUCCEEDED(hr) ? L"OK" : L"ECHEC");
    if (FAILED(hr)) return 1;

    if (fix){
        HiveFixInfo info = MakeHiveLoadable(out);
        wprintf(L"Recovery: %ls\n", HiveFixInfoToString(info).c_str());
        if (!info.ok) return 1;
    }
    else {
        wprintf(L"Recovery: NON demande (--fix absent) : la ruche reste dirty,\n"
                L"          `reg load` doit donc la refuser (ERROR_BADDB 1009).\n");
    }
    return 0;
}
