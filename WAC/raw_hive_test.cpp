/* raw_hive_test.cpp — harnais de validation de la lecture brute NTFS.
 * À exécuter sur Windows, en administrateur (accès volume brut).
 *
 * Usage : raw_hive_test.exe [volume] [chemin] [sortie] [--fix] [--list]
 *   --fix   applique MakeHiveLoadable() sur la ruche extraite
 *   --list  énumère un répertoire au lieu d'extraire un fichier
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

    bool fix = false, list = false;
    std::vector<const wchar_t*> positionnels;
    for (int i = 1; i < argc; ++i){
        if (wcscmp(argv[i], L"--fix") == 0)       fix = true;
        else if (wcscmp(argv[i], L"--list") == 0) list = true;
        else positionnels.push_back(argv[i]);
    }
    const wchar_t* vol  = positionnels.size() > 0 ? positionnels[0] : L"C";
    const wchar_t* path = positionnels.size() > 1 ? positionnels[1]
                                                  : L"\\Windows\\System32\\config\\SYSTEM";
    const wchar_t* out  = positionnels.size() > 2 ? positionnels[2] : L"SYSTEM.hiv";

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
