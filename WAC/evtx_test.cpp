/*  evtx_test.cpp — harnais de validation du parseur EVTX, hors de WAC.
 *
 *  Même intention que raw_hive_test : un défaut de parsing produit du JSON
 *  valide et faux, que le harnais de VM ne voit pas. Ce test-ci confronte le
 *  décodeur à de vrais journaux, dont des journaux volontairement abîmés
 *  (chunk à signature fausse, journal non fermé, tailles nulles).
 *
 *  Usage : evtx_test.exe <fichier.evtx> [nb enregistrements a afficher]
 *          evtx_test.exe --collecte <racine> <sortie>   (chaine COMPLETE :
 *          lit <racine>\Windows\System32\winevt\Logs\*.evtx comme le fait
 *          la collecte, et ecrit <sortie>\events.json. Eprouve la
 *          correspondance XML -> Event et l'ecriture en flux, que le decodage
 *          seul ne couvre pas.)
 *          evtx_test.exe <fichier.evtx> --dump   (un enregistrement par ligne,
 *          « identifiant<TAB>xml » en UTF-8, sauts de ligne echappes, pour
 *          comparaison automatique avec une implementation independante)
 *  Exclu du build de WAC par le motif « _test.cpp » de build-windows.sh.
 */
#include "evtx.h"
#include "tools.h"
#include "events.h"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <map>
#include <vector>
#include <fcntl.h>
#include <io.h>

/*  `conf` est la configuration globale de WAC, définie par main.cpp. Ce harnais
 *  n'embarque pas main.cpp : il en fournit une instance vide. evtx.cpp ne la
 *  lit pas — c'est tools.cpp qui la référence — mais l'éditeur de liens la
 *  réclame. Une instance par défaut suffit et garde le test isolé.
 */
AppliConf conf;

//! Ecrit une chaine large sur stdout en UTF-8, sans passer par la page de code
//! de la console : la comparaison automatique exige des octets stables.
static void writeUtf8(const std::wstring& s) {
	if (s.empty()) return;
	const int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0, nullptr, nullptr);
	if (n <= 0) return;
	std::vector<char> buffer(n);
	WideCharToMultiByte(CP_UTF8, 0, s.c_str(), (int)s.size(), buffer.data(), n, nullptr, nullptr);
	fwrite(buffer.data(), 1, n, stdout);
}

int wmain(int argc, wchar_t** argv) {
	if (argc < 2) {
		wprintf(L"usage: evtx_test <fichier.evtx> [nb|--dump]\n");
		wprintf(L"       evtx_test --collecte <racine> <sortie>\n");
		return 2;
	}

	/*  Ancienne STRATEGIE D'ECRITURE, sur les memes donnees : tous les
	 *  evenements construits en memoire, puis serialises d'un bloc, comme le
	 *  faisait la collecte par API. Le decodage est identique — seule l'ecriture
	 *  change — ce qui isole le cout de la strategie de celui de la source, et
	 *  permet une comparaison de memoire que la machine examinee, elle, ne
	 *  permet pas de refaire a l'identique.
	 */
	if (wcscmp(argv[1], L"--collecte-memoire") == 0) {
		if (argc < 4) { wprintf(L"usage: evtx_test --collecte-memoire <racine> <sortie>\n"); return 2; }
		conf.mountpoint = argv[2];
		int n = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, nullptr, 0, nullptr, nullptr);
		std::vector<char> tmp(n > 0 ? n : 1);
		WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, tmp.data(), n, nullptr, nullptr);
		conf._outputDir = tmp.data();

		const std::wstring directory = extractedPath(L"\\Windows\\System32\\winevt\\Logs");
		std::vector<Json> all;
		unsigned long long read = 0;
		for (const std::filesystem::path& j : listFilesByExtension(directory, { L".evtx" })) {
			const std::wstring canal = EvtxChannelFromFileName(j.filename().wstring());
			EvtxReadFile(j.wstring(), [&](const EvtxRecord& e) {
				const std::unique_ptr<XmlNode> root = xmlParse(e.xml);
				if (root) { all.push_back(Event(*root, canal, e.id,
				                     j.filename().wstring()).toJson()); ++read; }
				return true;
			}, nullptr);
		}
		Json arr = Json::arr();
		for (Json& o : all) arr.push(std::move(o));
		const HRESULT hr = writeJsonFile("events.json", arr);
		wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
		wprintf(L"evenements   : %llu\n", read);
		return 0;
	}

	// Chaine complete : la meme que celle qu'execute WAC, sans le reste de la
	// collecte. `mountpoint` est la racine des copies extraites (cf. tools.h).
	if (wcscmp(argv[1], L"--collecte") == 0) {
		if (argc < 4) { wprintf(L"usage: evtx_test --collecte <racine> <sortie>\n"); return 2; }
		conf.mountpoint = argv[2];
		int n = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, nullptr, 0, nullptr, nullptr);
		std::vector<char> tmp(n > 0 ? n : 1);
		WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, tmp.data(), n, nullptr, nullptr);
		conf._outputDir = tmp.data();
		Events ev;
		const HRESULT hr = ev.getData();
		wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
		wprintf(L"journaux     : %llu\n", ev.files);
		wprintf(L"evenements   : %llu\n", ev.read);
		wprintf(L"ecartes      : %llu\n", ev.unreadable);
		return 0;
	}
	const bool dump = (argc > 2) && (wcscmp(argv[2], L"--dump") == 0);
	const long toDisplay = (!dump && argc > 2) ? wcstol(argv[2], nullptr, 10) : 0;
	if (dump) _setmode(_fileno(stdout), _O_BINARY);

	long displayed = 0;
	unsigned long long empties = 0, withSystem = 0, withEventData = 0;
	std::map<std::wstring, unsigned long long> providers;

	EvtxSummary summary;
	const HRESULT hr = EvtxReadFile(argv[1], [&](const EvtxRecord& e) {
		if (e.xml.empty()) ++empties;
		if (e.xml.find(L"<System") != std::wstring::npos) ++withSystem;
		if (e.xml.find(L"<EventData") != std::wstring::npos
		    || e.xml.find(L"<UserData") != std::wstring::npos) ++withEventData;
		// Fournisseur : premier attribut Name du premier Provider.
		const size_t p = e.xml.find(L"<Provider Name=\"");
		if (p != std::wstring::npos) {
			const size_t d = p + 16, f = e.xml.find(L'"', d);
			if (f != std::wstring::npos) ++providers[e.xml.substr(d, f - d)];
		}
		if (dump) {
			std::wstring line = std::to_wstring(e.id) + L"\t";
			for (wchar_t ch : e.xml) {
				if (ch == L'\n') line += L"\\n";
				else if (ch == L'\r') line += L"\\r";
				else if (ch == L'\\') line += L"\\\\";
				else line += ch;
			}
			line += L"\n";
			writeUtf8(line);
			return true;
		}
		if (displayed < toDisplay) {
			++displayed;
			wprintf(L"--- enregistrement %llu\n%ls\n", e.id, e.xml.c_str());
		}
		return true;
	}, &summary);

	if (dump) return 0;
	wprintf(L"fichier      : %ls\n", argv[1]);
	wprintf(L"hresult      : 0x%08lx\n", (unsigned long)hr);
	wprintf(L"diagnostic   : %ls\n", summary.diagnostic.c_str());
	wprintf(L"lus          : %llu\n", summary.read);
	wprintf(L"illisibles   : %llu\n", summary.unreadable);
	wprintf(L"xml vide     : %llu\n", empties);
	wprintf(L"avec System  : %llu\n", withSystem);
	wprintf(L"avec Data    : %llu\n", withEventData);
	wprintf(L"fournisseurs : %llu\n", (unsigned long long)providers.size());
	for (const auto& kv : providers)
		if (kv.second > summary.read / 20) wprintf(L"   %-60ls %llu\n", kv.first.c_str(), kv.second);
	return 0;
}
