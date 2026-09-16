/*  event_messages_test.cpp — eprouve, ETAPE PAR ETAPE, la chaine qui rend le
 *  message en clair d'un evenement.
 *
 *  POURQUOI CE HARNAIS. La chaine compte cinq maillons, et un echec de masse ne
 *  dit pas lequel a cede : la collecte reste valide, le champ disparait, et
 *  chaque hypothese demandait jusque-la une collecte complete de plusieurs
 *  minutes pour etre eliminee. Ce programme fait le meme trajet et affiche
 *  chaque etape.
 *
 *  Il tourne SUR LA MACHINE examinee (ou une VM de test), la ruche SOFTWARE et
 *  les binaires de fournisseurs n'etant lisibles que la.
 *
 *  Usage : event_messages_test <ruche SOFTWARE> <guid> [id[:version] ...]
 *  Exclu du build de WAC par le motif « _test.cpp ».
 */
#include "tools.h"
#include "pe_resource.h"
#include "wevt.h"
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

AppliConf conf;

namespace {

void ligne(const wchar_t* etape, bool ok, const std::wstring& detail) {
	wprintf(L"  %ls  %-42ls %ls\n", ok ? L"ok   " : L"ECHEC", etape, detail.c_str());
}

} // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc < 3) {
		wprintf(L"usage: event_messages_test <ruche SOFTWARE> <guid> [id[:version] ...]\n");
		return 2;
	}
	conf.systemDrive = L"C:";

	// 1. La ruche, et la cle du fournisseur.
	ORHKEY software = NULL;
	HRESULT hr = OROpenHive(argv[1], &software);
	ligne(L"ouverture de la ruche SOFTWARE", hr == ERROR_SUCCESS,
	      hr == ERROR_SUCCESS ? argv[1] : L"code " + std::to_wstring(hr));
	if (hr != ERROR_SUCCESS) return 1;
	conf.Software = software;

	std::wstring guid = argv[2];
	const std::wstring cle =
		L"Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\" + guid;
	std::wstring declare;
	HRESULT hrv = getRegSzValue(software, cle.c_str(), L"ResourceFileName", &declare);
	if (hrv != ERROR_SUCCESS || declare.empty())
		hrv = getRegSzValue(software, cle.c_str(), L"MessageFileName", &declare);
	ligne(L"ResourceFileName / MessageFileName", hrv == ERROR_SUCCESS && !declare.empty(),
	      declare.empty() ? L"(absent)" : declare);
	if (declare.empty()) return 1;

	// 2. La resolution du chemin.
	const std::wstring resolu = cheminBinaire(declare);
	std::vector<std::wstring> candidats;
	if (!resolu.empty()) candidats.push_back(resolu);
	{
		const std::wstring nomSeul = std::filesystem::path(
			resolu.empty() ? declare : resolu).filename().wstring();
		if (!nomSeul.empty())
			candidats.push_back(conf.systemDrive + L"\\Windows\\System32\\" + nomSeul);
	}
	std::wstring trouve;
	for (const std::wstring& c : candidats) {
		std::error_code ec;
		const bool existe = std::filesystem::exists(c, ec);
		ligne(L"candidat de chemin", existe, c);
		if (existe && trouve.empty()) trouve = c;
	}
	if (trouve.empty()) return 1;

	// 3. Les deux ressources.
	PeResource pe;
	const bool ouvert = pe.ouvrir(trouve);
	ligne(L"lecture du PE", ouvert, ouvert ? trouve : pe.erreur());
	if (!ouvert) return 1;

	std::wstring types;
	for (const std::wstring& t : pe.typesPresents()) types += t + L" ";
	ligne(L"types de ressources presents", !types.empty(), types);

	const std::vector<uint8_t> brutWevt = pe.ressourceNommee(L"WEVT_TEMPLATE");
	ligne(L"WEVT_TEMPLATE", !brutWevt.empty(),
	      std::to_wstring(brutWevt.size()) + L" octets");

	std::vector<uint8_t> brutMsg = pe.ressource(PE_RT_MESSAGETABLE);
	std::wstring ouMsg = L"dans le binaire";
	if (brutMsg.empty()) {
		// Satellite localise : la table n'est pas dans la DLL sur un systeme
		// localise, mais dans <langue>\<nom>.mui.
		const std::filesystem::path p = trouve;
		for (PCWSTR l : { L"fr-FR", L"en-US", L"de-DE", L"es-ES" }) {
			const std::wstring mui = p.parent_path().wstring() + L"\\" + l + L"\\"
			                       + p.filename().wstring() + L".mui";
			std::error_code ec;
			if (!std::filesystem::exists(mui, ec)) continue;
			PeResource peMui;
			if (!peMui.ouvrir(mui)) continue;
			brutMsg = peMui.ressource(PE_RT_MESSAGETABLE);
			if (!brutMsg.empty()) { ouMsg = mui; break; }
		}
	}
	ligne(L"MESSAGETABLE", !brutMsg.empty(),
	      std::to_wstring(brutMsg.size()) + L" octets, " + ouMsg);

	// 4. L'analyse, puis la resolution des identifiants demandes.
	MetadonneesWevt meta;
	const size_t nbEv = meta.analyser(brutWevt, guid);
	ligne(L"evenements decrits", nbEv > 0, std::to_wstring(nbEv));
	TableMessages table;
	const size_t nbMsg = table.analyser(brutMsg);
	ligne(L"messages lus", nbMsg > 0, std::to_wstring(nbMsg));

	for (int i = 3; i < argc; ++i) {
		std::wstring a = argv[i];
		const size_t sep = a.find(L':');
		const uint16_t id = (uint16_t)wcstoul(a.substr(0, sep).c_str(), nullptr, 10);
		const uint8_t ver = (uint8_t)(sep == std::wstring::npos ? 0
		                              : wcstoul(a.substr(sep + 1).c_str(), nullptr, 10));
		const uint32_t m = meta.identifiantMessage(id, ver);
		const std::wstring modele = m ? table.texte(m) : std::wstring();
		ligne(L"evenement -> message", !modele.empty(),
		      std::to_wstring(id) + L" v" + std::to_wstring(ver) + L" -> "
		      + std::to_wstring(m));
		if (!modele.empty()) wprintf(L"         %ls\n", modele.substr(0, 160).c_str());
	}

	ORCloseHive(software);
	return 0;
}
