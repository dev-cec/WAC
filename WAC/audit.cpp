/*  audit.cpp — voir audit.h. */
#include "audit.h"
#include <vector>
#include <sddl.h>
#include "tools.h"

namespace Footprint {
const wchar_t* VOLUME_BRUT  = L"Lecture brute du volume (\\\\.\\C:) : aucun acces fichier, "
                              L"donc aucun horodatage de la cible modifie. Un audit d'acces aux "
                              L"objets, s'il est actif, peut journaliser l'ouverture du volume.";
const wchar_t* RUCHE_COPIE  = L"Ouverture d'une ruche COPIEE sur le support de collecte : "
                              L"la ruche d'origine n'est pas touchee.";
const wchar_t* FICHIER_COPIE = L"Lecture d'un fichier d'artefact extrait (copie sur le support "
                              L"de collecte) : aucun acces a l'original, aucun horodatage modifie, "
                              L"aucun service du systeme examine sollicite.";
const wchar_t* RUCHE_PATCH  = L"Modification de 8 octets du bloc de base d'une ruche COPIEE "
                              L"(alignement des numeros de sequence). L'original n'est pas "
                              L"modifie ; empreinte avant patch consignee.";
const wchar_t* RUCHE_REJEU  = L"Application des journaux de transaction a la ruche COPIEE, "
                              L"jamais a l'originale. Le contenu d'origine de chaque page remplacee "
                              L"est conserve dans un journal d'annulation : la copie brute reste "
                              L"reconstructible a l'octet.";
const wchar_t* SCM          = L"Une seule enumeration du gestionnaire de services, en lecture "
                              L"(EnumServicesStatusExW), pour relever l'etat courant. Aucun "
                              L"handle ouvert service par service : la configuration provient "
                              L"de la ruche SYSTEM copiee.";
const wchar_t* PROCESSUS    = L"Enumeration des processus : ouverture de handles de processus "
                              L"et de jetons (auditable si la politique le prevoit).";
const wchar_t* SESSIONS     = L"Interrogation des sessions ouvertes (LSA / Terminal Services) : "
                              L"sollicite LSASS, sans modification d'artefact.";
const wchar_t* ECRITURE_USB = L"Ecriture sur le support de collecte uniquement. Aucune ecriture "
                              L"sur le systeme examine.";
} // namespace Footprint

namespace {

//! Une opération consignée.
struct Operation {
	unsigned     sequence = 0;
	std::wstring horodatageUtc;
	std::wstring horodatageLocal;
	std::wstring operation;
	std::wstring cible;
	std::wstring resultat;      //!< "OK" ou le code et son message
	std::wstring footprint;
};

std::vector<Operation> g_operations;
unsigned     g_sequence      = 0;
std::wstring g_debutUtc, g_debutLocal;
FILETIME     g_debut         = { 0, 0 };
std::wstring g_ligneCommande;
std::wstring g_machine, g_utilisateur, g_sid, g_fuseau;
long         g_biaisMinutes  = 0;
bool         g_eleve         = false;

//! Horodatage courant, en UTC et en heure locale.
void maintenant(std::wstring& utc, std::wstring& local, FILETIME* brut = nullptr) {
	SYSTEMTIME stUtc = { 0 };
	GetSystemTime(&stUtc);
	utc = timeToIso8601(stUtc, true);

	SYSTEMTIME stLocal = { 0 };
	GetLocalTime(&stLocal);
	local = timeToIso8601(stLocal, false);

	if (brut) SystemTimeToFileTime(&stUtc, brut);
}

//! Contexte de la machine et de l'opérateur au moment de la collecte.
void releverContexte() {
	wchar_t tampon[512] = L"";
	DWORD taille = 512;
	if (GetComputerNameW(tampon, &taille)) g_machine = tampon;

	taille = 512;
	if (GetUserNameW(tampon, &taille)) g_utilisateur = tampon;

	// SID du compte sous lequel WAC s'execute : identifie l'operateur sans
	// ambiguite, meme si le nom de compte a change depuis.
	HANDLE jeton = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &jeton)) {
		DWORD requis = 0;
		GetTokenInformation(jeton, TokenUser, NULL, 0, &requis);
		if (requis) {
			std::vector<BYTE> tamponSid(requis);
			if (GetTokenInformation(jeton, TokenUser, tamponSid.data(), requis, &requis)) {
				LPWSTR texte = nullptr;
				PTOKEN_USER tu = reinterpret_cast<PTOKEN_USER>(tamponSid.data());
				if (ConvertSidToStringSidW(tu->User.Sid, &texte)) {
					g_sid = texte;
					LocalFree(texte);
				}
			}
		}
		TOKEN_ELEVATION elevation = { 0 };
		DWORD longueur = 0;
		if (GetTokenInformation(jeton, TokenElevation, &elevation, sizeof(elevation), &longueur))
			g_eleve = elevation.TokenIsElevated != 0;
		CloseHandle(jeton);
	}

	// Fuseau de la MACHINE EXAMINEE : indispensable pour reinterpreter les dates
	// locales des artefacts ( — le fuseau du suspect, pas celui de
	// l'analyste).
	TIME_ZONE_INFORMATION tz = { 0 };
	const DWORD type = GetTimeZoneInformation(&tz);
	if (type != TIME_ZONE_ID_INVALID) {
		g_fuseau = (type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightName : tz.StandardName;
		// Bias est en minutes A AJOUTER a l'heure locale pour obtenir l'UTC.
		g_biaisMinutes = tz.Bias + ((type == TIME_ZONE_ID_DAYLIGHT) ? tz.DaylightBias : tz.StandardBias);
	}
}

} // namespace

void auditInit(int argc, char* argv[]) {
	g_operations.clear();
	g_sequence = 0;
	maintenant(g_debutUtc, g_debutLocal, &g_debut);

	g_ligneCommande.clear();
	for (int i = 0; i < argc; ++i) {
		if (i) g_ligneCommande += L" ";
		g_ligneCommande += string_to_wstring(argv[i]);
	}

	releverContexte();
}

void auditRecord(const std::wstring& operation, const std::wstring& cible,
                 HRESULT resultat, const wchar_t* footprint) {
	Operation o;
	o.sequence = ++g_sequence;
	maintenant(o.horodatageUtc, o.horodatageLocal);
	o.operation = operation;
	o.cible     = cible;
	/* S_FALSE (1) signifie « réussi, mais partiellement » — typiquement des
	   ruches absentes tolérées par l'extraction. `getErrorMessage()` le traduit
	   comme le code Win32 1, « Fonction incorrecte », ce qui faisait lire un
	   succès partiel comme une panne dans le journal d'audit. Dans une pièce
	   d'enquête, un résultat mal qualifié vaut moins que pas de résultat. */
	if (resultat == ERROR_SUCCESS)
		o.resultat = L"OK";
	else if (resultat == S_FALSE)
		o.resultat = L"PARTIEL (voir le journal de collecte pour le détail)";
	else
		o.resultat = L"0x" + to_hex(resultat) + L" " + getErrorMessage(resultat);
	o.footprint = footprint ? footprint : L"";
	g_operations.push_back(std::move(o));
}

Json auditContexte() {
	Json racine = Json::obj();

	Json outil = Json::obj();
	outil.add(L"Name",        Json::str(L"WAC"));
	outil.add(L"CommandLine", Json::str(g_ligneCommande));
	outil.add(L"BuildDate",   Json::str(string_to_wstring(__DATE__) + L" " + string_to_wstring(__TIME__)));
	racine.add(L"Tool", std::move(outil));

	Json hote = Json::obj();
	hote.add(L"ComputerName", Json::str(g_machine));
	hote.add(L"SystemDrive",  Json::str(conf.systemDrive));

	/* DEUX fuseaux, et c'est voulu.
	   - SuspectTimeZone : releve dans la ruche SYSTEM examinee. C'est LUI qui sert
	     a formater les heures locales des artefacts, et donc la seule reference
	     valable pour interpreter une date locale.
	   - CollectionHostTimeZone : celui de la machine qui a execute WAC.
	   En collecte live les deux coincident. Une DIVERGENCE est un signal : image
	   analysee sur une autre machine, ou fuseau modifie depuis la collecte — dans
	   les deux cas l'analyste doit le savoir. */
	Json suspect = Json::obj();
	if (conf.timeZone.valid) {
		suspect.add(L"KeyName",      Json::str(conf.timeZone.keyName));
		suspect.add(L"StandardName", Json::str(conf.timeZone.standardName));
		suspect.add(L"DaylightName", Json::str(conf.timeZone.daylightName));
		// Minutes a AJOUTER a l'UTC pour obtenir l'heure locale : +120 = UTC+02:00.
		// Sens verifiable dans ce fichier meme (StartLocal = StartUtc + offset).
		suspect.add(L"UtcOffsetMinutes", Json::num((long long)-conf.timeZone.activeBiasMinutes));
		suspect.add(L"Source", Json::str(L"SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation"));
	}
	else {
		suspect.add(L"Source", Json::str(L"non relevé : repli sur le fuseau de la machine de collecte"));
	}
	hote.add(L"SuspectTimeZone", std::move(suspect));

	Json collecteur = Json::obj();
	collecteur.add(L"TimeZone",         Json::str(g_fuseau));
	collecteur.add(L"UtcOffsetMinutes", Json::num((long long)-g_biaisMinutes));
	hote.add(L"CollectionHostTimeZone", std::move(collecteur));

	if (conf.timeZone.valid && conf.timeZone.activeBiasMinutes != g_biaisMinutes)
		hote.add(L"TimeZoneMismatch", Json::boolean(true));

	racine.add(L"Host", std::move(hote));

	Json operateur = Json::obj();
	operateur.add(L"User",     Json::str(g_utilisateur));
	operateur.add(L"Sid",      Json::str(g_sid));
	operateur.add(L"Elevated", Json::boolean(g_eleve));
	racine.add(L"Operator", std::move(operateur));

	return racine;
}

std::wstring auditDebutUtc()   { return g_debutUtc; }
std::wstring auditDebutLocal() { return g_debutLocal; }

HRESULT auditWrite() {
	std::wstring finUtc, finLocal;
	FILETIME fin = { 0, 0 };
	maintenant(finUtc, finLocal, &fin);

	const ULONGLONG d = ((ULONGLONG)g_debut.dwHighDateTime << 32) | g_debut.dwLowDateTime;
	const ULONGLONG f = ((ULONGLONG)fin.dwHighDateTime << 32) | fin.dwLowDateTime;
	const ULONGLONG duree = (f > d) ? (f - d) / 10000000ULL : 0ULL;   // 100 ns -> s

	// MEME contexte que le manifeste de consigne : une seule construction, pour
	// que deux documents de la meme collecte ne puissent pas se contredire.
	Json racine = auditContexte();

	Json collecte = Json::obj();
	collecte.add(L"StartUtc",        Json::str(g_debutUtc));
	collecte.add(L"StartLocal",      Json::str(g_debutLocal));
	collecte.add(L"EndUtc",          Json::str(finUtc));
	collecte.add(L"EndLocal",        Json::str(finLocal));
	collecte.add(L"DurationSeconds", Json::num((unsigned long long)duree));
	collecte.add(L"OperationCount",  Json::num((unsigned long long)g_operations.size()));
	racine.add(L"Collection", std::move(collecte));

	Json operations = Json::arr();
	for (const Operation& o : g_operations) {
		Json j = Json::obj();
		j.add(L"Seq",            Json::num((unsigned long long)o.sequence));
		j.add(L"TimestampUtc",   Json::str(o.horodatageUtc));
		j.add(L"TimestampLocal", Json::str(o.horodatageLocal));
		j.add(L"Operation",      Json::str(o.operation));
		j.add(L"Target",         Json::str(o.cible));
		j.add(L"Result",         Json::str(o.resultat));
		j.add(L"Footprint",      Json::str(o.footprint));
		operations.push(std::move(j));
	}
	racine.add(L"Operations", std::move(operations));

	return writeJsonFile("investigation.json", racine);
}
