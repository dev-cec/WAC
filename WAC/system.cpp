#include "system.h"

namespace {

/*! Ajoute une valeur au JSON seulement si elle a une source.
*
* POURQUOI OMETTRE PLUTÔT QU'ÉMETTRE VIDE. Une clé présente mais vide se lit
* comme un échec de lecture — l'analyste ne peut pas distinguer « la ruche ne
* contient pas cette valeur » de « WAC n'a pas su la lire ». Les valeurs
* réellement illisibles sont, elles, consignées dans le journal et dans
* investigation.json.
*/
void ajouterSiRenseigne(Json& o, PCWSTR nom, const std::wstring& valeur) {
	if (!valeur.empty()) o.add(nom, Json::str(valeur));
}

/*! Traduit PROCESSOR_ARCHITECTURE (valeur texte de la ruche) en libellé.
* La ruche stocke la chaîne d'environnement, pas la constante numérique : elle
* est donc convertie vers le même vocabulaire que `os_architecture()` afin que
* la sortie reste comparable entre versions de WAC.
*/
std::wstring architectureDepuisRuche(const std::wstring& valeur) {
	if (valeur == L"AMD64") return os_architecture(PROCESSOR_ARCHITECTURE_AMD64);
	if (valeur == L"x86")   return os_architecture(PROCESSOR_ARCHITECTURE_INTEL);
	if (valeur == L"ARM64") return os_architecture(PROCESSOR_ARCHITECTURE_ARM64);
	if (valeur == L"ARM")   return os_architecture(PROCESSOR_ARCHITECTURE_ARM);
	if (valeur == L"IA64")  return os_architecture(PROCESSOR_ARCHITECTURE_IA64);
	// Valeur inattendue : restituée telle quelle plutôt que masquée derrière
	// « inconnue », pour que le cas non couvert reste visible.
	return valeur.empty() ? os_architecture(PROCESSOR_ARCHITECTURE_UNKNOWN) : valeur;
}

//! Convertit un temps Unix (secondes depuis 1970, UTC) en FILETIME.
FILETIME unixVersFiletime(unsigned long long secondes) {
	const unsigned long long DECALAGE_1601_1970 = 11644473600ULL;
	const unsigned long long cent_ns = (secondes + DECALAGE_1601_1970) * 10000000ULL;
	FILETIME ft = { (DWORD)(cent_ns & 0xFFFFFFFFULL), (DWORD)(cent_ns >> 32) };
	return ft;
}

} // namespace

HRESULT SystemInfo::getData() {

	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Operating System :");
	log(0, L"*******************************************************************************************************************");
	log(1, L"➕System");

	/*******************************************************************
	* 1. Identité de la machine — ruche SYSTEM
	*******************************************************************/
	if (conf.CurrentControlSet) {
		log(3, L"🔈getRegSzValue ComputerName");
		getRegSzValue(conf.CurrentControlSet, L"Control\\ComputerName\\ComputerName",
		              L"ComputerName", &netbiosName);

		/* Nom DNS. `Hostname` est le nom en vigueur, `NV Hostname` celui qui a
		   été persisté : ils ne diffèrent qu'entre un renommage et le
		   redémarrage suivant, cas qui mérite justement d'être visible. */
		log(3, L"🔈getRegSzValue Tcpip Hostname");
		if (getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
		                  L"Hostname", &computerName) != ERROR_SUCCESS)
			getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
			              L"NV Hostname", &computerName);
		if (computerName.empty()) computerName = netbiosName;

		log(3, L"🔈getRegSzValue Tcpip Domain");
		if (getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
		                  L"Domain", &domainName) != ERROR_SUCCESS || domainName.empty())
			getRegSzValue(conf.CurrentControlSet, L"Services\\Tcpip\\Parameters",
			              L"NV Domain", &domainName);
		if (domainName.empty()) domainName = L"WORKGROUP";

		std::wstring archiBrute;
		log(3, L"🔈getRegSzValue PROCESSOR_ARCHITECTURE");
		getRegSzValue(conf.CurrentControlSet, L"Control\\Session Manager\\Environment",
		              L"PROCESSOR_ARCHITECTURE", &archiBrute);
		osArchitecture = architectureDepuisRuche(archiBrute);

		log(2, L"❇️Computer name : " + computerName);
		log(2, L"❇️Domain name : " + domainName);
	}
	else
		log(2, L"🔥CurrentControlSet indisponible : identite machine non relevee");

	/*******************************************************************
	* 2. Installation — ruche SOFTWARE
	*******************************************************************/
	if (conf.Software) {
		PCWSTR cle = L"Microsoft\\Windows NT\\CurrentVersion";

		log(3, L"🔈getRegSzValue ProductName");
		getRegSzValue(conf.Software, cle, L"ProductName",            &productNameRaw);
		getRegSzValue(conf.Software, cle, L"EditionID",              &editionId);
		getRegSzValue(conf.Software, cle, L"InstallationType",       &installationType);
		getRegSzValue(conf.Software, cle, L"BuildLabEx",             &buildLabEx);
		getRegSzValue(conf.Software, cle, L"CSDVersion",             &servicePack);
		getRegSzValue(conf.Software, cle, L"RegisteredOwner",        &registeredOwner);
		getRegSzValue(conf.Software, cle, L"RegisteredOrganization", &registeredOrganization);
		getRegSzValue(conf.Software, cle, L"ProductId",              &productId);
		getRegSzValue(conf.Software, cle, L"SystemRoot",             &systemRoot);

		/* DisplayVersion (« 23H2 ») a remplacé ReleaseId (« 2009 », figé) à
		   partir de la version 20H2 : on prend le premier disponible. */
		if (getRegSzValue(conf.Software, cle, L"DisplayVersion", &displayVersion) != ERROR_SUCCESS)
			getRegSzValue(conf.Software, cle, L"ReleaseId", &displayVersion);

		/* Numéro de version. CurrentMajorVersionNumber / CurrentMinorVersionNumber
		   n'existent qu'à partir de Windows 10 ; avant, seule la chaîne
		   `CurrentVersion` (« 6.1 ») porte l'information. */
		std::wstring build;
		getRegSzValue(conf.Software, cle, L"CurrentBuildNumber", &build);
		if (build.empty()) getRegSzValue(conf.Software, cle, L"CurrentBuild", &build);

		DWORD majeur = 0, mineur = 0;
		if (getRegDwordValue(conf.Software, cle, L"CurrentMajorVersionNumber", &majeur) == ERROR_SUCCESS) {
			getRegDwordValue(conf.Software, cle, L"CurrentMinorVersionNumber", &mineur);
			version = std::to_wstring(majeur) + L"." + std::to_wstring(mineur);
		}
		else
			getRegSzValue(conf.Software, cle, L"CurrentVersion", &version);
		if (!build.empty()) version += (version.empty() ? L"" : L".") + build;

		// UBR = révision mensuelle : distingue deux machines de même build.
		DWORD ubr = 0;
		if (getRegDwordValue(conf.Software, cle, L"UBR", &ubr) == ERROR_SUCCESS && !version.empty())
			version += L"." + std::to_wstring(ubr);

		/* Correction du libellé de l'OS (cf. en-tête). Windows 11 se déclare
		   « Windows 10 » dans ProductName ; le build est le seul discriminant. */
		osName = productNameRaw;
		const unsigned long numeroBuild = build.empty() ? 0UL : wcstoul(build.c_str(), nullptr, 10);
		if (numeroBuild >= 22000 && osName.find(L"Windows 10") != std::wstring::npos) {
			osName.replace(osName.find(L"Windows 10"), 10, L"Windows 11");
			log(2, L"❇️ProductName corrige : build " + build + L" => " + osName);
		}

		/* Date d'installation. `InstallTime` (REG_QWORD, FILETIME UTC) existe
		   depuis Windows 8 et est précise ; `InstallDate` (REG_DWORD, temps Unix
		   UTC) est le repli pour les systèmes antérieurs. */
		unsigned long long installTime = 0;
		if (getRegQwordValue(conf.Software, cle, L"InstallTime", &installTime) == ERROR_SUCCESS
		    && installTime != 0) {
			installDateUtc.dwLowDateTime  = (DWORD)(installTime & 0xFFFFFFFFULL);
			installDateUtc.dwHighDateTime = (DWORD)(installTime >> 32);
		}
		else {
			DWORD installDate = 0;
			if (getRegDwordValue(conf.Software, cle, L"InstallDate", &installDate) == ERROR_SUCCESS
			    && installDate != 0)
				installDateUtc = unixVersFiletime(installDate);
		}

		// Identifiant unique de l'installation : sert a corréler des artefacts
		// issus de machines différentes (telemetrie, journaux applicatifs).
		log(3, L"🔈getRegSzValue MachineGuid");
		getRegSzValue(conf.Software, L"Microsoft\\Cryptography", L"MachineGuid", &machineGuid);

		log(2, L"❇️OS : " + osName + L" " + version);
	}
	else
		log(2, L"🔥Ruche SOFTWARE indisponible : informations d'installation non relevees");

	/*******************************************************************
	* 3. Instant de la collecte — mesuré à chaud, sans trace
	*******************************************************************/
	log(3, L"🔈GetSystemTime");
	GetSystemTime(&localDateTimeUtc);
	TIME_ZONE_INFORMATION timezone = { 0 };
	log(3, L"🔈GetTimeZoneInformation");
	if (GetTimeZoneInformation(&timezone) != TIME_ZONE_ID_INVALID) {
		log(3, L"🔈SystemTimeToTzSpecificLocalTime");
		SystemTimeToTzSpecificLocalTime(&timezone, &localDateTimeUtc, &localDateTime);
	}
	else
		log(2, L"🔥GetTimeZoneInformation", TIME_ZONE_ID_UNKNOWN);

	/* Heure de dernier démarrage.
	 *
	 * Calculée à partir de GetTickCount64() : heure courante moins la durée
	 * d'activité. Choisi plutôt que WMI (Win32_OperatingSystem.LastBootUpTime),
	 * qui laisserait une trace d'exécution WMI pour une seule valeur.
	 *
	 * LIMITE À CONNAÎTRE : GetTickCount64() n'inclut PAS le temps passé en veille
	 * ou en hibernation. Sur une machine mise en veille, l'heure calculée est donc
	 * POSTÉRIEURE au démarrage réel, de la durée cumulée des veilles. La valeur
	 * borne l'activité observée, elle ne prouve pas l'instant du démarrage : la
	 * source exacte serait l'événement System 6005/6009.
	 * Le champ BootTimeSource du JSON consigne cette réserve pour l'analyste.
	 */
	log(3, L"🔈GetTickCount64");
	const ULONGLONG uptimeMs = GetTickCount64();
	uptimeSeconds = uptimeMs / 1000ULL;
	FILETIME maintenantUtc = { 0, 0 };
	SystemTimeToFileTime(&localDateTimeUtc, &maintenantUtc);
	const ULONGLONG maintenant100ns = ((ULONGLONG)maintenantUtc.dwHighDateTime << 32)
	                                | maintenantUtc.dwLowDateTime;
	const ULONGLONG uptime100ns = uptimeMs * 10000ULL;          // ms -> 100 ns
	if (maintenant100ns > uptime100ns) {
		const ULONGLONG boot100ns = maintenant100ns - uptime100ns;
		FILETIME bootUtc = { (DWORD)(boot100ns & 0xFFFFFFFFULL), (DWORD)(boot100ns >> 32) };
		FileTimeToSystemTime(&bootUtc, &lastBootUpTimeUtc);
		FILETIME bootLocal = { 0, 0 };
		if (utcVersLocalSuspect(bootUtc, &bootLocal))
			FileTimeToSystemTime(&bootLocal, &lastBootUpTime);
		log(2, L"❇️Last boot (UTC) : " + timeToIso8601(lastBootUpTimeUtc, true));
	}
	else
		log(2, L"🔥Duree d'activite incoherente avec l'heure systeme : boot non calcule");

	return ERROR_SUCCESS;
}

HRESULT SystemInfo::toJson() {
	log(3, L"🔈system toJson");
	Json o = Json::obj();

	ajouterSiRenseigne(o, L"ComputerName",    computerName);
	ajouterSiRenseigne(o, L"NetbiosName",     netbiosName);
	ajouterSiRenseigne(o, L"DomainName",      domainName);
	ajouterSiRenseigne(o, L"OsArchitecture",  osArchitecture);

	ajouterSiRenseigne(o, L"OsName",          osName);
	/* La valeur brute n'est répétée que lorsqu'elle DIFFÈRE du libellé retenu :
	   c'est alors la trace de la correction Windows 10 / Windows 11, qui doit
	   rester vérifiable. Sinon elle ferait doublon. */
	if (!productNameRaw.empty() && productNameRaw != osName)
		o.add(L"ProductNameRaw", Json::str(productNameRaw));
	ajouterSiRenseigne(o, L"Version",                version);
	ajouterSiRenseigne(o, L"DisplayVersion",         displayVersion);
	ajouterSiRenseigne(o, L"EditionId",              editionId);
	ajouterSiRenseigne(o, L"InstallationType",       installationType);
	ajouterSiRenseigne(o, L"BuildLabEx",             buildLabEx);
	ajouterSiRenseigne(o, L"ServicePack",            servicePack);
	ajouterSiRenseigne(o, L"RegisteredOwner",        registeredOwner);
	ajouterSiRenseigne(o, L"RegisteredOrganization", registeredOrganization);
	ajouterSiRenseigne(o, L"ProductId",              productId);
	ajouterSiRenseigne(o, L"SystemRoot",             systemRoot);
	ajouterSiRenseigne(o, L"MachineGuid",            machineGuid);
	// installDateUtc est en UTC : la version locale doit etre CONVERTIE, pas
	// seulement re-etiquetee (defaut detecte par le controle croise du harness).
	ajouterSiRenseigne(o, L"InstallDate",            utcTimeToIso8601Local(installDateUtc));
	ajouterSiRenseigne(o, L"InstallDateUtc",         timeToIso8601Utc(installDateUtc));

	o.add(L"LocalDateTime",     Json::str(timeToIso8601(localDateTime, false)));
	o.add(L"LocalDateTimeUtc",  Json::str(timeToIso8601(localDateTimeUtc, true)));
	ajouterSiRenseigne(o, L"LastBootUpTime",    timeToIso8601(lastBootUpTime, false));
	ajouterSiRenseigne(o, L"LastBootUpTimeUtc", timeToIso8601(lastBootUpTimeUtc, true));
	o.add(L"UptimeSeconds",     Json::num(uptimeSeconds));
	// La reserve accompagne la valeur : sans elle, l'heure de demarrage se lirait
	// comme une certitude alors qu'elle borne seulement l'activite observee.
	o.add(L"BootTimeSource",    Json::str(L"calculé depuis GetTickCount64 ; "
	                                      L"exclut les périodes de veille et "
	                                      L"d'hibernation, donc borne supérieure "
	                                      L"du démarrage réel"));

	/* Fuseau : celui du SUSPECT quand la ruche a pu être lue. Le champ
	   TimeZoneSource dit laquelle des deux origines a servi — sans lui, un
	   décalage inattendu serait indistinguable d'une erreur de lecture. */
	if (conf.timeZone.valid) {
		ajouterSiRenseigne(o, L"CurrentTimeZoneId",      conf.timeZone.keyName);
		/* Le libelle saisonnier est stocke comme reference MUI
		   (« @tzres.dll,-301 ») sur les systemes recents. `CurrentTimeZoneId`
		   (« Romance Standard Time ») reste l'identifiant canonique et suffit a
		   interpreter les heures locales ; la reference est conservee pour
		   tracabilite, sans etre presentee comme un nom. */
		const std::wstring caption = conf.timeZone.daylightInEffect
		                           ? conf.timeZone.daylightName
		                           : conf.timeZone.standardName;
		if (!caption.empty()) {
			if (estReferenceMui(caption))
				o.add(L"CurrentTimeZoneCaptionResource", Json::str(caption));
			else
				o.add(L"CurrentTimeZoneCaption", Json::str(caption));
		}
		o.add(L"CurrentBias",       Json::num((long long)conf.timeZone.activeBiasMinutes));
		o.add(L"DaylightInEffect",  Json::boolean(conf.timeZone.daylightInEffect));
		o.add(L"TimeZoneSource",    Json::str(L"ruche SYSTEM de la machine examinée"));
	}
	else {
		/* Repli : la machine d'exécution. Correct en collecte live, faux sur une
		   image montée ailleurs — d'où la mention explicite. */
		TIME_ZONE_INFORMATION tz = { 0 };
		const DWORD r = GetTimeZoneInformation(&tz);
		if (r != TIME_ZONE_ID_INVALID) {
			const bool ete = (r == TIME_ZONE_ID_DAYLIGHT);
			o.add(L"CurrentTimeZoneCaption",
			      Json::str(ete ? tz.DaylightName : tz.StandardName));
			o.add(L"CurrentBias",      Json::num((long long)(tz.Bias
			                           + (ete ? tz.DaylightBias : tz.StandardBias))));
			o.add(L"DaylightInEffect", Json::boolean(ete));
		}
		o.add(L"TimeZoneSource", Json::str(L"machine d'exécution (ruche SYSTEM illisible) "
		                                   L"— ne vaut que si la collecte est live"));
	}

	return writeJsonFile("OperatingSystem.json", o);
}

void SystemInfo::clear() {
	log(3, L"🔈system clear");
}
