#include "users.h"

namespace {

/* Offsets dans la valeur `F` d'un compte SAM (structure de taille fixe, 0x50
 * octets). Alignés sur RegRipper (samparse.pl) et creddump, qui concordent.
 * Nommés plutôt qu'écrits en clair dans le code : un offset nu ne se relit pas.
 */
const size_t F_TAILLE_MIN          = 0x44;
const size_t F_DERNIERE_CONNEXION  = 0x08;   // FILETIME
const size_t F_MOT_DE_PASSE_POSE   = 0x18;   // FILETIME
const size_t F_EXPIRATION          = 0x20;   // FILETIME
const size_t F_DERNIER_ECHEC       = 0x28;   // FILETIME
const size_t F_RID                 = 0x30;   // DWORD
const size_t F_DRAPEAUX            = 0x38;   // WORD (ACB)
const size_t F_ECHECS              = 0x40;   // WORD
const size_t F_CONNEXIONS          = 0x42;   // WORD

/* Offsets dans la valeur `V`. La valeur commence par une table d'entrées de 12
 * octets (offset, longueur, inconnu) ; les offsets sont relatifs à 0xCC, soit la
 * fin de cette table. */
const size_t V_BASE          = 0xCC;
const size_t V_NOM           = 0x0C;
const size_t V_NOM_COMPLET   = 0x18;
const size_t V_COMMENTAIRE   = 0x24;

//! Lit un FILETIME à un offset, sans jamais dépasser le tampon.
FILETIME lireFiletime(const BYTE* donnees, DWORD taille, size_t offset) {
	FILETIME ft = { 0, 0 };
	if (offset + sizeof(FILETIME) > taille) return ft;
	memcpy(&ft, donnees + offset, sizeof(FILETIME));
	return ft;
}

/*! Lit une chaîne de la valeur `V` d'après son entrée dans la table d'offsets.
*
* Les chaînes ne sont PAS terminées par un zéro : la longueur de l'entrée est la
* seule borne. Une longueur corrompue pointerait hors du tampon, d'où la
* vérification systématique.
*
* @param donnees la valeur `V`
* @param taille sa taille
* @param entree l'offset de l'entrée dans la table (V_NOM, V_NOM_COMPLET, …)
* @return la chaîne, ou "" si l'entrée est vide ou incohérente
*/
std::wstring lireChaineV(const BYTE* donnees, DWORD taille, size_t entree) {
	if (entree + 8 > taille) return L"";
	DWORD offsetRelatif = 0, longueur = 0;
	memcpy(&offsetRelatif, donnees + entree,     sizeof(DWORD));
	memcpy(&longueur,      donnees + entree + 4, sizeof(DWORD));
	if (longueur == 0 || longueur > taille) return L"";
	const size_t debut = V_BASE + offsetRelatif;
	if (debut + longueur > taille) {
		log(2, L"🔥Valeur V du SAM incoherente : entree hors tampon");
		return L"";
	}
	return std::wstring((PCWSTR)(donnees + debut), longueur / sizeof(wchar_t));
}

/*! Décompose les drapeaux de compte (ACB) en libellés lisibles.
*
* `Disabled` seul ne suffit pas à décrire un compte : « mot de passe jamais
* expiré », « compte verrouillé » ou « mot de passe non requis » sont des faits
* que l'analyste doit voir sans avoir à décoder un entier.
*/
std::wstring decrireDrapeaux(DWORD acb) {
	/* ATTENTION : ces bits sont les ACB du SAM, PAS les UF_* de lmaccess.h.
	   Les deux espaces se ressemblent mais sont décalés — ACB_DISABLED vaut
	   0x0001 alors que UF_ACCOUNTDISABLE vaut 0x0002. Remplacer ces valeurs par
	   les constantes UF_* « pour faire propre » inverserait la lecture de tous
	   les comptes. Elles sont donc écrites en clair, avec leur nom ACB. */
	struct { DWORD bit; PCWSTR nom; } TABLE[] = {
		{ 0x0001, L"ACCOUNT_DISABLED" },
		{ 0x0002, L"HOME_DIRECTORY_REQUIRED" },
		{ 0x0004, L"PASSWORD_NOT_REQUIRED" },
		{ 0x0008, L"TEMPORARY_DUPLICATE_ACCOUNT" },
		{ 0x0010, L"NORMAL_ACCOUNT" },
		{ 0x0020, L"MNS_LOGON_ACCOUNT" },
		{ 0x0040, L"INTERDOMAIN_TRUST_ACCOUNT" },
		{ 0x0080, L"WORKSTATION_TRUST_ACCOUNT" },
		{ 0x0100, L"SERVER_TRUST_ACCOUNT" },
		{ 0x0200, L"PASSWORD_DOES_NOT_EXPIRE" },
		{ 0x0400, L"ACCOUNT_AUTO_LOCKED" },
	};
	std::wstring s;
	for (const auto& e : TABLE) {
		if ((acb & e.bit) == 0) continue;
		if (!s.empty()) s += L"|";
		s += e.nom;
	}
	return s;
}

/*! Recompose le SID de la machine depuis `SAM\Domains\Account`, valeur `V`.
*
* Les trois sous-autorités du SID de domaine local occupent les 12 derniers
* octets de la valeur. Sans elles, seul le RID serait connu — un RID ne
* s'interprète pas seul et ne se corrèle avec aucun autre artefact.
*
* @param hSam la ruche SAM ouverte
* @param base préfixe de clé ("SAM\\" ou "", cf. `racineSam`)
* @return "S-1-5-21-a-b-c", ou "" en cas d'échec
*/
std::wstring lireSidMachine(ORHKEY hSam, const std::wstring& base) {
	LPBYTE donnees = NULL;
	DWORD taille = 0;
	log(3, L"🔈getRegBinaryValue " + base + L"Domains\\Account V");
	if (getRegBinaryValue(hSam, (base + L"Domains\\Account").c_str(), L"V",
	                      &donnees, &taille) != ERROR_SUCCESS) {
		log(2, L"🔥SID de machine illisible : les SID seront limites au RID");
		// getRegBinaryValue alloue le tampon AVANT de lire : il faut le rendre
		// meme quand la lecture echoue, sinon la sortie en erreur fuit.
		delete[] donnees;
		return L"";
	}
	std::wstring sid;
	if (taille >= 12) {
		const BYTE* fin = donnees + taille - 12;
		DWORD a = 0, b = 0, c = 0;
		memcpy(&a, fin,     sizeof(DWORD));
		memcpy(&b, fin + 4, sizeof(DWORD));
		memcpy(&c, fin + 8, sizeof(DWORD));
		sid = L"S-1-5-21-" + std::to_wstring(a) + L"-" + std::to_wstring(b)
		    + L"-" + std::to_wstring(c);
		log(2, L"❇️SID de machine : " + sid);
	}
	else
		log(2, L"🔥Valeur V de SAM\\Domains\\Account trop courte");
	delete[] donnees;
	return sid;
}

//! Chemin de profil associé à un SID, "" si le compte n'a jamais ouvert de session.
std::wstring profilDuSid(const std::wstring& sid) {
	if (sid.empty()) return L"";
	for (const std::tuple<std::wstring, std::wstring>& p : conf.profiles)
		if (enMinuscules(std::get<0>(p)) == enMinuscules(sid)) return std::get<1>(p);
	return L"";
}

} // namespace

Json User::toJson() const {
	log(3, L"🔈user toJson");
	Json o = Json::obj();
	o.add(L"Name",     Json::str(name));
	if (!fullName.empty()) o.add(L"FullName", Json::str(fullName));
	if (!comment.empty())  o.add(L"Comment",  Json::str(comment));
	o.add(L"SID",      Json::str(SID));
	o.add(L"RID",      Json::num(rid));
	o.add(L"Disabled", Json::boolean((flags & 0x0001) != 0));
	if (!flagsLibelles.empty()) o.add(L"AccountFlags", Json::str(flagsLibelles));
	/* Un profil absent signifie que le compte n'a jamais ouvert de session sur
	   cette machine : fait à part entière, pas une lecture manquée. */
	if (!profile.empty()) o.add(L"Profile", Json::str(profile));

	o.add(L"LogonCount",       Json::num(logonCount));
	o.add(L"BadPasswordCount", Json::num(badPasswordCount));

	// Chaque horodatage est emis dans les deux referentiels, comme partout
	// ailleurs dans WAC ; vide si le SAM ne porte pas la date.
	struct { PCWSTR nom; PCWSTR nomUtc; const FILETIME* ft; } DATES[] = {
		{ L"LastLogon",        L"LastLogonUtc",        &lastLogonUtc },
		{ L"PasswordLastSet",  L"PasswordLastSetUtc",  &passwordLastSetUtc },
		{ L"AccountExpires",   L"AccountExpiresUtc",   &accountExpiresUtc },
		{ L"LastBadPassword",  L"LastBadPasswordUtc",  &lastBadPasswordUtc },
		{ L"AccountModified",  L"AccountModifiedUtc",  &keyLastWriteUtc },
	};
	for (const auto& d : DATES) {
		const std::wstring local = utcTimeToIso8601Local(*d.ft);
		if (local.empty()) continue;
		o.add(d.nom,    Json::str(local));
		o.add(d.nomUtc, Json::str(timeToIso8601Utc(*d.ft)));
	}
	return o;
}

void User::clear() {
	log(3, L"🔈user clear");
}

HRESULT Users::getData() {
	log(0, L"*******************************************************************************************************************");
	log(0, L"ℹ️Users :");
	log(0, L"*******************************************************************************************************************");

	const std::wstring rucheSam = conf.mountpoint + L"\\Windows\\system32\\config\\SAM";
	ORHKEY hSam = NULL;
	log(3, L"🔈OROpenHive SAM");
	HRESULT hresult = OROpenHive(rucheSam.c_str(), &hSam);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥Ruche SAM indisponible : comptes locaux non collectes", hresult);
		return hresult;
	}

	/* La ruche SAM porte une clé racine nommée « SAM » : le chemin complet est
	   donc `SAM\Domains\Account\Users`. Les deux formes sont essayées, car la
	   racine exposée dépend de la façon dont la ruche a été écrite — une erreur
	   ERROR_FILE_NOT_FOUND ici se lirait sinon comme « ruche absente » alors
	   qu'elle est présente et lisible. */
	ORHKEY hUsers = NULL;
	std::wstring base;
	for (PCWSTR prefixe : { L"SAM\\", L"" }) {
		const std::wstring chemin = std::wstring(prefixe) + L"Domains\\Account\\Users";
		log(3, L"🔈OROpenKey " + chemin);
		hUsers = NULL;   // offreg peut ecrire dans la sortie meme en cas d'echec
		if (OROpenKey(hSam, chemin.c_str(), &hUsers) == ERROR_SUCCESS) {
			base = prefixe;
			break;
		}
	}
	if (!hUsers) {
		log(2, L"🔥OROpenKey Domains\\Account\\Users introuvable dans la ruche SAM");
		ORCloseHive(hSam);
		return ERROR_FILE_NOT_FOUND;
	}
	log(2, L"❇️Racine SAM : \"" + base + L"Domains\\Account\\Users\"");

	const std::wstring sidMachine = lireSidMachine(hSam, base);

	DWORD nSousCles = 0;
	log(3, L"🔈ORQueryInfoKey SAM\\Domains\\Account\\Users");
	hresult = ORQueryInfoKey(hUsers, NULL, NULL, &nSousCles, NULL, NULL, NULL,
	                         NULL, NULL, NULL, NULL);
	if (hresult != ERROR_SUCCESS) {
		log(2, L"🔥ORQueryInfoKey SAM\\Domains\\Account\\Users", hresult);
		ORCloseKey(hUsers);
		ORCloseHive(hSam);
		return hresult;
	}

	WCHAR nomCle[MAX_KEY_NAME] = L"";
	for (DWORD i = 0; i < nSousCles; ++i) {
		printProgressStep(L"User", i + 1, nSousCles);
		DWORD taille = MAX_KEY_NAME;
		log(3, L"🔈OREnumKey Users " + std::to_wstring(i));
		if (OREnumKey(hUsers, i, nomCle, &taille, NULL, NULL, NULL) != ERROR_SUCCESS)
			continue;
		/* La sous-clé `Names` n'est pas un compte mais un index nom -> RID :
		   elle est ignorée, les RID étant déjà portés par la valeur `F`. */
		if (enMinuscules(nomCle) == L"names") continue;

		ORHKEY hCompte = NULL;
		log(3, L"🔈OROpenKey Users\\" + std::wstring(nomCle));
		if (OROpenKey(hUsers, nomCle, &hCompte) != ERROR_SUCCESS) {
			log(2, L"🔥OROpenKey Users\\" + std::wstring(nomCle));
			continue;
		}

		User u;
		log(3, L"🔈ORQueryInfoKey Users\\" + std::wstring(nomCle));
		ORQueryInfoKey(hCompte, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		               &u.keyLastWriteUtc);

		// --- valeur F : horodatages, RID, drapeaux, compteurs ---
		LPBYTE f = NULL;
		DWORD tailleF = 0;
		if (getRegBinaryValue(hCompte, nullptr, L"F", &f, &tailleF) == ERROR_SUCCESS
		    && tailleF >= F_TAILLE_MIN) {
			u.lastLogonUtc       = lireFiletime(f, tailleF, F_DERNIERE_CONNEXION);
			u.passwordLastSetUtc = lireFiletime(f, tailleF, F_MOT_DE_PASSE_POSE);
			u.accountExpiresUtc  = lireFiletime(f, tailleF, F_EXPIRATION);
			u.lastBadPasswordUtc = lireFiletime(f, tailleF, F_DERNIER_ECHEC);
			memcpy(&u.rid, f + F_RID, sizeof(DWORD));
			WORD w = 0;
			memcpy(&w, f + F_DRAPEAUX,   sizeof(WORD)); u.flags = w;
			memcpy(&w, f + F_ECHECS,     sizeof(WORD)); u.badPasswordCount = w;
			memcpy(&w, f + F_CONNEXIONS, sizeof(WORD)); u.logonCount = w;
			u.flagsLibelles = decrireDrapeaux(u.flags);
		}
		else
			log(2, L"🔥Valeur F absente ou trop courte pour " + std::wstring(nomCle));
		delete[] f;

		/* Si `F` n'a pas donné le RID, le nom de la clé le porte en hexadécimal :
		   repli qui évite de perdre le compte pour un seul champ illisible. */
		if (u.rid == 0) u.rid = (DWORD)wcstoul(nomCle, nullptr, 16);

		// --- valeur V : nom, nom complet, commentaire ---
		LPBYTE v = NULL;
		DWORD tailleV = 0;
		if (getRegBinaryValue(hCompte, nullptr, L"V", &v, &tailleV) == ERROR_SUCCESS) {
			u.name     = lireChaineV(v, tailleV, V_NOM);
			u.fullName = lireChaineV(v, tailleV, V_NOM_COMPLET);
			u.comment  = lireChaineV(v, tailleV, V_COMMENTAIRE);
		}
		else
			log(2, L"🔥Valeur V absente pour " + std::wstring(nomCle));
		delete[] v;
		ORCloseKey(hCompte);

		if (u.name.empty()) {
			// Sans nom, l'entrée n'est pas exploitable : signalée, pas émise.
			log(2, L"🔥Compte sans nom exploitable, RID " + std::to_wstring(u.rid));
			continue;
		}
		if (!sidMachine.empty()) u.SID = sidMachine + L"-" + std::to_wstring(u.rid);
		u.profile = profilDuSid(u.SID);

		log(1, L"➕User");
		log(2, L"❇️User name : " + u.name + L" (RID " + std::to_wstring(u.rid) + L")");
		users.push_back(std::move(u));
	}

	ORCloseKey(hUsers);
	ORCloseHive(hSam);
	log(2, L"❇️" + std::to_wstring(users.size()) + L" comptes locaux releves dans le SAM");
	return users.empty() ? ERROR_EMPTY : ERROR_SUCCESS;
}

HRESULT Users::toJson() {
	log(3, L"🔈users toJson");
	Json arr = Json::arr();
	for (const User& u : users) arr.push(u.toJson());
	return writeJsonFile("users.json", arr);
}

void Users::clear() {
	log(3, L"🔈users clear");
	users.clear();   // detruit les elements -> libere reellement
}
