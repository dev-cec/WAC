#!/usr/bin/env python3
"""check-json.py — contrôle les sorties JSON de WAC.

Deux contrôles :
  1. validité JSON de chaque fichier ;
  2. cohérence des chemins Windows — un chemin sorti d'un double échappement
     apparaît, APRÈS parsing, avec des barres obliques inverses doublées.

Ce qui n'est PAS contrôlé ici : l'exactitude et la complétude des données. Un
JSON valide peut contenir des valeurs fausses (mauvais champ, date mal
interprétée) ou être tronqué par un arrêt prématuré de la collecte — c'est
run-wac-test.sh qui vérifie la terminaison de WAC.

Sortie non nulle si au moins un fichier est invalide ou incohérent.
"""
import json, sys, glob, os, re

# Un double échappement se reconnaît sur un motif de CHEMIN, pas sur du texte
# libre : le contenu d'un événement (script PowerShell, expression régulière,
# ligne de commande) peut légitimement contenir « \\ » — par exemple
# 'TIP\\(?:' où « \\ » est l'échappement PowerShell d'un backslash littéral.
# On ne signale donc que les motifs où le doublement est certainement fautif.
MOTIFS_FAUTIFS = (
    re.compile(r'[A-Za-z]:\\\\'),          # C:\\Windows  (lecteur)
    re.compile(r'^\\\\\\\\[A-Za-z0-9]'),   # \\\\serveur  (UNC déjà doublé)
    re.compile(r'\\\\\\\\(?:Device|REGISTRY|SystemRoot|\?\?)\\\\', re.I),
)

def incoherences(valeur):
    """Rend la liste des motifs de chemin doublement échappés dans la valeur."""
    return [m.group(0) for motif in MOTIFS_FAUTIFS for m in motif.finditer(valeur)]

def parcourir(obj, chemin=""):
    """Produit (chemin_json, valeur) pour chaque chaîne, en profondeur."""
    if isinstance(obj, dict):
        for cle, val in obj.items():
            yield from parcourir(val, f"{chemin}.{cle}")
    elif isinstance(obj, list):
        for val in obj:
            yield from parcourir(val, chemin)
    elif isinstance(obj, str):
        yield chemin, obj

def main():
    rep = sys.argv[1] if len(sys.argv) > 1 else "."
    ok = invalides = incoherents = 0

    for fichier in sorted(glob.glob(os.path.join(rep, "*.json"))):
        nom = os.path.basename(fichier)
        try:
            with open(fichier, encoding="utf-8-sig") as f:
                donnees = json.load(f)
        except Exception as e:
            print(f"  ❌ {nom:<34} INVALIDE: {str(e)[:70]}")
            invalides += 1
            continue

        nb = len(donnees) if isinstance(donnees, list) else 1

        # Artefact dont la collecte a échoué : ce n'est pas une erreur de format,
        # mais ça doit se voir — sinon un artefact manquant passe inaperçu.
        if isinstance(donnees, dict) and donnees.get("CollectionStatus") == "NotCollected":
            print(f"  ⏭️  {nom:<34} NON COLLECTÉ — {donnees.get('Error', '?')}")
            ok += 1
            continue

        fautes = [(c, v, m) for c, v in parcourir(donnees)
                            for m in [incoherences(v)] if m]

        if fautes:
            print(f"  ⚠️  {nom:<34} {nb:>6} entrées — "
                  f"chemin doublement échappé sur {len(fautes)} valeur(s)")
            for c, v, motifs in fautes[:3]:
                print(f"        {c} → {motifs[0]!r} dans {v[:70]!r}")
            incoherents += 1
        else:
            print(f"  ✅ {nom:<34} {nb:>6} entrées")
            ok += 1

    print(f"\n{ok} conformes, {incoherents} avec chemin doublement échappé, "
          f"{invalides} invalides")

    incoherents += controles_croises(rep)
    return 1 if (invalides or incoherents) else 0


def charge(rep, nom):
    """Charge un JSON de sortie, ou None s'il est absent ou illisible."""
    chemin = os.path.join(rep, nom)
    if not os.path.exists(chemin):
        return None
    try:
        with open(chemin, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def controles_croises(rep):
    """Contrôles de COHÉRENCE entre artefacts.

    Ces contrôles attrapent des défauts que ni la syntaxe ni la validité des
    chemins ne révèlent : une date correctement formatée peut désigner le mauvais
    instant. Le cas qui a motivé ce bloc : toutes les sessions démarraient deux
    heures AVANT le démarrage du système — symptôme d'un double décalage horaire
    (valeur UTC traitée comme locale) sur `sessions`, invisible autrement.

    Rend le nombre d'incohérences trouvées.
    """
    print("\n-- Cohérence entre artefacts --")
    trouvees = 0

    osj = charge(rep, "OperatingSystem.json")
    sessions = charge(rep, "Sessions.json")

    boot = (osj or {}).get("LastBootUpTimeUtc") if isinstance(osj, dict) else None
    if not boot:
        print("  ⏭️  heure de démarrage absente : contrôle sessions/boot ignoré")
    elif not isinstance(sessions, list):
        print("  ⏭️  Sessions.json absent : contrôle sessions/boot ignoré")
    else:
        # Une session ne peut pas commencer avant le démarrage du système.
        # Tolérance de 60 s : GetTickCount64 exclut les veilles, et les sessions
        # de service démarrent dans la seconde qui suit le boot.
        avant = sorted({s.get("StartTimeUtc") for s in sessions
                        if s.get("StartTimeUtc") and s["StartTimeUtc"] < boot})
        if avant:
            print(f"  ❌ {len(avant)} session(s) démarrent AVANT le boot ({boot})")
            for v in avant[:3]:
                print(f"        StartTimeUtc = {v}")
            print("        → décalage horaire probable sur sessions ou sur le boot")
            trouvees += 1
        else:
            print(f"  ✅ aucune session antérieure au boot ({boot})")

    # Les couples <champ>/<champ>Utc doivent désigner le MÊME instant : si le
    # suffixe local et le suffixe Z portent la même heure murale, l'un des deux
    # est mal étiqueté.
    suspects = 0
    for fichier in sorted(glob.glob(os.path.join(rep, "*.json"))):
        d = charge(rep, os.path.basename(fichier))
        if d is None:
            continue
        for cle, val, cleUtc, valUtc in couples_dates(d):
            # "2026-09-15T08:00:00+02:00" et "...T08:00:00Z" : même heure murale
            if val[:19] == valUtc[:19] and not val.endswith("Z"):
                suspects += 1
                if suspects <= 3:
                    print(f"  ❌ {os.path.basename(fichier)} : {cle}={val} "
                          f"et {cleUtc}={valUtc} portent la même heure murale")
    if suspects:
        print(f"  ❌ {suspects} couple(s) local/UTC mal étiqueté(s)")
        trouvees += 1
    else:
        print("  ✅ couples local/UTC cohérents")

    trouvees += controle_services(rep)
    trouvees += controle_users(rep)
    trouvees += controle_processes(rep)
    trouvees += controle_prefetchs(rep)
    trouvees += controle_references_mft(rep)
    return trouvees


def controle_references_mft(rep):
    """Plausibilité des références $MFT lues dans les blocs beef0004.

    Contrôle croisé au sens large : ces numéros viennent du décodage d'un bloc
    d'extension, et leur plausibilité se juge sur des propriétés connues de
    NTFS. Les 27 premières entrées de la MFT sont réservées aux métafichiers
    (`$MFT`, `$MFTMirr`, `$LogFile`…) : un fichier ordinaire ne peut pas s'y
    trouver. Un numéro de séquence nul avec un numéro d'entrée non nul désigne
    un volume FAT, pas une erreur.
    """
    total = 0
    suspects = []
    for fichier in sorted(glob.glob(os.path.join(rep, "*.json"))):
        d = charge(rep, os.path.basename(fichier))
        if d is None:
            continue
        pile = [d]
        while pile:
            o = pile.pop()
            if isinstance(o, dict):
                if o.get("MftNote") == "NTFS":
                    total += 1
                    entree = o.get("MftEntryNumber") or 0
                    seq = o.get("MftSequenceNumber") or 0
                    if entree < 27 or seq == 0:
                        suspects.append((os.path.basename(fichier), entree, seq))
                pile.extend(o.values())
            elif isinstance(o, list):
                pile.extend(o)
    if total == 0:
        print("  ⏭️  aucune référence $MFT relevée : contrôle ignoré")
        return 0
    if suspects:
        print(f"  ❌ {len(suspects)}/{total} référence(s) $MFT implausible(s) "
              f"(entrée < 27 ou séquence nulle marquée NTFS)")
        for f, e, sq in suspects[:3]:
            print(f"        {f} : entrée {e}, séquence {sq}")
        return 1
    print(f"  ✅ {total} référence(s) $MFT plausible(s)")
    return 0


def controle_prefetchs(rep):
    """Le hash du chemin doit correspondre au suffixe du nom de fichier.

    Contrôle CROISÉ au sens fort : le hash est décodé depuis l'en-tête binaire,
    le nom de fichier est une donnée indépendante. S'ils divergent, le décodage
    est faux. C'est ce contrôle qui a chiffré le défaut de formatage : 65 hash
    sur 270 étaient tronqués, « CMD.EXE-0BD30981.pf » donnant « bd3981 »
    (doc §14.17).
    """
    d = charge(rep, "prefetchs.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  prefetchs.json absent ou vide : contrôle ignoré")
        return 0

    mauvais = []
    for p in d:
        nom = (p.get("Path") or "").replace("/", "\\").split("\\")[-1]
        if "-" not in nom or not nom.lower().endswith(".pf"):
            continue          # nom hors convention : rien à comparer
        attendu = nom.rsplit("-", 1)[-1][:-3]
        if (p.get("Hash") or "").upper() != attendu.upper():
            mauvais.append((nom, p.get("Hash")))
    if mauvais:
        print(f"  ❌ prefetchs.json : {len(mauvais)}/{len(d)} hash ne correspondent "
              f"pas au nom de fichier")
        for nom, h in mauvais[:3]:
            print(f"        {nom} -> {h}")
        return 1 + controle_prefetch_chemins(d)
    print(f"  ✅ prefetchs.json : {len(d)} hash conformes au nom de fichier")
    return controle_prefetch_chemins(d)


def controle_prefetch_chemins(d):
    r"""Les chemins `\VOLUME{guid}\…` doivent être résolus en chemins réels.

    Un Prefetch nomme les fichiers chargés par le programme sous la forme
    `\VOLUME{01dd…-8c10a5a9}\WINDOWS\SYSTEM32\NTDLL.DLL`, inexploitable telle
    quelle. WAC les traduit avec la lettre du volume. Une comparaison de longueur
    codée en dur faisait échouer cette traduction pour la TOTALITÉ des fichiers
    (doc §14.17) : 20 052 chemins restaient vides, et les empreintes MD5 avec
    eux.
    """
    total = sum(len(p.get("FilesStrings") or []) for p in d)
    if total == 0:
        print("  ⏭️  prefetchs.json : aucun fichier listé, contrôle ignoré")
        return 0
    resolus = sum(1 for p in d for f in (p.get("FilesStrings") or [])
                  if f.get("FullPath"))
    # La quasi-totalité doit être résolue : seuls les volumes absents du système
    # au moment de la collecte (disque débranché) échappent légitimement.
    if resolus * 10 < total * 9:
        print(f"  ❌ prefetchs.json : {total - resolus}/{total} chemins de fichiers "
              f"non résolus (\\VOLUME{{…}} non traduit en lettre de volume)")
        return 1
    print(f"  ✅ prefetchs.json : {resolus}/{total} chemins de fichiers résolus")
    return 0


def nom_processus(p):
    """Nom d'un processus, quelle que soit la version de WAC qui l'a écrit.

    La clé s'appelait « Nom » avant l'harmonisation du 2026-09-15 (doc §14.19).
    Lire les deux permet de contrôler aussi les résultats archivés — et évite
    qu'un contrôle rende silencieusement None, ce qui neutralise l'exclusion de
    WAC lui-même et produit un faux positif.
    """
    return p.get("Name") or p.get("Nom") or ""


def controle_processes(rep):
    """Vérifie que processes.json n'attribue pas les modules de WAC à autrui."""
    d = charge(rep, "processes.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  processes.json absent ou vide : contrôle ignoré")
        return 0
    trouvees = 0

    # CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0) désigne le PROCESSUS
    # COURANT : le processus Idle héritait des modules de WAC.exe (doc §14.15).
    # WAC lui-même porte légitimement son propre binaire en premier module —
    # c'est le SEUL processus qui le peut.
    coupables = [nom_processus(p) for p in d
                 if nom_processus(p).lower() != "wac.exe"
                 and any("wac.exe" in (m or "").lower() for m in p.get("Modules") or [])]
    if coupables:
        print(f"  ❌ processes.json : {coupables[:5]} portent WAC.exe parmi leurs "
              f"modules — l'outil de collecte s'attribue à un autre processus")
        trouvees += 1
    else:
        print("  ✅ processes.json : aucun processus ne porte WAC.exe en module")

    # Le propriétaire doit être connu pour la quasi-totalité des processus :
    # un taux élevé de SID vides signalerait le retour d'OpenProcess.
    sansSid = [nom_processus(p) for p in d if not p.get("SID")]
    # Seul le processus Idle (PID 0) n'a légitimement aucun jeton.
    pid = lambda p: p.get("ProcessId") if p.get("ProcessId") is not None else p.get("PID")
    illegitimes = [nom_processus(p) for p in d if not p.get("SID") and pid(p)]
    if illegitimes:
        print(f"  ❌ processes.json : {len(illegitimes)} processus sans propriétaire "
              f"{illegitimes[:5]} — relevé du SID à vérifier")
        trouvees += 1
    else:
        print(f"  ✅ processes.json : {len(d) - len(sansSid)}/{len(d)} propriétaires relevés")
    return trouvees


# États retournés par l'ancien convertisseur fautif : ce sont des FILTRES
# d'énumération, pas des états de service. Leur réapparition signifierait que
# serviceState_to_wstring a régressé (cf. doc §14.14).
ETATS_FANTOMES = {"SERVICE_ACTIVE", "SERVICE_INACTIVE", "SERVICE_STATE_ALL"}


def controle_services(rep):
    """Vérifie que services.json porte des états réels et des pilotes."""
    d = charge(rep, "services.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  services.json absent ou vide : contrôle ignoré")
        return 0
    trouvees = 0

    fantomes = sorted({s.get("Status") for s in d
                       if s.get("Status") in ETATS_FANTOMES})
    if fantomes:
        print(f"  ❌ services.json : état(s) issus des filtres d'énumération "
              f"{fantomes} — serviceState_to_wstring a régressé")
        trouvees += 1
    else:
        print("  ✅ services.json : aucun état fantôme")

    # Un type "SERVICE_TYPE_UNKNOWN" massif signalerait le retour de la
    # comparaison par égalité sur un champ de bits.
    inconnus = sum(1 for s in d if s.get("Type") == "SERVICE_TYPE_UNKNOWN")
    if inconnus > len(d) // 10:
        print(f"  ❌ services.json : {inconnus}/{len(d)} types inconnus "
              f"— décomposition des drapeaux à vérifier")
        trouvees += 1
    else:
        print(f"  ✅ services.json : {len(d) - inconnus}/{len(d)} types reconnus")

    # La lecture hors ligne doit voir les pilotes, que l'énumération SCM
    # filtrée sur SERVICE_WIN32 excluait entièrement.
    pilotes = sum(1 for s in d if "DRIVER" in (s.get("Type") or ""))
    if pilotes == 0:
        print("  ❌ services.json : aucun pilote — la ruche en contient toujours")
        trouvees += 1
    else:
        print(f"  ✅ services.json : {pilotes} pilote(s) présents")
    return trouvees


def controle_users(rep):
    """Vérifie que les SID reconstruits depuis le SAM sont bien formés."""
    d = charge(rep, "users.json")
    if not isinstance(d, list) or not d:
        print("  ⏭️  users.json absent ou vide : contrôle ignoré")
        return 0
    trouvees = 0

    # SID recomposé depuis le SID de machine + le RID : sans le SID de machine,
    # le champ serait vide et le compte incorrélable.
    mauvais = sorted({u.get("Name") for u in d
                      if not (u.get("SID") or "").startswith("S-1-5-21-")})
    if mauvais:
        print(f"  ❌ users.json : SID non reconstruit pour {mauvais[:5]} "
              f"— SID de machine illisible dans SAM\\Domains\\Account")
        trouvees += 1
    else:
        print(f"  ✅ users.json : {len(d)} SID bien formés")

    # Le RID doit se retrouver à la fin du SID : garde-fou sur l'appariement.
    incoherents = [u.get("Name") for u in d
                   if u.get("RID") and (u.get("SID") or "").rsplit("-", 1)[-1]
                   != str(u["RID"])]
    if incoherents:
        print(f"  ❌ users.json : RID absent de la fin du SID pour {incoherents[:5]}")
        trouvees += 1
    else:
        print("  ✅ users.json : RID cohérents avec les SID")
    return trouvees


ISO = re.compile(r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d')


def couples_dates(obj):
    """Produit (clé, valeur, cléUtc, valeurUtc) pour chaque paire <X>/<X>Utc."""
    if isinstance(obj, dict):
        for cle, val in obj.items():
            cleUtc = cle + "Utc"
            autre = obj.get(cleUtc)
            if (isinstance(val, str) and isinstance(autre, str)
                    and ISO.match(val) and ISO.match(autre)):
                yield cle, val, cleUtc, autre
        for val in obj.values():
            yield from couples_dates(val)
    elif isinstance(obj, list):
        for val in obj:
            yield from couples_dates(val)


if __name__ == "__main__":
    sys.exit(main())
