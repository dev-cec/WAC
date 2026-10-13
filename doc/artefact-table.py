#!/usr/bin/env python3
"""artefact-table.py — writes the table of the artefacts by version of Windows
for the manuals, from the table of the code (backlog B-039).

ONE SOURCE: sources/artefact_catalogue.cpp. Its test dumps it
(artefact_catalogue_test <wac.yml> --dump, tab-separated) and this script
turns the dump into doc/artefact-table_EN.tex and doc/artefact-table_FR.tex,
which the manuals \\input. The French edition translates the texts of the
table with the dictionary below; a text left in English stops the script —
a line added to the table must be translated here, or the French manual
would silently mix both languages.

Usage: doc/artefact-table.py <dump.tsv>
  sources$ g++ -std=c++17 -I. artefact_catalogue.cpp artefact_catalogue_test.cpp -o /tmp/act
  sources$ /tmp/act wac.yml --dump > /tmp/artefacts.tsv && ../doc/artefact-table.py /tmp/artefacts.tsv
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# Phrases of the locations and formats, longest first: replaced where found.
PHRASES = [
    ("device properties with dates", "propriétés des périphériques avec leurs dates"),
    ("…with the device properties' dates (first install, last connection, last removal)",
     "…avec les dates des propriétés du périphérique (première installation, dernière connexion, dernier retrait)"),
    ("live: logon sessions of the running system", "en direct : sessions ouvertes sur le système en marche"),
    ("live: processes of the running system", "en direct : processus du système en marche"),
    ("live: TCP/IP tables of the running system", "en direct : tables TCP/IP du système en marche"),
    ("Start menu, desktops, Quick Launch of each profile and of All Users",
     "menu Démarrer, bureaux, Lancement rapide de chaque profil et de All Users"),
    ("of each profile and of All Users", "de chaque profil et de All Users"),
    ("Internet Explorer 5 to 9: index.dat of History, cache, cookies, downloads",
     "Internet Explorer 5 à 9 : index.dat de l'historique, du cache, des cookies, des téléchargements"),
    ("Internet Explorer 10 and 11, Edge Legacy:", "Internet Explorer 10 et 11, Edge Legacy :"),
    ("…and Chromium browsers, Firefox: History, places.sqlite, session files",
     "…et navigateurs Chromium, Firefox : History, places.sqlite, fichiers de session"),
    ("Outlook PST and OST, Thunderbird mbox, in each profile", "PST et OST d'Outlook, mbox de Thunderbird, dans chaque profil"),
    ("TerminalServices-LocalSessionManager and RemoteConnectionManager logs",
     "journaux TerminalServices-LocalSessionManager et RemoteConnectionManager"),
    ("…and exFAT volumes (Vista SP1; XP with KB955704)", "…et volumes exFAT (Vista SP1 ; XP avec KB955704)"),
    ("FAT12, FAT16, FAT32 volumes", "volumes FAT12, FAT16, FAT32"),
    ("the same folder, with", "le même dossier, avec"),
    ("the same folders", "les mêmes dossiers"), ("the same keys", "les mêmes clés"),
    ("the same stream", "le même flux"), ("the same value", "la même valeur"),
    ("Thumbs.db in each folder", "Thumbs.db dans chaque dossier"),
    ("SOFTWARE, SYSTEM and NTUSER.DAT:", "SOFTWARE, SYSTEM et NTUSER.DAT :"),
    ("SOFTWARE and NTUSER.DAT", "SOFTWARE et NTUSER.DAT"),
    (", and NTUSER.DAT", ", et NTUSER.DAT"), ("Shell and ShellNoRoam", "Shell et ShellNoRoam"),
    ("SECURITY hive:", "ruche SECURITY :"),
    ("Start Menu\\Programs\\Startup de chaque profil", "Start Menu\\Programs\\Startup de chaque profil"),
    ("<file>:Zone.Identifier", "<fichier>:Zone.Identifier"),
    ("…and ", "…et "),
    # formats
    ("alternate data stream, INI text", "flux de données alterné, texte INI"),
    ("BagMRU shell items", "éléments de shell de BagMRU"),
    ("BIN bitmap cache", "cache d'images BIN"), ("BMC bitmap cache", "cache d'images BMC"),
    ("BITS state file", "fichier d'état de BITS"), ("certificate blobs", "certificats (blobs)"),
    ("CIM repository", "dépôt CIM"),
    ("CMMM, Vista and 7 layout", "CMMM, disposition de Vista et 7"),
    ("CMMM, Windows 8 and later layout", "CMMM, disposition de Windows 8 et suivants"),
    ("DetectionHistory records", "enregistrements DetectionHistory"),
    ("header 0x30 or 0x34, entries", "en-tête 0x30 ou 0x34, entrées"),
    ("header 0xDEADBEEF, 96 entries", "en-tête 0xDEADBEEF, 96 entrées"),
    ("header ", "en-tête "), ("entries \"", "entrées \""),
    ("EVT (LfLe records)", "EVT (enregistrements LfLe)"), ("EVTX, binary XML", "EVTX, XML binaire"),
    ("EVTX events", "événements EVTX"),
    ("exFAT directory entries", "entrées de répertoire exFAT"), ("FAT directory entries", "entrées de répertoire FAT"),
    ("F and V records, hashes under AES", "enregistrements F et V, condensats sous AES"),
    ("F and V records, hashes under RC4 (boot key)", "enregistrements F et V, condensats sous RC4 (clé de démarrage)"),
    ("INFO2 records", "enregistrements INFO2"), ("JOB binary", "binaire JOB"),
    ("master key file, version 2", "fichier de clé maîtresse, version 2"),
    ("MRUList and strings", "MRUList et chaînes"), ("MRUListEx and shell items", "MRUListEx et éléments de shell"),
    ("MRUListEx and UTF-16 strings", "MRUListEx et chaînes UTF-16"),
    ("NTFS 3.1 file records", "enregistrements de fichier NTFS 3.1"),
    ("NTFS boot sector, journal header", "secteur de démarrage NTFS, en-tête du journal"),
    ("transactional NTFS log, raw copy", "journal NTFS transactionnel, copie brute"),
    ("NTFS log, raw copy", "journal NTFS, copie brute"),
    ("NTFS security descriptor stream", "flux des descripteurs de sécurité NTFS"),
    ("OLE compound file, DestList version 3 and 4", "fichier composé OLE, DestList version 3 et 4"),
    ("OLE compound file", "fichier composé OLE"),
    ("PST/OST (ANSI and Unicode), mbox", "PST/OST (ANSI et Unicode), mbox"),
    ("registry hive, File and Programs keys", "ruche, clés File et Programs"),
    ("registry hive, Inventory* keys", "ruche, clés Inventory*"),
    ("registry hives, raw copy", "ruches, copie brute"), ("registry hives", "ruches"),
    ("registry keys, SYSTEMTIME dates", "clés de registre, dates SYSTEMTIME"),
    ("registry keys", "clés de registre"),
    ("registry values, profiles and port lists", "valeurs de registre, profils et listes de ports"),
    ("registry values, rule strings v2.x", "valeurs de registre, règles en chaînes v2.x"),
    ("registry values, security descriptors", "valeurs de registre, descripteurs de sécurité"),
    ("registry values", "valeurs de registre"),
    ("Report.wer, UTF-16 text", "Report.wer, texte UTF-16"),
    ("ROT13 names, 16-byte values", "noms en ROT13, valeurs de 16 octets"),
    ("ROT13 names, 72-byte values", "noms en ROT13, valeurs de 72 octets"),
    ("SAM alias records", "enregistrements d'alias de la SAM"),
    ("SCCA version 30 and 31, compressed (MAM)", "SCCA version 30 et 31, compressé (MAM)"),
    ("shell link", "raccourci"),
    ("text, sections", "texte, sections"), ("text, XP layout", "texte, disposition de XP"),
    ("UTF-16 text", "texte UTF-16"), ("UTF-8 text", "texte UTF-8"),
    ("V3 (128-bit references)", "V3 (références de 128 bits)"), ("V4 (range tracking)", "V4 (suivi des plages)"),
    ("XML, registry values", "XML, valeurs de registre"),
]
# Whole cells that are one word.
WHOLE = {"files": "fichiers", "text": "texte", "observation": "observation"}
NOTES = {
    "Still written by Windows 11 (measured, build 26200), though the Timeline is no longer shown. Server editions to be measured.":
        "Toujours écrit par Windows 11 (mesuré, build 26200), bien que la Chronologie n'y soit plus affichée. Éditions serveur à mesurer.",
    "Amcache.hve also on Windows 7 with update KB2952664.": "Amcache.hve aussi sous Windows 7 avec la mise à jour KB2952664.",
    "Server editions to be measured.": "Éditions serveur à mesurer.",
    "Before Vista: Documents and Settings\\All Users\\Application Data\\Microsoft\\Network\\Downloader.":
        "Avant Vista : Documents and Settings\\All Users\\Application Data\\Microsoft\\Network\\Downloader.",
    "Server 2012 and 2012 R2 have no built-in Defender; quarantine copied encrypted on every version.":
        "Server 2012 et 2012 R2 n'ont pas de Defender intégré ; la quarantaine est copiée chiffrée sur toutes les versions.",
    "Depends on the mail program installed, not on Windows.": "Dépend du logiciel de messagerie installé, non de Windows.",
    "Windows XP: Dr Watson (drwtsn32.log, user.dmp), not collected.": "Windows XP : Dr Watson (drwtsn32.log, user.dmp), non collecté.",
    "Copied raw on every version: not converted.": "Copié brut sur toutes les versions : non converti.",
    "Depends on Office (2010 and later), not on Windows.": "Dépend d'Office (2010 et suivants), non de Windows.",
    "Earlier with PSReadLine installed by hand (PowerShell 5, Windows 7 and later).":
        "Plus tôt si PSReadLine a été installé à la main (PowerShell 5, Windows 7 et suivants).",
    "Switched off by default on the server editions.": "Désactivé par défaut sur les éditions serveur.",
    "Registry values and .rdp files read on every version; only the tiles of the .bmc cache are not exported.":
        "Valeurs de registre et fichiers .rdp lus sur toutes les versions ; seules les tuiles du cache .bmc ne sont pas exportées.",
    "Windows XP and Server 2003: events 528 and 682 of Security.evt, not converted.":
        "Windows XP et Server 2003 : événements 528 et 682 de Security.evt, non convertis.",
    "Empty since Windows 10 1803 unless the backup task was switched back on. Copied raw: not converted.":
        "Vide depuis Windows 10 1803, sauf si la tâche de sauvegarde a été réactivée. Copié brut : non converti.",
    "Windows.edb is collected with its logs, not converted. Windows XP: Windows Desktop Search, an optional install.":
        "Windows.edb est collecté avec ses journaux, non converti. Windows XP : Windows Desktop Search, installation facultative.",
    "The journal exists only where it was created: always on the system volume from Vista on.":
        "Le journal n'existe que là où il a été créé : toujours sur le volume système à partir de Vista.",
    "Chromium and Firefox depend on the browser installed, not on Windows.":
        "Chromium et Firefox dépendent du navigateur installé, non de Windows.",
    "Windows XP: Search Assistant\\ACMru, not collected.": "Windows XP : Search Assistant\\ACMru, non collecté.",
}
# Words that betray a text left in English.
ENGLISH = re.compile(r"\b(and|the|of|with|raw|values|keys|records|entries|header|layout|files|live|each|"
                     r"browsers|logs|names|strings|copy|file|stream|hive|hives)\b")
LABELS = {
    "EN": {"artefact": "Artefact", "since": "From", "where": "Where", "format": "Format", "decoded": r"Con\-verted",
           "yes": "yes", "no": "no", "expected": "always there from", "caption":
           "One line per form of each artefact: the first Windows that has it, where it lies, its format, and "
           "whether WAC converts that form (a form not converted is collected raw at most)."},
    "FR": {"artefact": "Artefact", "since": "Depuis", "where": "Emplacement", "format": "Format", "decoded": "Converti",
           "yes": "oui", "no": "non", "expected": "toujours présent depuis", "caption":
           "Une ligne par forme de chaque artefact : le premier Windows qui la porte, son emplacement, son format, "
           "et si WAC convertit cette forme (une forme non convertie est au plus collectée brute)."},
}


def french(text):
    """A location or a format, in French."""
    if text in WHOLE:
        return WHOLE[text]
    for english, translated in PHRASES:
        text = text.replace(english, translated)
    return text


def latex(text):
    """A text of the table, safe in LaTeX."""
    out = []
    for c in text:
        out.append({"\\": r"\textbackslash{}", "$": r"\$", "_": r"\_", "&": r"\&", "%": r"\%", "#": r"\#",
                    "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
                    "<": r"\textless{}", ">": r"\textgreater{}", "\"": "''"}.get(c, c))
    return "".join(out)


def release(build, releases):
    """The client release a build belongs to, from the dump's own (build, name) pairs."""
    name = None
    for first, label in sorted(releases):
        if build >= first:
            name = label
    return name


def translated(where, form, note):
    """A form's texts in French; stops on a text the dictionary leaves in English."""
    where, form = french(where), french(form)
    if note:
        if note not in NOTES:
            sys.exit(f"note without a French translation: {note}")
        note = NOTES[note]
    for text in (where, form):
        left = ENGLISH.search(re.sub(r"\\[A-Za-z0-9_ .*?<>-]+", " ", text))   # paths and key names are not prose
        if left:
            sys.exit(f"left in English ({left.group(0)}): {text}")
    return where, form, note


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    by_key = {}
    with open(sys.argv[1], encoding="utf-8") as f:
        for line in f:
            cells = line.rstrip("\n").split("\t")
            if len(cells) == 10:
                by_key.setdefault(cells[0], []).append(cells)
    if not by_key:
        sys.exit("no row in the dump")
    releases = {(int(r[4]), r[5]) for forms in by_key.values() for r in forms}
    for language in ("EN", "FR"):
        t = LABELS[language]
        out = ["% Generated by doc/artefact-table.py from sources/artefact_catalogue.cpp — do not edit.",
               r"{\small", r"\begin{longtable}{@{}L{2.8cm}L{2.0cm}L{5.0cm}L{3.3cm}L{1.5cm}@{}}", r"\toprule",
               rf"\textbf{{{t['artefact']}}} & \textbf{{{t['since']}}} & \textbf{{{t['where']}}} & "
               rf"\textbf{{{t['format']}}} & \textbf{{{t['decoded']}}} \\", r"\midrule\endhead"]
        for number, (key, forms) in enumerate(by_key.items()):
            if number:
                out.append(r"\addlinespace")
            note = forms[0][9]
            for i, (_key, _since, _until, _expected, _form_since, form_release, where, form, decoded, _note) in enumerate(forms):
                if language == "FR":
                    where, form, note = translated(where, form, forms[0][9])
                label = rf"\texttt{{{latex(key)}}}" if i == 0 else ""
                out.append(rf"{label} & {latex(form_release)} & \texttt{{{latex(where)}}} & {latex(form)} & "
                           rf"{t['yes'] if decoded == 'yes' else t['no']} \\")
            # Its remark, after its last form: since when its source is always there, and its note.
            remark = []
            expected = int(forms[0][3])
            if expected:
                remark.append(f"{t['expected']} {release(expected, releases) or expected}")
            if note:
                remark.append(note)
            if remark:
                out.append(rf" & \multicolumn{{4}}{{@{{}}L{{12.8cm}}@{{}}}}{{\itshape {latex((' ; ' if language == 'FR' else '; ').join(remark))}}} \\")
        out += [r"\bottomrule", r"\end{longtable}", "}", "", rf"\noindent{{\small {t['caption']}}}", ""]
        path = os.path.join(HERE, f"artefact-table_{language}.tex")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        print(path, len(by_key), "artefacts,", sum(len(v) for v in by_key.values()), "forms")


if __name__ == "__main__":
    main()
