#!/usr/bin/env python3
"""attack-coverage.py — the coverage of MITRE ATT&CK by the traces WAC
collects, for the article of the 3.0.0 (backlog B-052).

ONE SOURCE, ATT&CK's own data: the STIX bundle of Enterprise ATT&CK
(mitre-attack/attack-stix-data, version and SHA-256 cited in the output).
Since ATT&CK 18, a technique is detected by detection strategies, each made
of analytics; a Windows analytic names its log sources, each a pair (data
component, log source: "Process Creation", "WinEventLog:Sysmon EventCode=1").
The script walks, for each Windows technique, every pair its Windows
analytics name, and decides each pair from two tables written below, once:
  - LOG_SOURCES: what WAC does with a log source — a Windows event log is
    taken whatever its channel, even moved (events); a live telemetry, a
    network capture, a cloud service is not on the examined disk;
  - COMPONENTS: the artefacts of WAC that hold, on disk, a trace of a data
    component beyond the logs ("Process Creation": Prefetch, Amcache…).
A log source or a component the tables do not decide stops the script: a
new version of ATT&CK is decided before its table is written, never left
out silently.

Usage: doc/attack-coverage.py <enterprise-attack-<version>.json>
  writes doc/attack-coverage_EN.tex and doc/attack-coverage_FR.tex
"""
import collections
import hashlib
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# The LaTeX escaping of the artefact table, the same for both tables.
_spec = importlib.util.spec_from_file_location("artefact_table", os.path.join(HERE, "artefact-table.py"))
_artefact_table = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_artefact_table)
latex = _artefact_table.latex

# Why a source is not taken: the same few reasons, in both languages.
REASONS = {
    "live": ("live telemetry (ETW, API calls, performance counters): never written to the disk",
             "télémétrie vivante (ETW, appels d'API, compteurs) : jamais écrite sur le disque"),
    "network": ("network capture: on the wire, not on the machine",
                "capture réseau : sur le réseau, pas sur la machine"),
    "cloud": ("cloud service: in the tenant's logs, not on the machine",
              "service en nuage : dans les journaux du locataire, pas sur la machine"),
    "edr": ("an EDR product's own telemetry: in its console",
            "télémétrie propre à un EDR : dans sa console"),
    "firmware": ("firmware: not read, WAC reads the disk",
                 "micrologiciel : non lu, WAC lit le disque"),
    "server": ("server role (IIS, AD FS, domain controller): version 4.0",
               "rôle serveur (IIS, AD FS, contrôleur de domaine) : version 4.0"),
    "model": ("an AI model's behaviour: ATT&CK names no trace of it on Windows",
              "comportement d'un modèle d'IA : ATT&CK ne lui connaît aucune trace sous Windows"),
}

# The Windows techniques ATT&CK gives no Windows analytic: decided here, from
# what the technique leaves on the disk — (WAC keys, reason).
WITHOUT_ANALYTIC = {
    "T1021.004": (["events"], None),                  # SSH: OpenSSH/Operational, sshd's own log
    "T1546.018": (["mft", "usn_journal"], None),      # Python startup hooks: .pth and usercustomize files written
    "T1552.003": (["powershell_history"], None),      # shell history: PSReadLine's
    "T1685.007": ([], "model"),
    "T1698": ([], "model"),
    "T1699": ([], "model"),
}

# Log sources, by the start of their name (lower case), first match wins:
# (WAC keys, reason when nothing is taken).
LOG_SOURCES = [
    ("wineventlog:sysmon", (["events", "sysmon"], None)),
    ("wineventlog:iis", ([], "server")),
    ("wineventlog:microsoft-iis", ([], "server")),
    ("wineventlog:adfs", ([], "server")),
    ("wineventlog:", (["events"], None)),
    ("autoruns:registryscan", (["persistence", "run_keys", "services", "scheduled_tasks", "startup_folders"], None)),
    ("windows firewall log", (["firewall_log"], None)),
    ("applicationlog:intune", (["intune_logs", "events"], None)),
    ("applicationlog:iis", ([], "server")),
    ("applicationlog:callrecords", ([], "cloud")),
    ("etw", ([], "live")),
    ("windows:perfmon", ([], "live")),
    ("windows:osquery", ([], "live")),
    ("edr", ([], "edr")),
    ("m365defender", ([], "edr")),
    ("m365:defender", ([], "edr")),
    ("m365:", ([], "cloud")),
    ("azure:", ([], "cloud")),
    ("aws:", ([], "cloud")),
    ("nsm:", ([], "network")),
    ("network traffic", ([], "network")),
    ("dns:query", ([], "network")),
    ("firmware:", ([], "firmware")),
]

# Data components: the artefacts of WAC that keep, on the disk, a trace of
# what the component records — beyond the event logs, decided above.
COMPONENTS = {
    "Process Creation": ["prefetch", "amcache", "shimcache", "bam", "userassist", "muicache", "srum", "program_usage"],
    "Process Access": [],
    "Process Modification": [],
    "Process Metadata": ["processes"],
    "Process Termination": [],
    "Command Execution": ["powershell_history", "prefetch"],
    "Script Execution": ["powershell_history", "powershell_profiles"],
    "OS API Execution": [],
    "Module Load": [],
    "File Creation": ["mft", "usn_journal", "zone_identifiers"],
    "File Modification": ["mft", "usn_journal", "log_file"],
    "File Deletion": ["usn_journal", "deleted_files", "recycle_bin"],
    "File Access": ["jump_lists", "recent_documents", "shortcuts", "shellbags", "explorer_recent_docs"],
    "File Metadata": ["mft", "security_descriptors", "zone_identifiers"],
    "Network Connection Creation": ["srum", "network", "firewall_log", "rdp_client", "bits", "web_client"],
    "Network Traffic Content": [],
    "Network Traffic Flow": ["srum", "firewall_log"],
    "Network Share Access": ["mount_points", "network_shares", "shellbags"],
    "Windows Registry Key Modification": ["run_keys", "persistence", "services", "registry_backups", "shadow_copies"],
    "Windows Registry Key Creation": ["run_keys", "persistence", "services", "registry_backups", "shadow_copies"],
    "Windows Registry Key Access": [],
    "Service Creation": ["services"],
    "Service Modification": ["services"],
    "Service Metadata": ["services"],
    "Driver Load": ["services"],
    "Scheduled Job Creation": ["scheduled_tasks"],
    "Scheduled Job Modification": ["scheduled_tasks"],
    "Scheduled Job Metadata": ["scheduled_tasks"],
    "WMI Creation": ["wmi"],
    "Logon Session Creation": ["users", "rdp_server"],
    "Logon Session Metadata": ["users", "sessions", "rdp_server"],
    "User Account Authentication": ["users"],
    "User Account Creation": ["users"],
    "User Account Modification": ["users", "local_groups"],
    "User Account Deletion": [],
    "User Account Metadata": ["users", "local_groups", "security"],
    "Group Enumeration": [],
    "Firewall Rule Modification": ["firewall"],
    "Drive Creation": ["usbstor", "mounted_devices", "devices", "setupapi", "mount_points"],
    "Drive Access": ["mount_points", "shellbags", "fat_volumes"],
    "Drive Modification": ["ntfs_volumes", "boot_records"],
    "Volume Creation": ["mounted_devices", "ntfs_volumes", "shadow_copies"],
    "Host Status": [],
    "Named Pipe Metadata": [],
    "Application Log Content": ["defender", "setupapi", "error_reports"],
    "Web Credential Creation": ["web_client", "dpapi_master_keys"],
    "Firmware Modification": [],
    "Active Directory Object Modification": [],
    "Active Directory Object Access": [],
    "Active Directory Object Creation": [],
    "Active Directory Object Deletion": [],
    "Active Directory Credential Request": [],
    "Cloud Service Metadata": [],
    "Cloud Storage Access": [],
    "Instance Creation": [],
    "Instance Start": [],
    "Domain Registration": [],
}

LABELS = {
    "EN": {"technique": "Technique", "logs": "Logs", "disk_short": "Disk", "yes": "yes", "left": "Sources not taken",
           "source": "Log source", "decision": "WAC",
           "component": "Data component", "disk": "On the disk, beyond the logs",
           "caption": "ATT\\&CK Enterprise {version} ({date}, SHA-256 {sha}): {techniques} Windows techniques and "
                      "sub-techniques; {covered} with at least one trace WAC collects, {nothing} whose sources are all "
                      "off the disk; {absent} (marked *) have no Windows analytic in ATT\\&CK and are decided from the technique itself. \\emph{{Logs}}: a log WAC takes holds a trace of the technique; \\emph{{Disk}}: an artefact on the disk does, beyond the logs. A Windows event log is only there if the "
                      "machine kept it: WAC records the channels' configuration and the audit policy, which say so.",
           "reasons": "Sources not taken, and why", "sep": "; "},
    "FR": {"technique": "Technique", "logs": "Journaux", "disk_short": "Disque", "yes": "oui", "left": "Sources non prises",
           "source": "Source de journal", "decision": "WAC",
           "component": "Composant de données", "disk": "Sur le disque, hors des journaux",
           "caption": "ATT\\&CK Enterprise {version} ({date}, SHA-256 {sha}) : {techniques} techniques et "
                      "sous-techniques Windows ; {covered} avec au moins une trace que WAC prélève, {nothing} dont "
                      "toutes les sources sont hors du disque ; {absent} (marquées *) n'ont pas d'analytique Windows dans ATT\\&CK et sont décidées d'après la technique elle-même. \\emph{{Journaux}} : un journal que WAC prend porte une trace de la technique ; \\emph{{Disque}} : un artefact sur le disque en porte une, hors des journaux. Un journal "
                      "d'événements n'est là que si la machine l'a tenu : WAC relève la configuration des canaux et "
                      "la politique d'audit, qui le disent.",
           "reasons": "Sources non prises, et pourquoi", "sep": " ; "},
}


# The keys that are logs: a trace there exists only if the machine logged it.
LOG_KEYS = {"events", "sysmon"}


def live(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def log_source(name):
    """The decision on a log source: (WAC keys, reason); stops on one undecided."""
    lower = name.lower()
    for start, decision in LOG_SOURCES:
        if lower.startswith(start):
            return decision
    sys.exit(f"log source without a decision: {name}")


def component_keys(name):
    """The artefacts of WAC holding a component on the disk; stops on one undecided."""
    if name not in COMPONENTS:
        sys.exit(f"data component without a decision: {name}")
    return COMPONENTS[name]


def techniques(bundle):
    """Each Windows technique: (id, name, set of WAC keys, set of reasons, analysed)."""
    objects = {o["id"]: o for o in bundle["objects"]}
    analytics_of = collections.defaultdict(list)
    for r in bundle["objects"]:
        if r["type"] == "relationship" and r["relationship_type"] == "detects" and live(r):
            strategy = objects.get(r["source_ref"])
            if strategy and live(strategy):
                analytics_of[r["target_ref"]] += strategy.get("x_mitre_analytic_refs", [])
    rows = []
    for t in bundle["objects"]:
        if t["type"] != "attack-pattern" or not live(t) or "Windows" not in t.get("x_mitre_platforms", []):
            continue
        tid = next(e["external_id"] for e in t["external_references"] if e.get("source_name") == "mitre-attack")
        keys, reasons, analysed = set(), set(), False
        for ref in analytics_of.get(t["id"], []):
            a = objects.get(ref)
            if not a or not live(a) or "Windows" not in a.get("x_mitre_platforms", []):
                continue
            sources = a.get("x_mitre_log_source_references", [])
            if isinstance(sources, str):     # some analytics carry it as a JSON text
                sources = json.loads(sources)
            for s in sources:
                analysed = True
                taken, reason = log_source(s["name"])
                keys.update(taken)
                if reason:
                    reasons.add(reason)
                keys.update(component_keys(objects[s["x_mitre_data_component_ref"]]["name"]))
        if not analysed:
            if tid not in WITHOUT_ANALYTIC:
                sys.exit(f"technique without a Windows analytic and without a decision: {tid} {t['name']}")
            taken, reason = WITHOUT_ANALYTIC[tid]
            keys.update(taken)
            if reason:
                reasons.add(reason)
        rows.append((tid, t["name"], keys, reasons, analysed))
    rows.sort(key=lambda r: [int(n) for n in re.findall(r"\d+", r[0])])
    return rows


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    bundle = json.loads(raw)
    collection = next(o for o in bundle["objects"] if o["type"] == "x-mitre-collection")
    version, date = collection["x_mitre_version"], collection["modified"][:10]
    sha = hashlib.sha256(raw).hexdigest().upper()
    rows = techniques(bundle)
    covered = sum(1 for r in rows if r[2])
    absent = sum(1 for r in rows if not r[4])
    for language in ("EN", "FR"):
        t, index = LABELS[language], 0 if language == "EN" else 1
        out = [f"% Generated by doc/attack-coverage.py from ATT&CK Enterprise {version} — do not edit.", r"{\small"]
        # The decisions, once: log sources, then data components.
        out += [r"\begin{longtable}{@{}L{5.2cm}L{9.4cm}@{}}", r"\toprule",
                rf"\textbf{{{t['source']}}} & \textbf{{{t['decision']}}} \\", r"\midrule\endhead"]
        for start, (taken, reason) in LOG_SOURCES:
            decision = ", ".join(rf"\texttt{{{latex(k)}}}" for k in taken) or latex(REASONS[reason][index])
            out.append(rf"\texttt{{{latex(start)}…}} & {decision} \\")
        out += [r"\bottomrule", r"\end{longtable}", "",
                r"\begin{longtable}{@{}L{5.2cm}L{9.4cm}@{}}", r"\toprule",
                rf"\textbf{{{t['component']}}} & \textbf{{{t['disk']}}} \\", r"\midrule\endhead"]
        for name, keys in COMPONENTS.items():
            out.append(rf"{latex(name)} & {', '.join(rf'\texttt{{{latex(k)}}}' for k in keys) or '—'} \\")
        out += [r"\bottomrule", r"\end{longtable}", ""]
        # Each technique.
        # Each technique, on one line: whether a log WAC takes holds a trace of
        # it, whether an artefact on the disk does beyond the logs (the tables
        # above say which), and the sources not taken.
        out += [r"\begin{longtable}{@{}L{1.9cm}L{6.3cm}L{1.6cm}L{1.6cm}L{3.2cm}@{}}", r"\toprule",
                rf"\textbf{{ID}} & \textbf{{{t['technique']}}} & \textbf{{{t['logs']}}} & \textbf{{{t['disk_short']}}} & "
                rf"\textbf{{{t['left']}}} \\", r"\midrule\endhead"]
        short = {"live": "ETW", "network": "NSM", "cloud": "cloud", "edr": "EDR", "firmware": "firmware",
                 "server": "4.0", "model": "IA" if index else "AI"}
        for tid, name, keys, reasons, analysed in rows:
            logs = t["yes"] if keys & LOG_KEYS else "—"
            disk = t["yes"] if keys - LOG_KEYS else "—"
            left = ", ".join(short[r] for r in sorted(reasons))
            out.append(rf"{latex(tid)} & {latex(name)}{'' if analysed else '*'} & {logs} & {disk} & {left} \\")
        out += [r"\bottomrule", r"\end{longtable}", "}", "",
                rf"\noindent{{\small {t['caption'].format(version=version, date=date, sha=sha[:16] + '…', techniques=len(rows), covered=covered, nothing=len(rows) - covered, absent=absent)}}}",
                "", rf"\noindent{{\small {t['reasons']}{' : ' if index else ': '}"
                + t["sep"].join(f"{short[k]}, {latex(v[index])}" for k, v in REASONS.items()) + "}", ""]
        path = os.path.join(HERE, f"attack-coverage_{language}.tex")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        print(path, len(rows), "techniques,", covered, "covered,", absent, "without a Windows analytic")


if __name__ == "__main__":
    main()
