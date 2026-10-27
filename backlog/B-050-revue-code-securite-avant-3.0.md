# B-050 — Revue de code et revue de sécurité de tout le projet, avant la 3.0.0

| Statut | Priorité | Effort |
|---|---|---|
| en cours (préalable à la publication de la 3.0.0) | P1 | fort |

## Pourquoi
Demande utilisateur du 2026-10-15 : avant de publier la 3.0.0, une revue de code de l'ensemble du projet, et idéalement une revue de sécurité. La 3.0 ajoute beaucoup de décodeurs de formats non documentés (Prefetch 26, ShimCache et Amcache de Windows 8, index de recherche ESE, files BITS anciennes, réseau et journaux de XP…), et le travail de 2.0.1 à 2.0.3 a montré que des défauts anciens produisent du JSON valide et faux sans le moindre signal : rejeu des ruches qui perdait une entrée, condensats SAM faux au schéma RC4, empreintes prises sur les copies de travail. Une revue d'ensemble, distincte des contrôles du harnais, cherche ce que les cycles ne voient pas.

## Périmètre
Tout le dépôt, pas seulement les modifications récentes :
- `sources/` : chaque collecteur et décodeur, le lecteur NTFS brut, le lecteur de ruches, le lecteur ESE, la consigne et son sceau, la configuration ;
- les scripts livrés (`sources/scripts` : vérification de la consigne, en PowerShell et en shell) ;
- `build-windows.sh`, `bump-version.sh` ;
- le harnais (`vmtest/`) : en second, il ne part pas chez l'analyste.

## Ce que la revue de code doit chercher
- **Justesse** : lectures bornées par la taille réelle du tampon (règle commune n° 3), résultats d'appels lus (n° 5), champs vides non émis (n° 1), dates UTC et locales, codes Windows (énumération ou champ de bits), conversions d'encodage ;
- **Règles communes** (`/var/www/html/.claude/CLAUDE.md`) : code mort, copier-coller, nommage anglais, commentaires faux ou absents ;
- **Cohérence** : une seule normalisation des chemins, une seule fonction par conversion, même structure pour chaque artefact.

## Ce que la revue de sécurité doit chercher
Toute pièce lue est hostile (règle commune n° 3) : ruches, bases ESE et SQLite, Prefetch, raccourcis, journaux, quarantaine de Defender… forgés pour faire lire WAC hors de son tampon, boucler, allouer sans borne ou écrire hors du dossier de sortie. Aussi :
- l'innocuité de la collecte (rien d'écrit sur le disque examiné) ;
- la consigne intouchable après sa copie initiale ;
- l'absence de secret dans le code et dans l'historique git ;
- les dépendances (SQLite, libyaml) et le chargement des DLL système (esent.dll, WinHTTP).

## Outils
- **`/code-review`** (Claude Code) : par cible de chemin, module par module (lecteurs bruts, décodeurs, consigne, scripts), au niveau `high` ou `xhigh`, constats rapportés puis vérifiés un par un ; `--fix` seulement après lecture. La variante `/code-review ultra` n'est pas utilisée (décision utilisateur du 2026-10-27).
- **`/security-review`** (Claude Code) : revue de sécurité dédiée ; à appliquer à l'ensemble du code, par branche ou par lots, en plus de `/code-review`.
- Le harnais existant : chaque constat corrigé reçoit le test qui l'aurait pris (règle commune, section 6).

## Critères d'acceptation
- Chaque module de `sources/` passé en revue (liste tenue dans le journal ci-dessous) ;
- chaque constat soit corrigé (commit cité, avec son test), soit écarté avec sa raison écrite ici ;
- revue de sécurité passée sur tout le code livré ;
- cycles VM Windows 11 et 8.1 sans échec après les corrections ;
- puis seulement : montée de version 3.0.0 (`bump-version.sh --major`) et publication.

## Lots de revue (2026-10-27)
Par exposition aux données hostiles, les lecteurs du disque brut en premier :
1. **Disque et système de fichiers** : raw_hive (lecteur NTFS), mft, usn_journal, fat_volume, fat_volumes, vss, deleted_files, carving, boot_records, ntfs_volumes, security_descriptors, exhibit_reader, raw_collect.
2. **Registre** : offline_registry, hive_recover, sam_secrets, security_hive, des, rsa, registry_common, registry_lot2, registry_lot3, reg_*, users, local_groups, account_names, persistence, services, idList, recent_docs, user_shell_folders, cloud_identity, sysmon, event_log_files.
3. **Compression, conteneurs, binaires** : inflate, lzx, lznt1, xpress, cab, zip, oleparser, pe_resource, version_info, authenticode, trust_set, trust_update, binaires, cim_repository, wmi_persistence.
4. **Bases de données** : ese_database, ese_recovery, sqlite_reader, search_index, search_property_types, srum, web_client, browser_sessions, activities_cache, bits_jobs.
5. **Journaux et fichiers** : evtx, evt, wevt, event_messages, events, prefetchs, jumplist_automatic, jumplist_custom, recycle_bin, thumbcache, ie_index_dat, pst_file, pst_messages, mbox_mail, emails, defender_history, defender_log, setupapi_log, firewall_log, intune_logs, xml_light, csv_reader, yaml_light, powershell_history, powershell_profiles, rdp_client, rdp_server, scheduledTasks, error_reports, link_tracking, zone_identifiers, hosts_file, shortcuts, startup_folders, dpapi_master_keys.
6. **Cœur** : main, tools, consigne, audit, config, time_zone, sha, quickdigest5, http_client, live_snapshot, running_machine, processes, network, sessions, system, translations, artefact_catalogue, xp_imports, trans_id (table produite), asciiart.
7. **Scripts et compilation** : sources/scripts (verifier-consigne, verify-exhibits, .ps1 et .sh), build-windows.sh, bump-version.sh.

## Tâches
- [x] Découper le dépôt en lots de revue (ci-dessus)
- [ ] `/code-review` lot par lot ; constats triés et traités (lots 1 et 2 : faits — 1315c4da, 49d34970 ; lot 3 à relancer)
- [ ] `/security-review` sur le code livré ; constats triés et traités
- [x] `/code-review ultra` : écarté par l'utilisateur (2026-10-27) — la revue se fait lot par lot avec `/code-review`
- [ ] Cycles VM verts après corrections
- [ ] Mise à jour des documents (validation, innocuité) si une correction change une opération

## Journal
- 2026-10-15 : fiche créée à la demande de l'utilisateur : revue de code de l'ensemble du projet avant de publier la 3.0.0, gros chantier ; idéalement une revue de sécurité avec le greffon adapté (`/security-review`).
- 2026-10-17 : décision utilisateur — la 3.0.0 couvre les clients de XP à 11 avec tous les artefacts (clichés instantanés et fichiers supprimés compris) ; la revue porte sur ce périmètre, avant la publication.
- 2026-10-27 : lot 1 (disque et système de fichiers), `/code-review high`, 18 constats vérifiés un par un dans le code :
  - corrigés : (1) aucune écriture de pièce vérifiée — un support plein laissait une pièce courte aux empreintes de la donnée lue → flux et fermeture contrôlés avant tout succès (`checkOutput`) ; (2) valeur d'un `$DATA` résident, et point de réanalyse WOF, non bornés par l'attribut → `residentAttributeValue`, une seule fonction pour les dix lectures de valeur résidente du projet (raw_hive, mft, deleted_files) ; (3) `NtfsVolume::open` lisait l'octet des secteurs par cluster tel quel (clusters de 128 Kio à 2 Mio mal lus, décalage non borné pour la taille d'enregistrement) → `parseNtfsBootSector`, déjà testé, enregistrement de 256 o à 64 Kio ; (4) échecs d'une arborescence (volume non ouvert, index illisible) ignorés, dans les sous-dossiers comme au niveau de la collecte → remontés ; (5) bloc WOF décompressé plus court que prévu écrit tel quel, les suivants décalés → refusé ; (6) carving des volumes FAT avant le niveau 1 NTFS, `max_total_mib` épuisé par une clé → `carveFatVolumes`, avec le carving NTFS ; (7) `FatAwareReader` réussissait sans fichier de sortie ouvert → échec d'écriture ; (8) `reading.front()` sur une liste vide quand le volume ne s'ouvre pas, et `ExtractFilesRaw` n'inscrivait alors aucun échec → chaque élément inscrit en échec, appelant protégé, résultat du catalogue lu ; (9) un fichier FAT présent dont le nom commence par 0xE5 (stocké 0x05) montré supprimé → distingué ; (10) exposant de l'unité de compression et taille de bloc d'index non bornés (décalage indéfini, 4 Gio alloués) → `compressionUnitClusters` (≤ 16), `plausibleIndexBlockSize` (512 o à 64 Kio) ; fichiers FAT non lus faute de budget absents du décompte de l'audit → comptés ; commentaire orphelin de ntfs_volumes.cpp retiré.
  - écartés : copie `S_FALSE` inscrite « OK » au manifeste — elle y porte déjà `DeclaredBytes` en plus de `Bytes`, et changer « OK » casserait les scripts de vérification livrés ; trous d'une récupération partielle comptés « récupérés » pour le carving — ce sont des clusters repris (en usage, ou réclamés par un supprimé plus récent), les tailler ne rendrait rien ; `pdfEnd` au premier `%%EOF` — voulu et documenté (carving.h : la première version, document entier) ; double lecture d'un fichier de cliché (empreinte, puis copie) — voulue, pour ne pas recopier un fichier identique à sa version plus récente ; `VolumeLease` sous un verrou commun, `$J` lu en mémoire, `$MFT` lue trois fois en récupération — coût, pas justesse : notés pour une version de performance.
  - tests : `ntfs_runs_test` (valeur résidente, unité de compression, taille de bloc), `fat_test` (0x05 / 0xE5) ; (1), (4), (6), (7), (8) touchent le système de fichiers vivant : vérifiés par la lecture du code et par les cycles VM après compilation.
- 2026-10-27 : lot 2 (registre), `/code-review high`, 10 constats vérifiés, tous retenus :
  - (1) `L"…" + id` (un entier) décalait le pointeur du littéral (reg_shellbags, reg_mru, reg_mru_apps) — illisible, et un identifiant forgé faisait planter → `std::to_wstring` ;
  - (2) et (8) énumération des sous-clés : `ERROR_MORE_DATA` laissait le nom précédent dans le tampon (un service relu, celui au nom long caché), et dix-sept boucles différentes, certaines arrêtées à la première erreur (tous les frères suivants perdus, sans un mot) → `subkeysOf`, la seule énumération : nombre demandé d'abord, nom long relu en entier, sous-clé illisible journalisée et sautée ; `subkeys()` s'y appuie ; reg_mru saute la sous-clé « * » par son nom, non plus par son rang ;
  - (3) bloc Beef0004 construit dès 8 octets, sa partie fixe en a 18 → `BEEF0004_FIXED_PART`, la constante de sa table ;
  - (4) `Vector<VT_LPWSTR>` : avance `4 + size × 2` sur 32 bits, revenue à 0 pour une taille forgée, quatre milliards d'éléments → avance en `size_t`, bornée par le tampon, nombre plafonné (`MAX_VECTOR_ELEMENTS`, la borne des autres vecteurs) ;
  - (5) bornes `base + offset + length` débordables sous WAC32 (sam_secrets, users, local_groups, hive_recover) → `fits()`, sans addition ;
  - (6) `ArchiveDirectory` vide ou d'un autre type lu comme la racine du volume système, parcourue tout entière → aucun dossier ;
  - (7) clés AppCompatCache et MountedDevices jamais fermées, la ruche gardée ouverte → fermées ;
  - (9) `readStringData` (raccourcis) : bornes débordables → `fits()` ;
  - (10) cible d'un `.url` prise à la deuxième ligne (« 3=19,11 » pour ceux d'Internet Explorer) → `internetShortcutUrl`, la ligne `URL=` de la section `[InternetShortcut]`.
  - tests : `shell_items_test` (vecteur de chaînes forgé), `file_artefacts_test` (`.url`) ; (5) ne déborde qu'en 32 bits, les tests tournent en 64 : la borne est vérifiée par lecture ; (2)/(8) et (7) touchent le lecteur de ruches vivant : vérifiés par les cycles VM.
- 2026-10-27 : décision utilisateur — pas de `/code-review ultra`. Lot 3 (compression, conteneurs, binaires) lancé puis arrêté à la demande de l'utilisateur, avant tout constat : à relancer. Correctifs des lots 1 et 2 écrits, ni compilés ni testés, non commités : prochaine étape `./build-windows.sh --test`, puis les tests (`ntfs_runs_test`, `fat_test`, `shell_items_test`, `file_artefacts_test`) et un cycle Windows 11.
- 2026-10-27 : lots 1 et 2 compilés (`--test`, sans avertissement) et testés : ntfs_runs_test 100 023, fat_test 7, shell_items_test 685, file_artefacts_test 254 contrôles, et les tests des fichiers supprimés, du carving, des clichés, de la $MFT, du journal USN et du rejeu des ruches sans échec ; chaque nouveau test vu échouer par mutation. Au passage : le vecteur de chaînes (MS-OLEPS) lisait le nombre d'éléments comme première longueur et ignorait le bourrage — corrigé avec le reste ; `parseNtfsBootSector` sorti de ntfs_volumes dans ntfs_boot_sector (portable, lié à raw_hive_test) ; `fits` dans portable_conversions.h. Commits 1315c4da (lot 1), 49d34970 (lot 2). Cycles VM à suivre.
