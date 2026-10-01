/*! \file
 *  \brief The wording of the console's texts, in French and English (see translations.h).
 */
#include "translations.h"

namespace {

//! One text: its name, its French and its English wording.
struct Wording {
	Text id;              //!< the text
	const wchar_t* french;  //!< French wording
	const wchar_t* english; //!< English wording
};

/*! Every text, in the order of `Text`: the check below refuses a table out of
 *  order or incomplete at compile time. %1 to %9 are replaced by the arguments
 *  given to text(). */
constexpr Wording WORDINGS[] = {
	{ Text::HeadingPrerequisites,      L"[VÉRIFICATION DES PRÉREQUIS]",                  L"[PREREQUISITE VERIFICATION]" },
	{ Text::HeadingCheckingCollection, L"[CONTRÔLE DE LA COLLECTE]",                     L"[CHECKING THE COLLECTION]" },
	{ Text::HeadingLiveState,          L"[OBSERVATION DE LA MACHINE EN MARCHE]",         L"[SEARCHING FOR ARTIFACTS IN WINDOWS API]" },
	{ Text::HeadingRawExtraction,      L"[EXTRACTION BRUTE]",                            L"[RAW EXTRACTION]" },
	{ Text::HeadingForConversion,      L"[PRÉLÈVEMENTS POUR LA CONVERSION]",             L"[COLLECTION FOR THE CONVERSION]" },
	{ Text::HeadingRegistry,           L"[ARTEFACTS DU REGISTRE]",                       L"[SEARCHING FOR ARTIFACTS IN THE REGISTRY]" },
	{ Text::HeadingFiles,              L"[ARTEFACTS DES FICHIERS]",                      L"[SEARCHING FOR ARTIFACTS IN FILES]" },
	{ Text::HeadingEventLogs,          L"[JOURNAUX D'ÉVÉNEMENTS]",                       L"[SEARCHING FOR ARTIFACTS IN EVENT LOGS]" },
	{ Text::HeadingExhibitStore,       L"[CONSIGNE]",                                    L"[EXHIBIT STORE]" },
	{ Text::HeadingInvestigationLog,   L"[JOURNAL D'INVESTIGATION]",                     L"[INVESTIGATION LOG]" },

	{ Text::StepWindowsVersion,        L"Windows 10 ou ultérieur",                       L"Check OS >= Windows 10" },
	{ Text::StepAdministratorRights,   L"Droits d'administrateur",                       L"Check administrator rights" },
	{ Text::StepCollectionMedium,      L"Contrôle du support de collecte",               L"Checking the collection medium" },
	{ Text::StepSealAndFingerprints,   L"Contrôle du sceau et des empreintes des pièces", L"Checking the seal and the fingerprints of the exhibits" },
	{ Text::StepRebuildWorkingCopy,    L"Copie de travail reconstituée depuis la consigne", L"Rebuilding the working copy from the exhibit store" },
	{ Text::StepRepairWorkingHives,    L"Réparation des ruches de la copie de travail",  L"Repairing the hives of the working copy" },

	{ Text::StepRunningMachine,        L"Réglages de la machine en marche",              L"Extraction of RUNNING MACHINE SETTINGS" },
	{ Text::StepSessions,              L"Sessions",                                      L"Extraction of SESSIONS" },
	{ Text::StepProcesses,             L"Processus",                                     L"Extraction of PROCESS" },
	{ Text::StepNetworkState,          L"État du réseau",                                L"Extraction of NETWORK STATE" },
	{ Text::StepServiceStates,         L"État des services",                             L"Extraction of SERVICE STATES" },
	{ Text::StepSystemClock,           L"Horloge du système",                            L"Extraction of SYSTEM CLOCK" },

	{ Text::StepSystemHives,           L"Ruches du système (lecture brute NTFS)",        L"Extracting system hives (raw NTFS)" },
	{ Text::StepUserHives,             L"Ruches des utilisateurs (lecture brute NTFS)",  L"Extracting user hives (raw NTFS)" },
	{ Text::StepFileArtefacts,         L"Artefacts fichiers (lecture brute NTFS)",       L"Extracting file artefacts (raw NTFS)" },
	{ Text::StepNtfsMetadata,          L"Métadonnées NTFS ($MFT, $UsnJrnl, $LogFile) (lecture brute NTFS)",
	                                   L"Extracting NTFS metadata ($MFT, $UsnJrnl, $LogFile) (raw NTFS)" },
	{ Text::StepFatMetadata,           L"Volumes FAT et exFAT (lecture brute des métadonnées)", L"FAT and exFAT volumes (raw reading of the metadata)" },
	{ Text::StepTrustSet,              L"Jeu de confiance",                              L"Trust set" },
	{ Text::StepCopyBinaries,          L"Copie des binaires prélevés dans la copie de travail", L"Copying collected binaries to the working directory" },
	{ Text::StepSealExhibitStore,      L"Scellement de la consigne (manifeste + SHA-256)", L"Sealing the exhibit store (manifest + SHA-256)" },
	{ Text::StepEventResources,        L"Fichiers de ressources de chaque fournisseur d'événements",
	                                   L"Extracting the resource files of every event provider" },
	{ Text::StepAllExecutables,        L"Lecture de chaque exécutable, prélèvement des non authentifiés (lecture brute NTFS)",
	                                   L"Reading every executable, collecting the unauthenticated (raw NTFS)" },
	{ Text::StepOpenSystemHive,        L"Ouverture de la ruche SYSTEM",                  L"loading the HKLM\\SYSTEM key" },
	{ Text::StepOpenSoftwareHive,      L"Ouverture de la ruche SOFTWARE",                L"loading the HKLM\\SOFTWARE key" },
	{ Text::StepUserProfiles,          L"Profils des utilisateurs (ruche SOFTWARE)",     L"Listing USER PROFILES (SOFTWARE hive)" },

	{ Text::StepWriteLiveState,        L"Écriture des processus, sessions et réseau",    L"Writing PROCESS, SESSIONS and NETWORK" },
	{ Text::StepFindControlSet,        L"Recherche de la sous-clé CurrentControlSet",    L"Searching for the CurrentControlSet subkey" },
	{ Text::StepOpenControlSet,        L"Ouverture de la sous-clé CurrentControlSet",    L"Opening the CurrentControlSet subkey" },
	{ Text::StepSuspectTimeZone,       L"Fuseau horaire de la machine examinée (ruche SYSTEM)", L"Reading suspect time zone (SYSTEM hive)" },
	{ Text::StepSuspectCodePage,       L"Page de code ANSI de la machine examinée (ruche SYSTEM)", L"Reading suspect ANSI code page (SYSTEM hive)" },
	{ Text::StepAccountNames,          L"Noms des comptes (SAM, services, profils)",     L"Naming the accounts (SAM, services, profiles)" },
	{ Text::StepUsbstor,               L"Clés USBSTOR du registre",                      L"Extracting USBSTOR Registry Keys" },
	{ Text::StepMountedDevices,        L"Clés MountedDevices du registre",               L"Extracting the MOUNTED DEVICE registry keys" },
	{ Text::StepBam,                   L"Clés BAM du registre",                          L"Extracting BAM Registry Keys" },
	{ Text::StepMuiCache,              L"Clés MUICache du registre",                     L"Extracting MUICACHE Registry Keys" },
	{ Text::StepAmcache,               L"Amcache : inventaire (applications, exécutables, pilotes, périphériques)", L"Amcache inventory (applications, executables, drivers, devices)" },
	{ Text::StepUserAssist,            L"Clés UserAssist du registre",                   L"Extracting USERASSIST Registry Keys" },
	{ Text::StepRunKeys,               L"Clés Run du registre",                          L"Extracting RUN Registry Keys" },
	{ Text::StepShimcache,             L"Shimcache",                                     L"Extracting SHIMCACHE Registry Keys" },
	{ Text::StepShellbags,             L"Shellbags",                                     L"Extracting SHELLBAGS Registry Keys" },
	{ Text::StepMru,                   L"Listes MRU du registre",                        L"Extracting MRU Registry Keys" },
	{ Text::StepMruApps,               L"Listes MRU des applications",                   L"Extracting MRUAPPS Registry Keys" },
	{ Text::StepSystemInformation,     L"Informations sur le système",                   L"Extraction of SYSTEM INFORMATION" },
	{ Text::StepServices,              L"Services",                                      L"Extraction of SERVICES" },
	{ Text::StepUsers,                 L"Utilisateurs",                                  L"Extraction of USERS" },

	{ Text::StepScheduledTasks,        L"Tâches planifiées (hors ligne)",                L"Extracting SCHEDULED TASKS (offline)" },
	{ Text::StepRecentDocuments,       L"Documents récents",                             L"Extracting RECENT DOCS" },
	{ Text::StepPrefetch,              L"Prefetch",                                      L"Extracting PREFETCHS" },
	{ Text::StepReadMft,               L"Lecture de la $MFT",                            L"Reading the $MFT" },
	{ Text::StepWriteMft,              L"Écriture de la $MFT",                           L"Writing the $MFT" },
	{ Text::StepUsnJournal,            L"Journal des modifications ($UsnJrnl)",          L"Extracting the CHANGE JOURNAL" },
	{ Text::StepJumpListsAutomatic,    L"Listes de sauts automatiques",                  L"Extracting JUMPLIST AUTOMATIC" },
	{ Text::StepJumpListsCustom,       L"Listes de sauts personnalisées",                L"Extracting JUMPLIST CUSTOM" },
	{ Text::StepEvents,                L"Journaux d'événements",                         L"Extraction of EVENTS" },
	{ Text::StepPowerShellHistory,     L"Historique PowerShell",                         L"Extracting POWERSHELL HISTORY" },
	{ Text::StepSetupApi,              L"Installations de périphériques (setupapi.dev.log)", L"Extracting DEVICE INSTALLATIONS (setupapi.dev.log)" },
	{ Text::StepRecycleBin,            L"Corbeille",                                     L"Extracting RECYCLE BIN" },
	{ Text::StepHosts,                 L"Fichier hosts",                                 L"Extracting HOSTS FILE" },
	{ Text::StepErrorReports,          L"Rapports d'erreurs (WER)",                      L"Extracting ERROR REPORTS (WER)" },
	{ Text::StepDefenderLogs,          L"Journaux de Defender (MPLog)",                  L"Extracting DEFENDER LOGS (MPLog)" },
	{ Text::StepDefenderDetections,    L"Détections de Defender (DetectionHistory)",     L"Extracting DEFENDER DETECTIONS (DetectionHistory)" },
	{ Text::StepDefenderQuarantine,    L"Quarantaine de Defender",                       L"Extracting DEFENDER QUARANTINE" },
	{ Text::StepStartupFolders,        L"Dossiers de démarrage",                         L"Extracting STARTUP FOLDERS" },
	{ Text::StepZoneIdentifiers,       L"Origine des fichiers téléchargés (Zone.Identifier)", L"Extracting ZONE.IDENTIFIER streams" },
	{ Text::StepSecurityHive,          L"Ruche SECURITY (noms des secrets, connexions en cache, audit)", L"Extracting the SECURITY HIVE (secret names, cached logons, audit)" },
	{ Text::StepPersistence,           L"Persistance dans le registre (IFEO, AppInit, Winlogon, LSA, COM…)", L"Extracting REGISTRY PERSISTENCE (IFEO, AppInit, Winlogon, LSA, COM…)" },
	{ Text::StepOfficeTrustRecords, L"Documents Office approuvés (macros activées)", L"Extracting Office TRUSTED DOCUMENTS (macros enabled)" },
	{ Text::StepTypedPaths, L"Chemins tapés dans l'Explorateur", L"Extracting Explorer TYPED PATHS" },
	{ Text::StepWordWheelQueries, L"Recherches de l'Explorateur", L"Extracting Explorer SEARCHES (WordWheelQuery)" },
	{ Text::StepRootCertificates, L"Certificats racines de la machine et des utilisateurs", L"Extracting ROOT CERTIFICATES of the machine and users" },
	{ Text::StepInternetSettingsSet, L"Réglages de proxy des utilisateurs", L"Extracting INTERNET SETTINGS (proxy) of the users" },
	{ Text::StepFirewall, L"Règles et profils du pare-feu", L"Extracting FIREWALL rules and profiles" },
	{ Text::StepWmiPersistence, L"Abonnements WMI (dépôt CIM lu hors ligne)", L"Extracting WMI SUBSCRIPTIONS (CIM repository, read offline)" },
	{ Text::StepSrum, L"Usage des ressources (SRUM)", L"Extracting RESOURCE USAGE (SRUM)" },
	{ Text::StepBitsJobs, L"Travaux BITS", L"Extracting BITS JOBS" },
	{ Text::StepFatVolumes, L"Volumes FAT et exFAT", L"Extracting FAT AND EXFAT VOLUMES" },
	{ Text::StepInstalledPrograms, L"Programmes installés", L"Extracting INSTALLED PROGRAMS (Uninstall)" },
	{ Text::StepDefenderConfiguration, L"Configuration de Defender : exclusions et protection", L"Extracting DEFENDER CONFIGURATION (exclusions, protection)" },
	{ Text::StepExplorerRecentDocs, L"Fichiers ouverts (RecentDocs de l'Explorateur)", L"Extracting EXPLORER RECENTDOCS" },
	{ Text::StepMountPoints, L"Volumes et partages vus (MountPoints2)", L"Extracting MOUNTPOINTS2 (volumes and shares)" },
	{ Text::StepKnownNetworks, L"Réseaux connus (NetworkList)", L"Extracting KNOWN NETWORKS (NetworkList)" },
	{ Text::StepProgramUsages, L"Usage des programmes (FeatureUsage, JumplistData, compatibilité, épinglés)", L"Extracting PROGRAM USAGE (FeatureUsage, JumplistData, compatibility, pinned)" },
	{ Text::StepDevices, L"Périphériques (USB, SCSI, portables, volumes)", L"Extracting DEVICES (USB, SCSI, portable, volumes)" },
	{ Text::StepNetworkShares, L"Partages réseau de la machine", L"Extracting NETWORK SHARES" },
	{ Text::StepNetworkConfiguration, L"Configuration réseau (hors ligne)", L"Extracting NETWORK CONFIGURATION (offline)" },
	{ Text::StepEventLogConfiguration, L"Configuration des journaux d'événements", L"Extracting EVENT LOG CONFIGURATION" },

	{ Text::StepWriteConversionLog,    L"Écriture de conversion.json",                   L"Writing conversion.json" },
	{ Text::StepWriteInvestigationLog, L"Écriture de investigation.json",                L"Writing investigation.json" },

	{ Text::ArtefactProcesses,         L"Processus",                                     L"Processes" },
	{ Text::ArtefactSessions,          L"Sessions",                                      L"Sessions" },
	{ Text::ArtefactNetwork,           L"Réseau",                                        L"Network" },
	{ Text::ArtefactUsbDevices,        L"Périphériques USB",                             L"USB devices" },
	{ Text::ArtefactMountedDevices,    L"Volumes montés",                                L"Mounted devices" },
	{ Text::ArtefactBam,               L"BAM",                                           L"BAM" },
	{ Text::ArtefactMuiCache,          L"MUICache",                                      L"MUICache" },
	{ Text::ArtefactAmcacheApplications, L"Amcache : applications",                      L"Amcache applications" },
	{ Text::ArtefactAmcacheApplicationFiles, L"Amcache : fichiers d'applications",       L"Amcache application files" },
	{ Text::ArtefactAmcacheInventory,  L"Amcache : pilotes, périphériques, raccourcis",   L"Amcache drivers, devices, shortcuts" },
	{ Text::ArtefactUserAssist,        L"UserAssist",                                    L"UserAssist" },
	{ Text::ArtefactRunKeys,           L"Clés Run",                                      L"Run keys" },
	{ Text::ArtefactShimcache,         L"Shimcache",                                     L"Shimcache" },
	{ Text::ArtefactShellbags,         L"Shellbags",                                     L"Shellbags" },
	{ Text::ArtefactMru,               L"MRU",                                           L"MRU" },
	{ Text::ArtefactMruApps,           L"MRU des applications",                          L"MRU applications" },
	{ Text::ArtefactServices,          L"Services",                                      L"Services" },
	{ Text::ArtefactUsers,             L"Utilisateurs",                                  L"Users" },
	{ Text::ArtefactScheduledTasks,    L"Tâches planifiées",                             L"Scheduled tasks" },
	{ Text::ArtefactRecentDocuments,   L"Documents récents",                             L"Recent documents" },
	{ Text::ArtefactPrefetch,          L"Prefetch",                                      L"Prefetch" },
	{ Text::ArtefactMft,               L"$MFT",                                          L"$MFT" },
	{ Text::ArtefactUsnJournal,        L"Journal des modifications",                     L"Change journal" },
	{ Text::ArtefactJumpListsAutomatic, L"Listes de sauts (automatiques)",               L"Jump lists (automatic)" },
	{ Text::ArtefactJumpListsCustom,   L"Listes de sauts (personnalisées)",              L"Jump lists (custom)" },
	{ Text::ArtefactPowerShellHistory, L"Historique PowerShell",                         L"PowerShell history" },
	{ Text::ArtefactSetupApi,          L"Installations de périphériques",                L"Device installations" },
	{ Text::ArtefactRecycleBin,        L"Corbeille",                                     L"Recycle bin" },
	{ Text::ArtefactHosts,             L"Fichier hosts",                                 L"Hosts file" },
	{ Text::ArtefactErrorReports,      L"Rapports d'erreurs",                            L"Error reports" },
	{ Text::ArtefactDefenderLogs,      L"Journaux de Defender",                          L"Defender logs" },
	{ Text::ArtefactDefenderDetections, L"Détections de Defender",                       L"Defender detections" },
	{ Text::ArtefactDefenderQuarantine, L"Quarantaine de Defender",                      L"Defender quarantine" },
	{ Text::ArtefactStartupFolders,    L"Dossiers de démarrage",                         L"Startup folders" },
	{ Text::ArtefactZoneIdentifiers,   L"Origine des fichiers téléchargés",              L"Zone.Identifier streams" },
	{ Text::ArtefactSecurityHive,      L"Ruche SECURITY",                                L"SECURITY hive" },
	{ Text::ArtefactPersistence,       L"Persistance dans le registre",                  L"Registry persistence" },
	{ Text::ArtefactOfficeTrustRecords, L"Documents Office approuvés", L"Office trusted documents" },
	{ Text::ArtefactTypedPaths, L"Chemins tapés dans l'Explorateur", L"Explorer typed paths" },
	{ Text::ArtefactWordWheelQueries, L"Recherches de l'Explorateur", L"Explorer searches" },
	{ Text::ArtefactRootCertificates, L"Certificats racines", L"Root certificates" },
	{ Text::ArtefactInternetSettingsSet, L"Réglages de proxy", L"Internet settings" },
	{ Text::ArtefactFirewall, L"Pare-feu", L"Firewall" },
	{ Text::ArtefactWmiPersistence, L"Abonnements WMI", L"WMI subscriptions" },
	{ Text::ArtefactSrum, L"Usage des ressources (SRUM)", L"Resource usage (SRUM)" },
	{ Text::ArtefactBitsJobs, L"Travaux BITS", L"BITS jobs" },
	{ Text::ArtefactFatVolumes, L"Volumes FAT et exFAT", L"FAT and exFAT volumes" },
	{ Text::ArtefactInstalledPrograms, L"Programmes installés", L"Installed programs" },
	{ Text::ArtefactDefenderConfiguration, L"Configuration de Defender", L"Defender configuration" },
	{ Text::ArtefactExplorerRecentDocs, L"Fichiers ouverts (RecentDocs)", L"Opened files (RecentDocs)" },
	{ Text::ArtefactMountPoints, L"Volumes et partages vus (MountPoints2)", L"Volumes and shares seen (MountPoints2)" },
	{ Text::ArtefactKnownNetworks, L"Réseaux connus", L"Known networks" },
	{ Text::ArtefactProgramUsages, L"Usage des programmes", L"Program usage" },
	{ Text::ArtefactDevices, L"Périphériques", L"Devices" },
	{ Text::ArtefactNetworkShares, L"Partages réseau", L"Network shares" },
	{ Text::ArtefactNetworkConfiguration, L"Configuration réseau", L"Network configuration" },
	{ Text::ArtefactEventLogConfiguration, L"Configuration des journaux d'événements", L"Event log configuration" },
	{ Text::NotRequested,              L"non demandé (%1 : false)",                      L"not requested (%1: false)" },

	{ Text::TimeElapsed,               L"FIN, durée : %1 s",                             L"END, Time elapsed : %1 s" },
	{ Text::PressAnyKey,               L"<<< Appuyez sur une touche pour quitter >>>",   L"<<< Press any key to quit >>>" },
	{ Text::ConversionLogNotWritten,   L"conversion.json non écrit",                     L"conversion.json not written" },

	{ Text::Help,
	  L"\nusage : %1 [--config=fichier | --write-config] [--update-trust[=dossier]] [--collect | --full | --convert=dossier] "
	  L"[--language=fr|en] [--debug] [--dump] [--events] [--binary | --binary-all] [--output=sortie] [--loglevel=2]\n"
	  L"\t--help ou /? : cette aide\n"
	  L"\twac.yml, à côté de WAC.exe : la configuration de la collecte, appliquée d'abord ; une option donnée ci-dessous la surcharge (voir --write-config)\n"
	  L"\t--write-config : écrit le wac.yml de référence, commenté, à côté de WAC.exe, et s'arrête\n"
	  L"\t--config=fichier : lit la configuration dans un autre fichier que wac.yml\n"
	  L"\t--language=fr|en : langue de la console (fr par défaut) ; les fichiers JSON et les journaux restent en anglais\n"
	  L"\t--full : collecte et convertit ici, même si la configuration dit convert: false\n"
	  L"\t--collect : collecte seule, sur la machine examinée : observations en direct et extraction brute dans la consigne scellée ; "
	  L"rien n'est converti. Avec --events, les fichiers de ressources de chaque fournisseur d'événements sont pris ; avec --binary, "
	  L"chaque exécutable et catalogue de signatures du volume système\n"
	  L"\t--convert=dossier : conversion seule, sur un poste d'analyse, de la collecte faite par --collect dans ce dossier : le sceau "
	  L"et chaque empreinte sont vérifiés d'abord, puis les JSON sont écrits à côté de la consigne, avec conversion.json pour journal. "
	  L"Donner les mêmes --events et --binary qu'à la collecte\n"
	  L"\t--update-trust[=dossier] : sur le poste d'analyse, AVANT la collecte, et seul : télécharge les racines de confiance et les "
	  L"certificats révoqués de Microsoft, vérifie leurs signatures et les écrit dans le dossier (par défaut 'trust' à côté de WAC.exe), "
	  L"à emporter sur la machine examinée avec WAC.exe\n"
	  L"\t--debug : trace du lecteur NTFS brut sur stderr (résolution des chemins, blocs d'index, suites de clusters)\n"
	  L"\t--binary-all : comme --binary, mais chaque exécutable est prélevé, authentifié ou non ; sa signature est tout de même "
	  L"vérifiée et le verdict consigné au manifeste\n"
	  L"\t--threads=N : fils d'exécution qui analysent les exécutables de --collect --binary (par défaut : ceux du processeur moins un)\n"
	  L"\t--dump : ajoute la valeur hexadécimale brute des shellbags et des raccourcis dans les JSON\n"
	  L"\t--events : extrait et décode les journaux d'événements .evtx (environ 117 Mo de plus)\n"
	  L"\t--binary : empreintes (MD5, SHA-1, SHA-256) de chaque fichier cité par les artefacts, lu en brut ; exécutables, "
	  L"bibliothèques, pilotes et scripts sont aussi prélevés dans la consigne\n"
	  L"\t--output=[nom de dossier] : dossier des résultats, dans le répertoire courant ('output' par défaut)\n"
	  L"\t--loglevel=[0] : niveau de détail du journal %1.log, et son activation\n"
	  L"\n"
	  L"\t loglevel = 0 => pas de journal\n"
	  L"\t loglevel = 1 => une ligne par type d'artefact traité\n"
	  L"\t loglevel = 2 => une ligne par artefact traité\n"
	  L"\t loglevel = 3 => chaque fonction appelée (mise au point seulement)\n",
	  L"\nusage: %1 [--config=file | --write-config] [--update-trust[=folder]] [--collect | --full | --convert=folder] "
	  L"[--language=fr|en] [--debug] [--dump] [--events] [--binary | --binary-all] [--output=output] [--loglevel=2]\n"
	  L"\t--help or /? : show this help\n"
	  L"\twac.yml, next to WAC.exe : the collection's configuration, applied first; an option given below overrides it (see --write-config)\n"
	  L"\t--write-config : write the reference wac.yml, commented, next to WAC.exe, and stop\n"
	  L"\t--config=file : read the configuration from another file than wac.yml\n"
	  L"\t--language=fr|en : language of the console (fr by default); the JSON files and the logs stay in English\n"
	  L"\t--full : collect and convert here, although the configuration says convert: false\n"
	  L"\t--collect : collection only, on the examined machine: live snapshots and raw extraction into the sealed exhibit store; "
	  L"nothing is converted. With --events, the resource files of every event provider are taken; with --binary, every "
	  L"executable and signature catalog of the system volume\n"
	  L"\t--convert=folder : conversion only, on an analysis workstation, of the collection made with --collect in that folder: "
	  L"the seal and every fingerprint are checked first, then the JSON files are written next to the exhibit store, with "
	  L"conversion.json as the log. Give the same --events and --binary as the collection\n"
	  L"\t--update-trust[=folder] : on the analysis workstation, BEFORE the collection, and alone: downloads Microsoft's trusted "
	  L"roots and disallowed certificates, checks their signatures, and writes them into folder (by default 'trust' next to "
	  L"WAC.exe), to be carried to the examined machine with WAC.exe\n"
	  L"\t--debug : trace the raw NTFS parser on stderr (path resolution, index blocks, data runs)\n"
	  L"\t--binary-all : like --binary, but every executable is collected, authenticated or not; its signature is still checked "
	  L"and the verdict recorded in the manifest\n"
	  L"\t--threads=N : threads analysing the executables of --collect --binary (default: the processor's threads minus one)\n"
	  L"\t--dump : add the raw hexadecimal value of shellbags and shortcuts to the JSON files\n"
	  L"\t--events : extract and parse the .evtx event logs (adds ~117 MB to the collection)\n"
	  L"\t--binary : fingerprint (MD5, SHA-1, SHA-256) every file referenced in artefacts, read raw; executables, libraries, "
	  L"drivers and scripts are also collected into the exhibit store\n"
	  L"\t--output=[directory name] : directory of the results, in the current directory ('output' by default)\n"
	  L"\t--loglevel=[0] : level of detail of the log %1.log, and its activation\n"
	  L"\n"
	  L"\t loglevel = 0 => no logging\n"
	  L"\t loglevel = 1 => one line per artefact type treated\n"
	  L"\t loglevel = 2 => one line per artefact treated\n"
	  L"\t loglevel = 3 => every function called (debugging only)\n" },
	{ Text::UpdateTrustAlone,          L"--update-trust s'exécute seul, sur le poste d'analyse", L"--update-trust runs alone, on the analysis workstation" },
	{ Text::ConfigurationExists,       L"%1 existe déjà : non remplacé",                 L"%1 exists already: not overwritten" },
	{ Text::ReferenceConfigurationMissing, L"configuration de référence absente de WAC.exe", L"reference configuration missing from WAC.exe" },
	{ Text::FileNotWritten,            L"non écrit : %1",                                L"not written: %1" },
	{ Text::FileWritten,               L"%1 écrit",                                      L"%1 written" },
	{ Text::InvalidThreads,            L"Nombre de fils d'exécution invalide : %1",      L"Invalid number of threads %1" },
	{ Text::InvalidOutput,             L"Dossier de sortie vide : %1",                   L"Invalid length for output param %1" },
	{ Text::InvalidOutputCharacter,    L"Caractère interdit dans le dossier de sortie : %1", L"Invalid character for param %1" },
	{ Text::InvalidLogLevel,           L"Niveau de journal non numérique : %1",          L"Invalid numeric value for output param %1" },
	{ Text::InvalidArgument,           L"Argument invalide : %1",                        L"Invalid argument %1" },
	{ Text::ConvertExcludesCollect,    L"--convert exclut --collect et --output",        L"--convert excludes --collect and --output" },
	{ Text::InvalidLanguage,           L"Langue inconnue : %1 (fr ou en attendu)",       L"Unknown language: %1 (fr or en expected)" },

	{ Text::ConfigurationLine,         L"ligne %1 : %2",                                 L"line %1: %2" },
	{ Text::ConfigurationUnreadable,   L"fichier de configuration illisible",            L"configuration file unreadable" },
	{ Text::ConfigurationTooLarge,     L"fichier de configuration illisible ou de plus de 64 Kio", L"configuration file unreadable or larger than 64 KiB" },
	{ Text::ConfigurationSectionNotValue, L"%1 prend une valeur, pas une section",       L"%1 takes a value, not a section" },
	{ Text::ConfigurationBooleanExpected, L"%1 : \"%2\", true ou false attendu",         L"%1: \"%2\", true or false expected" },
	{ Text::ConfigurationNumberExpected, L"%1 : \"%2\", un nombre attendu",              L"%1: \"%2\", a number expected" },
	{ Text::ConfigurationOutOfRange,   L"%1 : %2, entre %3 et %4 attendu",               L"%1: %2, between %3 and %4 expected" },
	{ Text::ConfigurationArtefactsSection, L"artefacts est une section : une ligne par artefact", L"artefacts is a section: one line per artefact" },
	{ Text::ConfigurationUnknownArtefact, L"artefact inconnu \"%1\"",                    L"unknown artefact \"%1\"" },
	{ Text::ConfigurationBinaryValue,  L"binary : \"%1\", none, unverified ou all attendu", L"binary: \"%1\", none, unverified or all expected" },
	{ Text::ConfigurationOutputValue,  L"output : un nom de dossier, sans \\, / ni :",   L"output: a folder name, without \\, / or :" },
	{ Text::ConfigurationLanguageValue, L"language : \"%1\", fr ou en attendu",          L"language: \"%1\", fr or en expected" },
	{ Text::ConfigurationUnknownSetting, L"réglage inconnu \"%1\"",                      L"unknown setting \"%1\"" },

	{ Text::ProgressUnit,              L"élém.",                                         L"elem" },
	{ Text::ProgressKibibytes,         L"Kio",                                           L"KiB" },
	{ Text::ProgressLevel,             L"%1 (niveau %2)",                                L"%1 (level %2)" },
	{ Text::ProgressRepair,            L"Réparation de %1",                              L"Repair of %1" },
	{ Text::ProgressHive,              L"ruche(s)",                                      L"hive" },
	{ Text::TrustFolder,               L"Dossier du jeu de confiance",                   L"Trust set folder" },
	{ Text::TrustRoots,                L"Liste des racines de confiance (authroot.stl)", L"Trusted roots list (authroot.stl)" },
	{ Text::TrustDisallowed,           L"Liste des certificats révoqués (disallowedcert.stl)", L"Disallowed certificates list (disallowedcert.stl)" },
	{ Text::TrustAuthorities,          L"Autorités de certification (CCADB)",            L"Certificate authorities (CCADB)" },
	{ Text::TrustWriting,              L"Écriture du jeu de confiance",                  L"Writing the trust set" },
	{ Text::TrustRevocationWanted,     L" - Listes de révocation demandées par les collectes précédentes : %1",
	                                   L" - Revocation lists wanted by earlier collections : %1" },
	{ Text::TrustRootsMissing,         L"   %1 racine(s) non obtenue(s) : listées dans %2 ; une signature qui en dépend n'est pas vérifiée.",
	                                   L"   %1 root(s) not obtained: listed in %2; a signature chaining to one is not verified." },
	{ Text::TrustNoRoot,               L"aucun certificat racine obtenu",                L"no root certificate obtained" },
	{ Text::TrustRootCertificates,     L"Certificats racines",                           L"Root certificates" },
	{ Text::TrustCodeSigningAuthorities, L"Autorités de signature de code de Microsoft", L"Microsoft code signing authorities" },
	{ Text::TrustRevocationLists,      L"Listes de révocation (CRL)",                    L"Revocation lists (CRL)" },
	{ Text::TrustDriverBlocklist,      L"Liste de blocage des pilotes vulnérables de Microsoft", L"Microsoft vulnerable driver blocklist" },
	{ Text::TrustDownloading,          L" - %1 : %2 / %3",                               L" - %1 : %2 / %3" },
	{ Text::TrustObtained,             L" - %1 : %2 / %3, %4 obtenu(s)",                 L" - %1 : %2 / %3, %4 obtained" },
};

//! The table covers every text, each at its own rank.
constexpr bool complete() {
	if (sizeof(WORDINGS) / sizeof(WORDINGS[0]) != static_cast<size_t>(Text::Count)) return false;
	for (size_t i = 0; i < sizeof(WORDINGS) / sizeof(WORDINGS[0]); ++i)
		if (static_cast<size_t>(WORDINGS[i].id) != i || !WORDINGS[i].french || !WORDINGS[i].english
		    || !WORDINGS[i].french[0] || !WORDINGS[i].english[0]) return false;
	return true;
}
static_assert(complete(), "WORDINGS must hold every Text, in the enumeration's order, in both languages");

Language g_language = Language::French;   //!< French by default, as the operators are

} // namespace

void setLanguage(Language language) { g_language = language; }

Language currentLanguage() { return g_language; }

bool languageFromCode(const std::wstring& code, Language& language) {
	if (code == L"fr") { language = Language::French; return true; }
	if (code == L"en") { language = Language::English; return true; }
	return false;
}

std::wstring text(Text id, Language language, std::initializer_list<std::wstring> arguments) {
	const Wording& w = WORDINGS[static_cast<size_t>(id)];
	const std::wstring wording = language == Language::French ? w.french : w.english;
	/* %1 to %9, read left to right: a value that itself contains "%2" is
	   copied as it is, never replaced in turn. */
	std::wstring result;
	for (size_t i = 0; i < wording.size(); ++i) {
		const wchar_t next = i + 1 < wording.size() ? wording[i + 1] : L'\0';
		if (wording[i] == L'%' && next >= L'1' && next <= L'9') {
			const size_t rank = static_cast<size_t>(next - L'1');
			if (rank < arguments.size()) result += *(arguments.begin() + rank);
			++i;
		}
		else result += wording[i];
	}
	return result;
}

std::wstring text(Text id, std::initializer_list<std::wstring> arguments) {
	return text(id, g_language, arguments);
}
