/*! \file
 *  \brief The texts WAC shows the operator, in French and in English.
 *
 *  WHAT IS TRANSLATED. The console only: steps, headings, help, refusals of the
 *  command line and of wac.yml. The JSON files, WAC.log and the investigation
 *  log stay in English whatever the language: they are evidence read by tools,
 *  and one collection must give the same files whoever ran it.
 *
 *  WHY AN ENUMERATION. Every text is named by a value of `Text`, and the table
 *  of translations.cpp holds, for each one and in the same order, its French
 *  and its English wording: a text added without its translation, or a table
 *  out of order, does not compile. Looking the text up by its English wording
 *  would fall back on English without a word.
 *
 *  The language is French by default; wac.yml (`language:`) or the command
 *  line (--language=) changes it.
 */
#pragma once
#include <initializer_list>
#include <string>

//! The language of the console.
enum class Language { French, English };

//! The texts of the console (see translations.cpp for their wording).
enum class Text : unsigned {
	// Headings of the phases
	HeadingPrerequisites, HeadingCheckingCollection, HeadingLiveState, HeadingRawExtraction,
	HeadingForConversion, HeadingRegistry, HeadingFiles, HeadingEventLogs, HeadingExhibitStore,
	HeadingInvestigationLog,
	// Steps: prerequisites, collection medium, conversion
	StepAdministratorRights, StepCollectionMedium, StepSealAndFingerprints,
	StepRebuildWorkingCopy, StepRepairWorkingHives,
	// Steps: live state
	StepRunningMachine, StepSessions, StepProcesses, StepNetworkState, StepServiceStates, StepSystemClock,
	// Steps: raw extraction
	StepSystemHives, StepUserHives, StepFileArtefacts, StepNtfsMetadata, StepFatMetadata, StepShadowCopies, StepTrustSet,
	StepCopyBinaries, StepSealExhibitStore, StepEventResources, StepAllExecutables,
	StepOpenSystemHive, StepOpenSoftwareHive, StepUserProfiles,
	// Steps: registry
	StepWriteLiveState, StepOpenControlSet, StepSuspectTimeZone,
	StepSuspectCodePage, StepAccountNames, StepUsbstor, StepMountedDevices, StepBam, StepMuiCache,
	StepAmcache, StepUserAssist, StepRunKeys, StepShimcache,
	StepShellbags, StepMru, StepMruApps, StepSystemInformation, StepServices, StepUsers, StepLocalGroups,
	// Steps: files and event logs
	StepScheduledTasks, StepRecentDocuments, StepPrefetch, StepReadMft, StepWriteMft, StepUsnJournal,
	StepJumpListsAutomatic, StepJumpListsCustom, StepEvents,
	StepPowerShellHistory, StepPowerShellProfiles, StepDeletedFiles, StepSetupApi, StepRecycleBin, StepHosts, StepErrorReports, StepDefenderLogs,
	StepDefenderDetections, StepDefenderQuarantine,
	StepStartupFolders, StepZoneIdentifiers, StepSecurityHive, StepPersistence,
	StepOfficeTrustRecords, StepTypedPaths, StepWordWheelQueries, StepRootCertificates, StepInternetSettingsSet, StepFirewall, StepWmiPersistence, StepSrum, StepBitsJobs, StepFatVolumes, StepInstalledPrograms, StepDefenderConfiguration, StepExplorerRecentDocs, StepMountPoints, StepKnownNetworks, StepProgramUsages, StepDevices, StepNetworkShares, StepNetworkConfiguration, StepEventLogConfiguration, StepShortcuts, StepSecurityDescriptors, StepNtfsVolumes, StepDpapiMasterKeys, StepUserShellFolders, StepWebClient, StepActivitiesCache, StepSearchIndex, StepRdpClient, StepRdpServer, StepThumbcache, StepEmails, StepSysmon, StepShadowCopyListing, StepShadowCopyContent,
	// Steps: investigation log
	StepWriteConversionLog, StepWriteInvestigationLog,
	// Artefacts switched off by wac.yml (their name, then the message)
	ArtefactProcesses, ArtefactSessions, ArtefactNetwork, ArtefactUsbDevices, ArtefactMountedDevices,
	ArtefactBam, ArtefactMuiCache, ArtefactAmcacheApplications, ArtefactAmcacheApplicationFiles, ArtefactAmcacheInventory,
	ArtefactUserAssist, ArtefactRunKeys, ArtefactShimcache, ArtefactShellbags, ArtefactMru,
	ArtefactMruApps, ArtefactServices, ArtefactUsers, ArtefactLocalGroups, ArtefactScheduledTasks,
	ArtefactRecentDocuments, ArtefactPrefetch, ArtefactMft, ArtefactUsnJournal,
	ArtefactJumpListsAutomatic, ArtefactJumpListsCustom,
	ArtefactPowerShellHistory, ArtefactPowerShellProfiles, ArtefactDeletedFiles, ArtefactSetupApi, ArtefactRecycleBin, ArtefactHosts, ArtefactErrorReports,
	ArtefactDefenderLogs, ArtefactDefenderDetections, ArtefactDefenderQuarantine, ArtefactStartupFolders, ArtefactZoneIdentifiers, ArtefactSecurityHive,
	ArtefactPersistence, ArtefactOfficeTrustRecords, ArtefactTypedPaths, ArtefactWordWheelQueries, ArtefactRootCertificates, ArtefactInternetSettingsSet, ArtefactFirewall, ArtefactWmiPersistence, ArtefactSrum, ArtefactBitsJobs, ArtefactFatVolumes, ArtefactInstalledPrograms, ArtefactDefenderConfiguration, ArtefactExplorerRecentDocs, ArtefactMountPoints, ArtefactKnownNetworks, ArtefactProgramUsages, ArtefactDevices, ArtefactNetworkShares, ArtefactNetworkConfiguration, ArtefactEventLogConfiguration, ArtefactShortcuts, ArtefactSecurityDescriptors, ArtefactNtfsVolumes, ArtefactDpapiMasterKeys, ArtefactUserShellFolders, ArtefactWebClient, ArtefactActivitiesCache, ArtefactSearchIndex, ArtefactRdpClient, ArtefactRdpServer, ArtefactThumbcache, ArtefactEmails, ArtefactSysmon, ArtefactShadowCopies,
	ArtefactOperatingSystem, ArtefactEvents,
	NotRequested, NotNeeded, AbsentFromVersion, ExpectedButMissing, UndecodedOnVersion, OlderThanValidated,
	StepExaminedVersion, ExaminedVersionUnknown, ExaminedVersionUnread,
	// End of the run
	TimeElapsed, PressAnyKey, ConversionLogNotWritten,
	// Command line and configuration file
	Help, UpdateTrustAlone, ConfigurationExists, ReferenceConfigurationMissing, FileNotWritten,
	FileWritten, InvalidThreads, InvalidOutput, InvalidOutputCharacter, InvalidLogLevel,
	InvalidArgument, ConvertExcludesCollect, InvalidLanguage,
	ConfigurationLine, ConfigurationUnreadable, ConfigurationTooLarge, ConfigurationSectionNotValue,
	ConfigurationBooleanExpected, ConfigurationNumberExpected, ConfigurationOutOfRange,
	ConfigurationArtefactsSection, ConfigurationUnknownArtefact, ConfigurationBinaryValue,
	ConfigurationOutputValue, ConfigurationLanguageValue, ConfigurationUnknownSetting,
	ConfigurationVersionMissing, ConfigurationVersionMismatch, ConfigurationListNotValue,
	ConfigurationListExpected, ConfigurationVolumeFolder,
	// Progress and trust set update (analysis workstation)
	ProgressUnit, ProgressKibibytes, ProgressLevel, ProgressRepair, ProgressHive, TrustFolder, TrustRoots, TrustDisallowed, TrustAuthorities, TrustWriting,
	TrustRevocationWanted, TrustRootsMissing, TrustNoRoot, TrustRootCertificates,
	TrustCodeSigningAuthorities, TrustRevocationLists, TrustDriverBlocklist, TrustDownloading,
	TrustObtained,
	Count   //!< number of texts, not a text
};

/*! Sets the language of the console, for every text shown from then on.
 *  @param language the language */
void setLanguage(Language language);

//! @return the language of the console
Language currentLanguage();

/*! Reads a language code of wac.yml or of --language=.
 *  @param code "fr" or "en"
 *  @param language receives the language
 *  @return false if the code is neither */
bool languageFromCode(const std::wstring& code, Language& language);

/*! A text in the console's language, its %1 to %9 replaced by `arguments`.
 *  @param id the text
 *  @param arguments the values of %1, %2… in that order
 *  @return the wording */
std::wstring text(Text id, std::initializer_list<std::wstring> arguments = {});

/*! A text in a given language — the English wording of an artefact's name,
 *  for instance, that goes into its JSON file whatever the console's.
 *  @param id the text
 *  @param language the language
 *  @param arguments the values of %1, %2… in that order
 *  @return the wording */
std::wstring text(Text id, Language language, std::initializer_list<std::wstring> arguments = {});
