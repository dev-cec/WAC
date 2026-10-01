/*! \file
 *  \brief Registry artefacts of the third lot (B-031): the keys RECmd's Kroll
 *         batch reads and WAC did not.
 *
 *  Each is read in the copied hives and shares the structure of the second
 *  lot (registry_lot2.h): one struct per element with toJson(), one class with
 *  getData(), toJson(), clear().
 *
 *  WHAT THEY PROVE.
 *   - Installed programs (Uninstall): what was installed, by whom (machine or
 *     user), when, where — a remote access tool, a miner — and what was
 *     removed since leaves the key's last write.
 *   - Defender configuration: the exclusions (paths, extensions, processes,
 *     addresses) an intruder adds so that their tools are not scanned, and the
 *     values that switch protection off — set in Defender's own settings or
 *     by a policy.
 *   - Explorer's RecentDocs: the files each user opened, by extension, most
 *     recent first — the names survive the files and the shortcuts of Recent.
 *   - MountPoints2: the volumes and network shares each user's Explorer saw
 *     (a USB key, \\\\server\\share), the last time it did, and the commands an
 *     entry may carry (Shell\\AutoRun\\command: an old persistence).
 *   - Known networks (NetworkList): every network the machine joined — its
 *     name, its kind, its gateway's hardware address, when it was first and
 *     last connected: where the machine has been.
 *   - Program usage: what each user launched or used — FeatureUsage counts,
 *     JumplistData's last use, the Program Compatibility Assistant's store of
 *     programs run, compatibility layers, RADAR's diagnosed programs, and the
 *     taskbar's pinned items (Taskband, each a whole shortcut).
 *   - Devices: the USB and SCSI devices the machine enumerated (Enum\\USB,
 *     Enum\\SCSI) with their install, first install, last arrival and last
 *     removal dates; the portable devices (a phone, a camera); the volume
 *     labels Windows Search cached per drive letter; the disk, volume and
 *     portable-device interfaces of DeviceClasses.
 *   - Network shares: the folders the machine shares (LanmanServer\\Shares),
 *     a way in or out for data; the administrative ones (C$, ADMIN$) are not
 *     stored there.
 *   - Network configuration, read offline: each adapter (description, driver,
 *     a forced hardware address), its last IPv4 and IPv6 settings and DHCP
 *     lease — what the live state no longer shows once the machine is
 *     unplugged or the lease gone.
 *   - Event log configuration: each channel's state (enabled or not, size,
 *     retention, access) and the classic logs' — an intruder who disables a
 *     channel or shrinks a log leaves it there.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include <windows.h>
#include "registry_common.h"

// ------------------------------------------------------------ Installed programs

/*! One program of an Uninstall key: every value of its subkey. */
struct InstalledProgram {
	std::wstring scope;         //!< "Machine", "Machine (32-bit)", "User", or "MSI product" (Installer\\UserData)
	std::wstring sid;           //!< the user, for a per-user installation or an MSI product (S-1-5-18: machine-wide)
	std::wstring keyName;       //!< the subkey's name: a product code or a name
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the subkey
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, as stored (DisplayName, Publisher, InstallDate…)
	Json toJson() const;        //!< @return the program as a JSON object
};

//! Programs of the machine's and of each user's Uninstall keys (installed_programs.json).
class InstalledPrograms {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any program
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the programs
private:
	std::vector<InstalledProgram> programs_;
};

// ------------------------------------------------------------ Defender configuration

/*! One Defender exclusion: a path, an extension, a process or an address
 *  Defender does not scan. */
struct DefenderExclusion {
	std::wstring source;        //!< "Settings" (Defender's key) or "Policy" (Policies\\Microsoft\\Windows Defender)
	std::wstring kind;          //!< the subkey: Paths, Extensions, Processes, IpAddresses, TemporaryPaths
	std::wstring value;         //!< what is excluded (the value's name)
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the kind's key: the latest exclusion of that kind
	Json toJson() const;        //!< @return the exclusion as a JSON object
};

/*! The values of one Defender settings key. */
struct DefenderSettings {
	std::wstring source;        //!< "Settings" or "Policy"
	std::wstring key;           //!< the key, under SOFTWARE ("Microsoft\\Windows Defender\\Real-Time Protection")
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the key
	std::vector<std::pair<std::wstring, Json>> values; //!< every value, as stored (DisableRealtimeMonitoring, TamperProtection…)
	Json toJson() const;        //!< @return the key as a JSON object
};

//! Defender's exclusions and protection settings (defender_configuration.json).
class DefenderConfiguration {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SOFTWARE is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<DefenderExclusion> exclusions_;
	std::vector<DefenderSettings> settings_;
};

// ------------------------------------------------------------ Explorer RecentDocs

/*! One file of a user's RecentDocs list. */
struct ExplorerRecentDoc {
	std::wstring sid;
	std::wstring extension;     //!< the subkey (".docx", "Folder"); empty for the list of every extension
	unsigned mruPosition = 0;   //!< position in its list, 0 for the most recent (MRUListEx)
	std::wstring name;          //!< the file's name, as Explorer recorded it
	Json shortcut = Json::obj();//!< the shell item that follows: the shortcut created in Recent
	FILETIME keyLastWriteUtc = { 0 };   //!< the list key's last write: when the file at position 0 was opened
	Json toJson() const;        //!< @return the entry as a JSON object
};

//! RecentDocs of every user (explorer_recent_docs.json).
class ExplorerRecentDocs {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any entry
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<ExplorerRecentDoc> entries_;
};

// ------------------------------------------------------------ MountPoints2

/*! One entry of a user's MountPoints2: a volume or a share. */
struct MountPoint {
	std::wstring sid;
	std::wstring name;          //!< the key: "{GUID}", "##server#share", or a CPC\\Volume entry
	std::wstring kind;          //!< "Volume" or "NetworkShare"; empty for anything else
	std::wstring share;         //!< for a share, "\\\\server\\share"
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the entry: the last time Explorer saw it
	std::vector<std::pair<std::wstring, Json>> values; //!< the entry's values (_LabelFromReg, BaseClass…)
	NameValues subkeys;         //!< every subkey below it and its default value (Shell\\AutoRun\\command…)
	Json toJson() const;        //!< @return the entry as a JSON object
};

//! MountPoints2 of every user (mount_points.json).
class MountPoints {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any entry
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the entries
private:
	std::vector<MountPoint> entries_;
};

// ------------------------------------------------------------ Known networks

/*! One network the machine joined: a NetworkList profile, with what its
 *  signature adds (gateway, DNS suffix). */
struct KnownNetwork {
	std::wstring profileGuid;   //!< the profile's key
	FILETIME profileLastWriteUtc = { 0 };   //!< last write of the profile's key
	std::vector<std::pair<std::wstring, Json>> values; //!< the profile's values but its dates (ProfileName, Category, NameType…)
	FILETIME createdUtc = { 0 };        //!< DateCreated, a local SYSTEMTIME, converted
	FILETIME lastConnectedUtc = { 0 };  //!< DateLastConnected, idem
	struct Signature {
		std::wstring kind;      //!< "Managed" or "Unmanaged"
		std::vector<std::pair<std::wstring, Json>> values; //!< Description, DnsSuffix, FirstNetwork, Source…
		std::wstring gatewayMac;//!< DefaultGatewayMac, as aa-bb-cc-dd-ee-ff
	};
	std::vector<Signature> signatures; //!< the signatures pointing to this profile
	Json toJson() const;        //!< @return the network as a JSON object
};

//! Networks of NetworkList (known_networks.json).
class KnownNetworks {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SOFTWARE is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the networks
private:
	std::vector<KnownNetwork> networks_;
};

// ------------------------------------------------------------ Program usage

/*! One trace of a program's use, from one of the sources of ProgramUsage. */
struct ProgramUsage {
	std::wstring source;        //!< the key it comes from (FeatureUsage\\AppLaunch, JumplistData…)
	std::wstring sid;           //!< the user; empty for a machine-wide source
	std::wstring name;          //!< the program (path, application ID or name)
	std::vector<std::pair<std::wstring, Json>> values; //!< what the source says of it (Count, LastUsed, Layers…)
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the source's key
	Json toJson() const;        //!< @return the trace as a JSON object
};

//! Program usage of the machine and of each user (program_usage.json).
class ProgramUsages {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any trace
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the traces
private:
	std::vector<ProgramUsage> usages_;
};

// ------------------------------------------------------------ Devices

/*! One device or device trace, from one of the sources of Devices. */
struct DeviceTrace {
	std::wstring source;        //!< Enum\\USB, Enum\\SCSI, WindowsPortableDevices, VolumeInfoCache, DeviceClasses
	std::wstring name;          //!< the device (device\\instance), the drive letter, the interface
	std::vector<std::pair<std::wstring, Json>> values; //!< its values, as stored (FriendlyName, Mfg, VolumeLabel…)
	FILETIME installUtc = { 0 };        //!< DEVPKEY_Device_InstallDate (property 0064)
	FILETIME firstInstallUtc = { 0 };   //!< DEVPKEY_Device_FirstInstallDate (0065)
	FILETIME lastArrivalUtc = { 0 };    //!< DEVPKEY_Device_LastArrivalDate (0066)
	FILETIME lastRemovalUtc = { 0 };    //!< DEVPKEY_Device_LastRemovalDate (0067)
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of its key
	Json toJson() const;        //!< @return the trace as a JSON object
};

//! Devices the machine has known (devices.json).
class Devices {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SYSTEM is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the traces
private:
	std::vector<DeviceTrace> devices_;
};

// ------------------------------------------------------------ Network shares

/*! One folder the machine shares. */
struct NetworkShare {
	std::wstring name;          //!< the share's name
	NameValues fields;          //!< its "Name=Value" lines, as stored (Path, Remark, Permissions, Type, MaxUses…)
	Json securityDescriptor = Json::obj(); //!< Shares\\Security\\<name>, decoded: who may use it
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of the Shares key
	Json toJson() const;        //!< @return the share as a JSON object
};

//! The machine's shares (network_shares.json).
class NetworkShares {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SYSTEM is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the shares
private:
	std::vector<NetworkShare> shares_;
};

// ------------------------------------------------------------ Network configuration

/*! One network adapter and its last configuration. */
struct NetworkAdapterConfiguration {
	std::wstring guid;          //!< the interface's GUID (NetCfgInstanceId)
	std::vector<std::pair<std::wstring, Json>> adapter; //!< its Control\\Class values (DriverDesc, ProviderName, NetworkAddress…)
	std::vector<std::pair<std::wstring, Json>> ipv4;    //!< Tcpip\\Parameters\\Interfaces\\{guid}, lease times as dates
	std::vector<std::pair<std::wstring, Json>> ipv6;    //!< Tcpip6\\Parameters\\Interfaces\\{guid}
	std::vector<std::pair<std::wstring, Json>> kernel;  //!< NetworkSetup2\\Interfaces\\{guid}\\Kernel (PermanentAddress…)
	FILETIME ipv4LastWriteUtc = { 0 };  //!< last write of its IPv4 key: its last configuration
	Json toJson() const;        //!< @return the adapter as a JSON object
};

//! The machine's network configuration, read offline (network_configuration.json).
class NetworkConfiguration {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why SYSTEM is missing
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases what was read
private:
	std::vector<std::pair<std::wstring, Json>> global_;  //!< Tcpip\\Parameters (Hostname, Domain, SearchList…)
	std::vector<NetworkAdapterConfiguration> adapters_;
};

// ------------------------------------------------------------ Event log configuration

/*! The configuration of one event log channel. */
struct EventLogChannel {
	std::wstring source;        //!< "WINEVT\\Channels" (SOFTWARE) or "Services\\EventLog" (SYSTEM, the classic logs)
	std::wstring name;          //!< the channel ("Microsoft-Windows-PowerShell/Operational", "Security")
	std::vector<std::pair<std::wstring, Json>> values; //!< its values, as stored (Enabled, MaxSize, Retention, ChannelAccess, File…)
	FILETIME keyLastWriteUtc = { 0 };   //!< last write of its key: its last configuration change
	Json toJson() const;        //!< @return the channel as a JSON object
};

//! The configuration of every event log (event_log_configuration.json).
class EventLogConfiguration {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, even without any channel
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the channels
private:
	std::vector<EventLogChannel> channels_;
};
