/*! \file
 *  \brief Registry persistence beyond the Run keys: what makes Windows start a
 *         program, or load a DLL, without the user asking.
 *
 *  WHAT THE ARTEFACT PROVES. Each mechanism below starts code chosen by
 *  whoever wrote the value — an installer, or an intruder who wants to
 *  survive a reboot where the Run keys would be looked at first:
 *   - Image File Execution Options: `Debugger` runs another program instead
 *     of the one asked for; `GlobalFlag` with SilentProcessExit's
 *     `MonitorProcess` runs one when a process exits;
 *   - AppInit_DLLs, AppCertDlls: a DLL loaded into (almost) every process;
 *   - Winlogon: `Shell`, `Userinit`, `Taskman`, `AppSetup`, `Notify` packages —
 *     started at logon, with the session;
 *   - LSA packages (authentication, security, notification): DLLs loaded into
 *     LSASS, which see passwords;
 *   - print monitors: DLLs loaded by the spooler, as SYSTEM;
 *   - Session Manager `BootExecute`: programs run before Windows starts;
 *   - Active Setup `StubPath`: a command run once per user at logon;
 *   - NetSh helpers: DLLs loaded by netsh.exe;
 *   - COM hijacking: a CLSID of the user's classes (UsrClass.dat) whose
 *     server replaces the machine's for that user.
 *
 *  WHAT IS EMITTED. Every value found, default ones included: telling the
 *  default from the added is the analysis's work (WAE), and a list trimmed
 *  here would hide what it did not expect. Each with its key's last write,
 *  which bounds when it was written, and, with --binary, the fingerprints of
 *  the file it names.
 *
 *  NOT HERE YET: BITS jobs (qmgr.db, an ESE database — see B-009).
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "binaires.h"

/*! One persistence value. */
struct PersistenceEntry {
	std::wstring mechanism;            //!< what the value does (IFEO Debugger, AppInit_DLLs…)
	std::wstring hive;                 //!< SOFTWARE, SYSTEM, NTUSER.DAT or UsrClass.dat
	std::wstring sid;                  //!< the user of a user hive; empty for the machine's
	std::wstring key;                  //!< the key, from the hive's root
	std::wstring name;                 //!< the value's name; "(default)" for the unnamed one
	std::wstring type;                 //!< REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD
	std::vector<std::wstring> values;  //!< the value; several for REG_MULTI_SZ
	FILETIME keyLastWriteUtc = { 0 };  //!< last write of the key, UTC
	BinaryFingerprint fingerprint;     //!< the file the value names, with --binary
	//! @return the entry as a JSON object
	Json toJson() const;
};

/*! The persistence values of every hive (persistence.json). */
class Persistence {
public:
	/*! Reads the machine's hives (SOFTWARE, SYSTEM) and each user's.
	 *  @return ERROR_SUCCESS, even when a hive or a key is absent */
	HRESULT getData();
	/*! Writes persistence.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the entries read.
	void clear();
private:
	std::vector<PersistenceEntry> entries_;   //!< every value found
};
