/*! \file
 *  \brief THE table of the applications' traces copied raw: remote administration,
 *         antivirus, messaging, cloud storage, file transfer, VPN, virtualisation,
 *         server applications, and the system's and servers' own logs.
 *
 *  WHY A TABLE. Each is a few folders a known product writes, of formats WAC does
 *  not convert: a line here, rather than a collector each. wac.yml has one section
 *  per group (one artefact of the catalogue) and, under it, one switch per product.
 *
 *  THE SOURCE. KAPE's targets give most paths, an independent list of where these
 *  products write. A product is rarely installed on a test machine: a witness proves
 *  that the path written here is taken, not that every version of the product writes
 *  there. The manuals say so.
 *
 *  WHAT IS LEFT OUT, ON PURPOSE. SSH private keys, which KAPE takes: clear secrets
 *  opening other machines, and the public half and the logs tell the story. Files a
 *  user keeps in a synchronised folder: the metadata says what was synchronised.
 *  Virtual disks and memory: the configuration and logs lead to them.
 *
 *  Portable C++, without windows.h: tested natively (application_traces_test).
 */
#pragma once

#include <set>
#include <string>
#include <vector>
#include "wildcard.h"

/*! A folder of a product. */
struct TracePiece {
	std::wstring folder;              //!< from the system volume's root, or from each profile (PROFILE_MARK); a component may hold `*`
	std::vector<std::wstring> filter; //!< ".ext", a whole name or a name with `*`; empty for every file
	unsigned depth;                   //!< levels below the folder: 0 for its own files
};

/*! How a product lays out the start of its log lines, where WAC reads their
 *  time (leadingTime): what is particular to it only — read so for any other
 *  product, the same text would be another date, or none. */
struct LineLayout {
	/*! Its dates month first, "10/31/2026 01:04:23:981": a date written so is
	 *  two dates for any other product. */
	bool monthFirst = false;
	/*! The writing process's identifier before the time, "4464 2026-11-10
	 *  21:59:57.158 Invalid user …": Win32-OpenSSH's file log (SyslogFacility
	 *  LOCAL0), measured 2026-11-10. Optional: a line starting with its time
	 *  is read as well. */
	bool processIdFirst = false;
	/*! A level word before the time, "   info 2026-11-11 19:23:27.390   hub …":
	 *  AnyDesk's ad.trace, measured 2026-11-11. Optional as processIdFirst. */
	bool levelFirst = false;
};

/*! A product: one switch of wac.yml. */
struct TraceProduct {
	std::string key;                  //!< its key under its group
	const wchar_t* name;              //!< for the investigation log
	std::vector<TracePiece> pieces;   //!< what it writes
	/*! Taken when wac.yml says nothing of it. False for what holds the user's
	 *  data or memory rather than traces of a program (crash dumps, Office's
	 *  document cache): decision of 2026-11-08, wac.yml switches it on. */
	bool onByDefault = true;
	LineLayout layout = {};           //!< how its log lines start

	/*! Its logs write UTC without saying so: measured by the harness, which
	 *  compares a log's last line with the moment the file was last written. */
	bool writesUtc = false;
};

/*! A group: one artefact, one section of wac.yml. */
struct TraceGroup {
	std::string key;                  //!< its key under `artefacts:`
	std::vector<TraceProduct> products; //!< its products, in the order of wac.yml
};

extern const wchar_t* const PROFILE_MARK;  //!< a folder starting so is looked for in each profile

//! Every group, in the order of wac.yml.
const std::vector<TraceGroup>& applicationTraces();

//! @return the group of that key, nullptr if there is none
const TraceGroup* traceGroup(const std::string& key);

/*! Whether a value holds a secret, by its name: its content is not emitted —
 *  a registry value (application_registry.h), a key or element of a product's
 *  configuration file (application_trace_files.h). A name holding "password",
 *  "passwd", "pwd" or "secret", or the whole name "pass" (FileZilla keeps a
 *  site's password in <Pass>), case ignored.
 *  @param name the value's name
 *  @return whether its content is left out */
bool isPasswordValue(const std::wstring& name);

/*! The group and product of the table a file of the examined machine belongs to. */
struct TraceOwner {
	const TraceGroup* group = nullptr;      //!< null if no product takes the file
	const TraceProduct* product = nullptr;  //!< its product
};

/*! The product that takes a file, as the collection took it: one of its
 *  folders (its `*` components matching), the file at most `depth` levels below,
 *  its name kept by the filter. A PROFILE_MARK folder stands for that folder in
 *  any profile — \Users\<name>, \Documents and Settings\<name>, the system's and
 *  the services' profiles. When two lines take the same file, the first of the
 *  table wins: the order of the table decides, the same at every conversion.
 *  @param sourcePath the file's path on the examined machine ("C:\…")
 *  @return its group and product, or nulls */
TraceOwner traceOwnerOf(const std::wstring& sourcePath);

/*! The switches wac.yml gives the products of application_traces.h and of
 *  application_registry: "group" or "group.product" switched off, and
 *  "group.product" switched on. */
struct ProductSwitches {
	std::set<std::string> off;  //!< groups and products switched off
	std::set<std::string> on;   //!< products switched on
};

/*! Whether a product is taken: its group is not switched off, nor itself, and
 *  it is on by default or switched on.
 *  @param switches what wac.yml says
 *  @param group,product their keys
 *  @param onByDefault the product's default (TraceProduct::onByDefault)
 *  @return whether it is taken */
bool traceProductWanted(const ProductSwitches& switches, const std::string& group, const std::string& product, bool onByDefault = true);
