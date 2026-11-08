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

/*! A product: one switch of wac.yml. */
struct TraceProduct {
	std::string key;                  //!< its key under its group
	const wchar_t* name;              //!< for the investigation log
	std::vector<TracePiece> pieces;   //!< what it writes
	/*! Taken when wac.yml says nothing of it. False for what holds the user's
	 *  data or memory rather than traces of a program (crash dumps, Office's
	 *  document cache): decision of 2026-11-08, wac.yml switches it on. */
	bool onByDefault = true;
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

/*! @param name a registry value's name
 *  @return whether it holds a password, by its name: its content is not emitted (application_registry.h) */
bool isPasswordValue(const std::wstring& name);

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
