/*! \file
 *  \brief Shortcuts outside the Recent folder: Start menu, desktop, Quick Launch and pinned task bar.
 *
 *  WHAT THE ARTEFACT PROVES. Recent (recentdocs.json) holds the shortcuts
 *  Windows makes when a document is opened; these are the ones a person or an
 *  installer PUT somewhere to be clicked: the Start menu of all users and of
 *  each profile, the desktop of each profile and the public one, Quick Launch
 *  and what is pinned to the task bar. An installed program leaves its
 *  shortcut there, and it outlives the program's removal; an intruder plants
 *  one there with a command line in its arguments, or retargets an existing
 *  one at their own binary (the icon stays the same). The target, its arguments,
 *  the volume and machine it was on are decoded as in recentdocs.json.
 *
 *  WHAT IS LEFT OUT. The Start menu's Startup folder: startup_folders.json
 *  takes it whole, every file and not only shortcuts. Taken here too, its
 *  shortcuts would be extracted and listed twice.
 *
 *  These folders were the first gap B-015 found between WAC and KAPE's
 *  KapeTriage target (backlog B-032).
 */
#pragma once

#include <memory>
#include <string>
#include <vector>
#include <windows.h>
#include "tools.h"
#include "recent_docs.h"

/*! A folder of shortcuts, collected raw then converted. */
struct ShortcutFolder {
	const wchar_t* relative;   //!< relative to the profile, or to the system volume for the folders of all users
	bool perProfile;           //!< true: one per profile; false: one for the machine
	bool recursive;            //!< true: the whole tree (Start menu, Quick Launch); false: the folder alone (desktop)
	const wchar_t* location;   //!< its name in the JSON: StartMenu, Desktop, QuickLaunch
};

//! The folders of shortcuts, of the machine and of each profile.
extern const ShortcutFolder SHORTCUT_FOLDERS[];
//! Number of entries of SHORTCUT_FOLDERS.
extern const size_t SHORTCUT_FOLDER_COUNT;
/*! Depth of the Start menu and Quick Launch trees: Programs\\<vendor>\\<product>
 *  is three levels, User Pinned\\TaskBar\\ImplicitAppShortcuts\\<id> four. A
 *  bound, in case a corrupt index loops. */
constexpr unsigned SHORTCUT_TREE_DEPTH = 6;

/*! One folder of shortcuts on the examined machine: an entry of
 *  SHORTCUT_FOLDERS for the machine or for one profile, or a profile's
 *  desktop redirected elsewhere (User Shell Folders). */
struct ShortcutLocation {
	const ShortcutFolder* folder;   //!< its kind: recursive or not, location name
	std::wstring absolute;          //!< its absolute path, letter included
	std::wstring sid;               //!< the profile's SID; empty for the folders of all users
	std::wstring startup;           //!< the Startup folder inside it, absolute; empty for none
};

/*! Every folder of shortcuts, for the collection and for the conversion alike.
 *  @return the folders of the machine, then each profile's, a redirected
 *          desktop after its profile's default one */
std::vector<ShortcutLocation> shortcutLocations();

/*! One shortcut. */
struct ShortcutItem {
	std::wstring location;     //!< StartMenu, Desktop, QuickLaunch or TaskBar (pinned)
	std::wstring sid;          //!< SID of the profile; empty for the folders of all users
	std::unique_ptr<RecentDoc> shortcut;   //!< the shortcut decoded
	//! @return the shortcut as a JSON object
	Json toJson() const;
};

/*! The shortcuts outside Recent (shortcuts.json). */
class Shortcuts {
public:
	/*! Reads the .lnk and .url files extracted from every folder of SHORTCUT_FOLDERS.
	 *  @return ERROR_SUCCESS, even without any file */
	HRESULT getData();
	/*! Writes shortcuts.json.
	 *  @return the result of the write */
	HRESULT toJson();
	//! Releases the shortcuts read.
	void clear();
private:
	std::vector<ShortcutItem> items_;   //!< one per shortcut
};
