/*! \file
 *  \brief What remote and archive tools keep in each user's hive
 *         (application_registry.json).
 *
 *  WHAT IT PROVES. PuTTY's and WinSCP's sessions and known host keys name the
 *  machines a user reached from here: lateral movement. WinRAR's and 7-Zip's
 *  histories name the archives made or opened: data gathered before leaving.
 *
 *  WHAT IS LEFT OUT. A value whose name holds "password": WinSCP keeps a session's
 *  password there, merely obfuscated. WAC says that the session has one, not what.
 *
 *  OUTPUT. One object per key: Sid, Product, Key, KeyLastWrite, Values.
 */
#pragma once

#include "tools.h"
#include <string>
#include <vector>

/*! A product and the keys it writes under a user's hive. */
struct RegistryProduct {
	const char* key;                    //!< its switch under application_registry
	const wchar_t* name;                //!< its name in the JSON
	std::vector<const wchar_t*> paths;  //!< its keys, walked with their subkeys
};

//! @return every product, in the order of wac.yml
const std::vector<RegistryProduct>& registryProducts();

//! The tools' keys in each user's hive (application_registry.json).
class ApplicationRegistry {
public:
	HRESULT getData();
	HRESULT toJson();
	void clear();
private:
	Json keys_ = Json::arr();
};
