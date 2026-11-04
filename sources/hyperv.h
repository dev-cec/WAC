/*! \file
 *  \brief The Hyper-V role: the virtual machines a host declares.
 *
 *  WHAT THE ARTEFACT PROVES. A virtual machine on a host is a machine out of the
 *  sight of the host's own defences (ATT&CK T1564.006): its name, and above all
 *  its disks, wherever they are. A disk image is not taken: its paths lead to it.
 *
 *  WHERE, measured on Server 2022: `ProgramData\Microsoft\Windows\Hyper-V`:
 *    - `data.vmcx`: the host's list, the configuration of each machine wherever it is;
 *    - `Virtual Machines\<id>.vmcx`, `Snapshots\<id>.vmcx`: each configuration.
 *  The .vmrs and .vmgs beside them hold the state of a running machine, its memory
 *  among it: not taken. Server 2012 R2 and before write `.xml` in the same folders:
 *  copied raw, not converted, not measured.
 *
 *  THE .vmcx FORMAT IS NOT DOCUMENTED. What was measured: a text key is one byte of
 *  length (its zero included), the key, a zero, then for a text value 4 bytes of
 *  length and that many bytes of UTF-16, without final zero; the whole tree is held
 *  twice, in two log-like copies. Its links between nodes are not reconstructed: WAC
 *  gives the key and text value pairs as found, each once. So it cannot say which `name`
 *  is the machine's, among those of its devices: the reader of the JSON does. Numbers
 *  (memory, processors) are not read.
 */
#pragma once

#include <string>
#include <utility>
#include <vector>
#include "tools.h"

/*! The key and text value pairs of a .vmcx, each once, in the file's order.
 *  @param bytes the file
 *  @param size its size
 *  @return the pairs */
std::vector<std::pair<std::wstring, std::wstring>> readVmcxStrings(const uint8_t* bytes, size_t size);

/*! The artefact: hyperv_machines.json, one object per configuration file. */
class HyperV {
public:
	HRESULT getData();  //!< @return ERROR_SUCCESS, even without the role
	HRESULT toJson();   //!< @return the result of the write
	void clear();       //!< releases what was read
private:
	Json machines_ = Json::arr();
};

//! The folder of the role's files, on the examined machine.
std::wstring hyperVFolder();
