/*! \file
 *  \brief WMI event subscriptions, read offline in the copied repository
 *         (wmi_persistence.json).
 *
 *  WHAT IT PROVES. An event filter (a WQL query: "every minute", "at logon",
 *  "when this process starts"), a consumer (a command line, a script in
 *  VBScript or JScript, a log entry) and the binding that ties them: WMI runs
 *  the consumer each time the filter fires, as SYSTEM, from wmiprvse.exe or
 *  scrcons.exe — a persistence invisible in the registry and in the startup
 *  folders, much used by intrusions.
 *
 *  WHAT IS READ. In EVERY namespace, not only root\subscription: every
 *  instance of a class deriving from __EventFilter, __EventConsumer (the
 *  standard consumers and any class an intruder defined),
 *  __FilterToConsumerBinding and __TimerInstruction (the timers a filter may
 *  wait for). Each with all its properties, as the repository holds them.
 *
 *  NOT EMITTED: the two dates at the start of an instance record. On the test
 *  VM, three objects created minutes apart carry the same first date, and the
 *  second equals their class's: neither is a creation date. The repository
 *  is in the exhibit store for whoever wants to study them.
 */
#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "cim_repository.h"
#include "tools.h"

/*! A subscription object: a filter, a consumer, a binding or a timer. */
struct WmiSubscriptionObject {
	std::wstring space;         //!< the namespace, "root\\subscription"
	std::wstring kind;          //!< "Filter", "Consumer", "Binding", "Timer"
	std::wstring className;     //!< "CommandLineEventConsumer", "__EventFilter"…
	CimValues values;
	Json toJson() const;        //!< @return the object as a JSON object
};

/*! The kind of a class, from its ancestors.
 *  @param chain the class and its ancestors, the root first
 *  @return "Filter", "Consumer", "Binding", "Timer", or empty for another class */
std::wstring wmiSubscriptionKind(const std::vector<const CimClass*>& chain);

//! WMI event subscriptions (wmi_persistence.json).
class WmiPersistence {
public:
	HRESULT getData();          //!< @return ERROR_SUCCESS, or why the repository cannot be read
	HRESULT toJson();           //!< @return the result of the write
	void clear();               //!< releases the objects
private:
	std::vector<WmiSubscriptionObject> objects_;
	size_t namespaces_ = 0;
};
