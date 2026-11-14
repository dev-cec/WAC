/*! \file
 *  \brief The roles of an event's data: which value is the subject, the
 *         actor, the how — the Context of an event (backlog B-086, role
 *         table of B-078).
 *
 *  WHY A TABLE. An event carries its roles as Name/Value pairs whose meaning
 *  depends on its provider and identifier: in a 4688, SubjectUserSid is who
 *  started the process and NewProcessName the process; in a 4624,
 *  TargetUserSid is who logged on. Read by shape, they are confused (the
 *  finding of the B-078 study). Each line here is one identifier, its roles
 *  named; an identifier not in the table gets no Context — nothing guessed.
 *
 *  The account a provider writes the event as (EvtSystemUserID) is NOT the
 *  actor in general (S-1-5-18 for almost everything): it is used only where
 *  a line says so.
 */
#pragma once
#include <string>
#include <utility>
#include <vector>
#include "context.h"

/*! An event, as its roles are read from it. */
struct EventRoleInput {
	std::wstring provider;                                  //!< EvtSystemProviderName
	unsigned long long id = 0;                              //!< EvtSystemEventID
	std::vector<std::pair<std::wstring, std::wstring>> data;   //!< EvtEventData, Name/Value, in order
	std::wstring systemUserId;                              //!< EvtSystemUserID
	std::wstring evidence;                                  //!< the log file on the examined machine
};

/*! The Context of an event by the role table; Kind None (no Context written)
 *  for an identifier the table does not hold.
 *  @param event the event's provider, identifier and data
 *  @return its Context */
RecordContext eventContext(const EventRoleInput& event);
