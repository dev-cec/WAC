/*! \file
 *  \brief The equivalents WAC32.exe uses where Windows XP lacks a function:
 *         declared here for their test (xp_imports_test.cpp), which runs them
 *         against the system's own on a Windows that has both.
 *
 *  See xp_imports.cpp for why and how. Nothing here exists in the 64-bit WAC.
 */
#pragma once

#if defined(_WIN32) && !defined(_WIN64)

#include <cstddef>

/*! InitializeConditionVariable, without Windows' own.
 *  @param variable the CONDITION_VARIABLE, a pointer-sized slot */
void xpInitializeConditionVariable(void** variable);

/*! SleepConditionVariableCS: leaves the critical section, waits to be woken
 *  or for the delay, enters it again. Like Windows', it may return without a
 *  wake-up having been meant for this thread: the caller tests its condition.
 *  @param variable the condition variable
 *  @param criticalSection the CRITICAL_SECTION, held by the caller
 *  @param milliseconds the longest wait, INFINITE for none
 *  @return non-zero when woken, zero on a time-out (ERROR_TIMEOUT) */
int xpSleepConditionVariable(void** variable, void* criticalSection, unsigned long milliseconds);

//! WakeConditionVariable: wakes one waiting thread, if any.
void xpWakeConditionVariable(void** variable);

//! WakeAllConditionVariable: wakes every waiting thread.
void xpWakeAllConditionVariable(void** variable);

/*! GetThreadId, through NtQueryInformationThread.
 *  @param thread a thread handle with THREAD_QUERY_INFORMATION
 *  @return its identifier, 0 if it could not be read */
unsigned long xpGetThreadId(void* thread);

/*! CompareStringOrdinal, with the system's own upper-casing (RtlUpcaseUnicodeChar).
 *  @param first, second the strings
 *  @param firstLength, secondLength their lengths in characters, -1 if null-terminated
 *  @param ignoreCase non-zero to compare upper-cased
 *  @return CSTR_LESS_THAN, CSTR_EQUAL or CSTR_GREATER_THAN; 0 for a null string */
int xpCompareStringOrdinal(const wchar_t* first, int firstLength, const wchar_t* second, int secondLength, int ignoreCase);

/*! wcsncpy_s, which the C library of Windows XP does not have.
 *  @param destination the buffer, always terminated
 *  @param size its size in characters
 *  @param source the string to copy
 *  @param count how many characters at most, (size_t)-1 (_TRUNCATE) for as many as fit
 *  @return 0, STRUNCATE (80) when truncated on request, ERANGE (34) when too small, EINVAL (22) */
int xpWcsncpyS(wchar_t* destination, size_t size, const wchar_t* source, size_t count);

#endif
