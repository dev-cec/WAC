/*! \file
 *  \brief Checks the equivalents WAC32.exe uses where Windows XP lacks a
 *         function (xp_imports.cpp), against the system's own.
 *
 *  WHY THIS TEST. Under XP these equivalents ARE the condition variables of
 *  the C++ runtime, the comparison of registry key names, the copy of a time
 *  zone's name: a defect there is a collection that hangs, or a key not
 *  found. They are called here DIRECTLY — on a Windows that also has the real
 *  functions, which serve as the reference:
 *    - xpCompareStringOrdinal against CompareStringOrdinal, on every pair of
 *      a set of strings (case, accents, lengths, embedded differences), with
 *      and without case, with explicit and with null-terminated lengths;
 *    - xpGetThreadId against GetCurrentThreadId and against the identifier
 *      CreateThread returns;
 *    - xpWcsncpyS against the cases of the C library's documentation: whole
 *      copy, truncation asked for, buffer too small, count reached;
 *    - the condition variable: a queue fed by one thread and emptied by
 *      four, 20,000 items — every item received exactly once, no thread left
 *      waiting; a wait without wake-up times out, at the delay asked for;
 *      WakeAll wakes every waiter.
 *
 *  A 32-bit program: `xp_imports_test.exe`, built by `build-windows.sh --test`,
 *  run on Windows (the 32-bit subsystem of the 64-bit test VM serves).
 */
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include "xp_imports.h"

namespace {

unsigned long long g_checks = 0, g_failures = 0;

//! Records one check, printing the failures.
void check(bool ok, const std::string& what) {
	++g_checks;
	if (!ok && ++g_failures <= 20) std::printf("  FAILED  %s\n", what.c_str());
}

/* The queue of the condition-variable test: one lock, one condition, both
   handled with the XP equivalents only. */
CRITICAL_SECTION g_lock;
void* g_condition = nullptr;
std::vector<int> g_queue;
bool g_finished = false;
LONG g_received[20000];
volatile LONG g_waitingForAll = 0;

DWORD WINAPI consume(LPVOID) {
	for (;;) {
		EnterCriticalSection(&g_lock);
		while (g_queue.empty() && !g_finished) xpSleepConditionVariable(&g_condition, &g_lock, INFINITE);
		if (g_queue.empty()) { LeaveCriticalSection(&g_lock); return 0; }
		const int item = g_queue.back();
		g_queue.pop_back();
		LeaveCriticalSection(&g_lock);
		InterlockedIncrement(&g_received[item]);
	}
}

DWORD WINAPI waitForAll(LPVOID) {
	EnterCriticalSection(&g_lock);
	InterlockedIncrement(&g_waitingForAll);
	while (!g_finished) xpSleepConditionVariable(&g_condition, &g_lock, INFINITE);
	LeaveCriticalSection(&g_lock);
	return 0;
}

void conditionVariable() {
	InitializeCriticalSection(&g_lock);
	xpInitializeConditionVariable(&g_condition);

	// A wait nobody wakes: it must time out, and not before its delay.
	EnterCriticalSection(&g_lock);
	const DWORD before = GetTickCount();
	const int woken = xpSleepConditionVariable(&g_condition, &g_lock, 200);
	const DWORD waited = GetTickCount() - before;
	const DWORD error = GetLastError();
	LeaveCriticalSection(&g_lock);
	check(!woken && error == ERROR_TIMEOUT && waited >= 180 && waited < 2000,
	      "condition: a wait without wake-up does not time out at its delay (" + std::to_string(waited) + " ms)");

	// A wake-up nobody waits for is lost, as Windows': the next wait still times out.
	xpWakeConditionVariable(&g_condition);
	xpWakeAllConditionVariable(&g_condition);
	EnterCriticalSection(&g_lock);
	check(!xpSleepConditionVariable(&g_condition, &g_lock, 50), "condition: a wake-up without waiter was kept for the next wait");
	LeaveCriticalSection(&g_lock);

	// One producer, four consumers.
	HANDLE consumers[4];
	for (HANDLE& c : consumers) c = CreateThread(nullptr, 0, consume, nullptr, 0, nullptr);
	const int items = (int)(sizeof(g_received) / sizeof(g_received[0]));
	for (int i = 0; i < items; ++i) {
		EnterCriticalSection(&g_lock);
		g_queue.push_back(i);
		LeaveCriticalSection(&g_lock);
		xpWakeConditionVariable(&g_condition);
	}
	EnterCriticalSection(&g_lock);
	g_finished = true;
	LeaveCriticalSection(&g_lock);
	xpWakeAllConditionVariable(&g_condition);
	const DWORD ended = WaitForMultipleObjects(4, consumers, TRUE, 60000);
	check(ended == WAIT_OBJECT_0, "condition: a consumer is still waiting after the last wake-up");
	for (HANDLE c : consumers) CloseHandle(c);
	int once = 0;
	for (int i = 0; i < items; ++i) once += g_received[i] == 1;
	check(once == items, "condition: " + std::to_string(items - once) + " item(s) of " + std::to_string(items) + " not received exactly once");

	// WakeAll: eight threads waiting on the same condition, all woken by one call.
	EnterCriticalSection(&g_lock);
	g_finished = false;
	LeaveCriticalSection(&g_lock);
	HANDLE waiters[8];
	for (HANDLE& w : waiters) w = CreateThread(nullptr, 0, waitForAll, nullptr, 0, nullptr);
	for (int i = 0; i < 500 && g_waitingForAll < 8; ++i) Sleep(10);
	Sleep(100);                                    // the last one has left the lock and waits
	EnterCriticalSection(&g_lock);
	g_finished = true;
	LeaveCriticalSection(&g_lock);
	xpWakeAllConditionVariable(&g_condition);
	check(WaitForMultipleObjects(8, waiters, TRUE, 30000) == WAIT_OBJECT_0, "condition: WakeAll left a waiter asleep");
	for (HANDLE w : waiters) CloseHandle(w);
	DeleteCriticalSection(&g_lock);
}

DWORD WINAPI idle(LPVOID) { Sleep(200); return 0; }

void threadIdentifier() {
	check(xpGetThreadId(GetCurrentThread()) == GetCurrentThreadId(), "GetThreadId: the current thread's is not GetCurrentThreadId's");
	DWORD created = 0;
	HANDLE thread = CreateThread(nullptr, 0, idle, nullptr, 0, &created);
	check(thread && xpGetThreadId(thread) == created && created != GetCurrentThreadId(),
	      "GetThreadId: another thread's is not the one CreateThread returned");
	if (thread) { WaitForSingleObject(thread, 5000); CloseHandle(thread); }
	check(xpGetThreadId(nullptr) == 0, "GetThreadId: an invalid handle gives an identifier");
}

void ordinalComparison() {
	const std::vector<std::wstring> strings = {
		L"", L"a", L"A", L"b", L"ab", L"AB", L"aB", L"abc", L"SOFTWARE", L"Software", L"software\\Microsoft",
		L"SOFTWARE\\MICROSOFT", L"été", L"ÉTÉ", L"éte", L"straße", L"STRASSE", L"i", L"I",
		L"ı", L"İ", L"σ", L"Σ", L"ς", L"z", L"{", L"_", L"Z", L"1", L"10", L"2",
		L"ControlSet001", L"controlset002", L"CurrentControlSet" };
	unsigned long long different = 0, compared = 0;
	size_t firstA = 0, firstB = 0;
	for (const std::wstring& a : strings)
		for (const std::wstring& b : strings)
			for (int ignoreCase = 0; ignoreCase < 2; ++ignoreCase) {
				const int reference = CompareStringOrdinal(a.c_str(), (int)a.size(), b.c_str(), (int)b.size(), ignoreCase);
				const int mine = xpCompareStringOrdinal(a.c_str(), (int)a.size(), b.c_str(), (int)b.size(), ignoreCase);
				const int terminated = xpCompareStringOrdinal(a.c_str(), -1, b.c_str(), -1, ignoreCase);
				// A prefix only: "SOFTWARE" in "SOFTWARE\\MICROSOFT", as the path comparisons ask.
				const int length = (int)(a.size() < b.size() ? a.size() : b.size());
				const int prefix = xpCompareStringOrdinal(a.c_str(), length, b.c_str(), length, ignoreCase);
				const int prefixReference = CompareStringOrdinal(a.c_str(), length, b.c_str(), length, ignoreCase);
				compared += 3;
				if (reference != mine || reference != terminated || prefix != prefixReference) {
					if (!different++) { firstA = &a - strings.data(); firstB = &b - strings.data(); }
				}
			}
	check(different == 0, std::to_string(different) + " comparison(s) of " + std::to_string(compared)
	      + " differ from CompareStringOrdinal, first: strings " + std::to_string(firstA) + " and " + std::to_string(firstB));
	check(xpCompareStringOrdinal(nullptr, 0, L"a", 1, 0) == 0 && CompareStringOrdinal(nullptr, 0, L"a", 1, 0) == 0,
	      "CompareStringOrdinal: a null string is compared");
}

void boundedCopy() {
	const size_t TRUNCATE = (size_t)-1;
	wchar_t eight[8];
	check(xpWcsncpyS(eight, 8, L"Paris", TRUNCATE) == 0 && std::wstring(eight) == L"Paris", "wcsncpy_s: a string that fits is not copied whole");
	check(xpWcsncpyS(eight, 8, L"1234567", TRUNCATE) == 0 && std::wstring(eight) == L"1234567", "wcsncpy_s: a string of exactly the room left");
	check(xpWcsncpyS(eight, 8, L"Romance Standard Time", TRUNCATE) == 80 && std::wstring(eight) == L"Romance",
	      "wcsncpy_s: _TRUNCATE does not truncate to the buffer, terminated");
	check(xpWcsncpyS(eight, 8, L"Romance Standard Time", 3) == 0 && std::wstring(eight) == L"Rom", "wcsncpy_s: the count is not respected");
	check(xpWcsncpyS(eight, 8, L"Romance Standard Time", 12) == 34 && eight[0] == L'\0', "wcsncpy_s: a buffer too small is not refused and emptied");
	check(xpWcsncpyS(eight, 8, nullptr, TRUNCATE) == 22 && eight[0] == L'\0' && xpWcsncpyS(nullptr, 8, L"a", TRUNCATE) == 22
	      && xpWcsncpyS(eight, 0, L"a", TRUNCATE) == 22, "wcsncpy_s: a null pointer or an empty buffer accepted");
	/* Against the C library's own, where it exists — taken from msvcrt.dll by
	   name: `wcsncpy_s` written here would be linked to WAC's. */
	using Library = int (__cdecl*)(wchar_t*, size_t, const wchar_t*, size_t);
	const Library library = reinterpret_cast<Library>(reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"msvcrt.dll"), "wcsncpy_s")));
	check(library != nullptr, "wcsncpy_s: msvcrt.dll has none here, nothing to compare with");
	wchar_t mine[8], theirs[8];
	for (const wchar_t* source : { L"", L"a", L"1234567", L"12345678", L"Romance Standard Time" }) {
		if (!library) break;
		const int a = xpWcsncpyS(mine, 8, source, TRUNCATE), b = library(theirs, 8, source, TRUNCATE);
		check(a == b && std::wstring(mine) == std::wstring(theirs), "wcsncpy_s: differs from the C library's on a string");
	}
}

} // namespace

int main() {
	boundedCopy();
	ordinalComparison();
	threadIdentifier();
	conditionVariable();
	std::printf("%llu check(s), %llu failure(s)\n", g_checks, g_failures);
	return g_failures ? 1 : 0;
}
