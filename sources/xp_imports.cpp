/*! \file
 *  \brief The fourteen functions Windows XP lacks, for the 32-bit WAC
 *         (WAC32.exe) — see xp_imports.h.
 *
 *  WHY THIS FILE (backlog B-037). A program does not load at all on a Windows
 *  that lacks ONE function it imports ("entry point not found"). Confronted
 *  with the DLLs of Windows XP SP1, a 32-bit WAC imported fourteen such
 *  functions out of 271: the condition variables and GetThreadId, which the
 *  C++ runtime itself calls (the guard of every static variable);
 *  GetTickCount64 and CompareStringOrdinal; wcsncpy_s; and the whole of
 *  bcrypt.dll. All came with Windows Vista.
 *
 *  HOW. Each one is DEFINED here, under the very name the linker looks for —
 *  the function and its import pointer (`__imp__Name@N`) —, so that WAC32.exe
 *  imports none of them. Each definition asks the running system once: where
 *  the real function exists (Vista and later), it is called, and WAC32
 *  behaves there as if it had imported it; where it does not, an equivalent
 *  made of what XP has takes its place. The 64-bit WAC is not concerned — no
 *  64-bit Windows lacks them but XP x64, which it does not address — and this
 *  file is empty for it: WAC.exe stays the same file, byte for byte.
 *
 *  build-windows.sh checks the result: every import of WAC32.exe is confronted
 *  with the exports of Windows XP SP1 (vmtest/reference/xp-sp1-exports.txt).
 */
#include "xp_imports.h"

#if defined(_WIN32) && !defined(_WIN64)

#include <windows.h>
#include <cstring>

namespace {

/*! A function looked up once. NOT a `static` local: the C++ runtime guards
 *  those with the very condition variables defined below, and the first
 *  guard would wait on itself. A plain zero-initialised global instead; two
 *  threads looking at once find the same address — the race is harmless. */
struct Lookup {
	void* function;
	LONG done;
};

//! The function of a system DLL already loaded, or nullptr if this Windows lacks it.
template <typename F>
F systemFunction(Lookup& lookup, const wchar_t* library, const char* name) {
	if (!lookup.done) {
		const HMODULE module = GetModuleHandleW(library);
		lookup.function = module ? reinterpret_cast<void*>(GetProcAddress(module, name)) : nullptr;
		lookup.done = 1;
	}
	return reinterpret_cast<F>(lookup.function);
}

/*! What a condition variable holds where Windows has none: the number of
 *  threads waiting and a semaphore that wakes them. Allocated at the
 *  variable's first use and never freed — a condition variable has no
 *  destructor in the Windows API, and the C++ runtime owns a handful. */
struct XpCondition {
	volatile LONG waiting;
	HANDLE wake;
};

/*! The state behind a condition variable, created on first use. Two threads
 *  may race to create it: the loser frees its own.
 *  @param variable the CONDITION_VARIABLE, a pointer-sized slot
 *  @return its state, nullptr if it could not be created */
XpCondition* conditionOf(void** variable) {
	XpCondition* state = static_cast<XpCondition*>(*variable);
	if (state) return state;
	state = static_cast<XpCondition*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(XpCondition)));
	if (!state) return nullptr;
	state->wake = CreateSemaphoreW(nullptr, 0, MAXLONG, nullptr);
	if (!state->wake) { HeapFree(GetProcessHeap(), 0, state); return nullptr; }
	void* previous = InterlockedCompareExchangePointer(variable, state, nullptr);
	if (!previous) return state;
	CloseHandle(state->wake);
	HeapFree(GetProcessHeap(), 0, state);
	return static_cast<XpCondition*>(previous);
}

//! Wakes up to `wanted` of the threads waiting on a condition.
void wakeWaiting(void** variable, LONG wanted) {
	XpCondition* state = static_cast<XpCondition*>(*variable);
	if (!state) return;                                   // nobody ever waited
	for (;;) {
		const LONG waiting = state->waiting;
		if (waiting <= 0) return;
		const LONG woken = waiting < wanted ? waiting : wanted;
		// The count is taken before the semaphore is released: a waiter woken is no longer counted.
		if (InterlockedCompareExchange(&state->waiting, waiting - woken, waiting) != waiting) continue;
		ReleaseSemaphore(state->wake, woken, nullptr);
		return;
	}
}

// bcrypt.dll, loaded when first needed (see its functions below).
Lookup bcryptLoaded;   // .function: the module

HMODULE bcryptLibrary() {
	if (!bcryptLoaded.done) {
		wchar_t folder[MAX_PATH] = L"";
		const UINT length = GetSystemDirectoryW(folder, MAX_PATH);
		if (length != 0 && length + 12 < MAX_PATH) {
			wcscpy(folder + length, L"\\bcrypt.dll");
			bcryptLoaded.function = LoadLibraryExW(folder, nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
		}
		bcryptLoaded.done = 1;
	}
	return static_cast<HMODULE>(bcryptLoaded.function);
}

template <typename F>
F bcryptFunction(Lookup& lookup, const char* name) {
	if (!lookup.done) {
		const HMODULE library = bcryptLibrary();
		lookup.function = library ? reinterpret_cast<void*>(GetProcAddress(library, name)) : nullptr;
		lookup.done = 1;
	}
	return reinterpret_cast<F>(lookup.function);
}

const LONG NOT_SUPPORTED = static_cast<LONG>(0xC00000BBu);   // STATUS_NOT_SUPPORTED

} // namespace

void xpInitializeConditionVariable(void** variable) {
	*variable = nullptr;
}

int xpSleepConditionVariable(void** variable, void* criticalSection, unsigned long milliseconds) {
	XpCondition* state = conditionOf(variable);
	if (!state) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
	/* Counted BEFORE the lock is left: a thread that wakes between the two
	   releases the semaphore, which keeps the wake-up for this one. */
	InterlockedIncrement(&state->waiting);
	LeaveCriticalSection(static_cast<LPCRITICAL_SECTION>(criticalSection));
	const DWORD waited = WaitForSingleObject(state->wake, milliseconds);
	if (waited != WAIT_OBJECT_0) {
		/* Timed out: no longer waiting — unless a wake-up counted this thread
		   out at the same instant, in which case its semaphore unit is taken. */
		for (;;) {
			const LONG waiting = state->waiting;
			if (waiting <= 0) { WaitForSingleObject(state->wake, INFINITE); break; }
			if (InterlockedCompareExchange(&state->waiting, waiting - 1, waiting) == waiting) break;
		}
	}
	EnterCriticalSection(static_cast<LPCRITICAL_SECTION>(criticalSection));
	if (waited == WAIT_OBJECT_0) return TRUE;
	SetLastError(ERROR_TIMEOUT);
	return FALSE;
}

void xpWakeConditionVariable(void** variable) { wakeWaiting(variable, 1); }

void xpWakeAllConditionVariable(void** variable) { wakeWaiting(variable, MAXLONG); }

unsigned long xpGetThreadId(void* thread) {
	/* NtQueryInformationThread(ThreadBasicInformation): the client identifier
	   holds the thread's. The layout is the documented one, 32 bits. */
	struct ThreadBasicInformation {
		LONG exitStatus;
		void* tebBaseAddress;
		void* uniqueProcess;
		void* uniqueThread;
		ULONG_PTR affinityMask;
		LONG priority;
		LONG basePriority;
	} information = {};
	using Query = LONG (WINAPI*)(HANDLE, int, void*, ULONG, ULONG*);
	static Lookup lookup1;
	const Query query = systemFunction<Query>(lookup1, L"ntdll.dll", "NtQueryInformationThread");
	if (!query || query(static_cast<HANDLE>(thread), 0, &information, sizeof(information), nullptr) < 0) return 0;
	return static_cast<unsigned long>(reinterpret_cast<ULONG_PTR>(information.uniqueThread));
}

int xpCompareStringOrdinal(const wchar_t* first, int firstLength, const wchar_t* second, int secondLength, int ignoreCase) {
	if (!first || !second) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
	// RtlUpcaseUnicodeChar: the upper-casing of the system itself, the one CompareStringOrdinal applies.
	using Upcase = wchar_t (WINAPI*)(wchar_t);
	static Lookup lookup2;
	const Upcase upcase = systemFunction<Upcase>(lookup2, L"ntdll.dll", "RtlUpcaseUnicodeChar");
	const size_t a = firstLength < 0 ? wcslen(first) : static_cast<size_t>(firstLength);
	const size_t b = secondLength < 0 ? wcslen(second) : static_cast<size_t>(secondLength);
	for (size_t i = 0; i < a && i < b; ++i) {
		wchar_t x = first[i], y = second[i];
		if (ignoreCase && upcase) { x = upcase(x); y = upcase(y); }
		if (x != y) return x < y ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
	}
	return a == b ? CSTR_EQUAL : a < b ? CSTR_LESS_THAN : CSTR_GREATER_THAN;
}

int xpWcsncpyS(wchar_t* destination, size_t size, const wchar_t* source, size_t count) {
	const int INVALID = 22, RANGE = 34, TRUNCATED = 80;       // EINVAL, ERANGE, STRUNCATE
	if (!destination || size == 0) return INVALID;
	if (!source) { destination[0] = L'\0'; return INVALID; }
	const bool truncate = count == static_cast<size_t>(-1);  // _TRUNCATE: as much as fits
	size_t i = 0;
	for (; i < size - 1 && (truncate || i < count) && source[i]; ++i) destination[i] = source[i];
	destination[i] = L'\0';
	const bool whole = !source[i] || (!truncate && i == count);
	if (whole) return 0;
	if (truncate) return TRUNCATED;
	destination[0] = L'\0';                                  // too small, and not asked to truncate
	return RANGE;
}

/* ---------------------------------------------------------------------------
   THE NAMES THE LINKER LOOKS FOR. Each function forwards to the system's own
   when this Windows has it, to the equivalent above otherwise; its import
   pointer follows, for the callers compiled against the DLL declaration.
   The assembler names are those of the 32-bit convention: `_Name@bytes` for
   stdcall, `_name` for cdecl.
   --------------------------------------------------------------------------- */
extern "C" {

void WINAPI wacInitializeConditionVariable(void** variable) __asm__("_InitializeConditionVariable@4");
void WINAPI wacInitializeConditionVariable(void** variable) {
	using Real = void (WINAPI*)(void**);
	static Lookup lookup3;
	const Real real = systemFunction<Real>(lookup3, L"kernel32.dll", "InitializeConditionVariable");
	if (real) real(variable); else xpInitializeConditionVariable(variable);
}

BOOL WINAPI wacSleepConditionVariableCS(void** variable, void* criticalSection, DWORD milliseconds) __asm__("_SleepConditionVariableCS@12");
BOOL WINAPI wacSleepConditionVariableCS(void** variable, void* criticalSection, DWORD milliseconds) {
	using Real = BOOL (WINAPI*)(void**, void*, DWORD);
	static Lookup lookup4;
	const Real real = systemFunction<Real>(lookup4, L"kernel32.dll", "SleepConditionVariableCS");
	return real ? real(variable, criticalSection, milliseconds) : xpSleepConditionVariable(variable, criticalSection, milliseconds);
}

void WINAPI wacWakeConditionVariable(void** variable) __asm__("_WakeConditionVariable@4");
void WINAPI wacWakeConditionVariable(void** variable) {
	using Real = void (WINAPI*)(void**);
	static Lookup lookup5;
	const Real real = systemFunction<Real>(lookup5, L"kernel32.dll", "WakeConditionVariable");
	if (real) real(variable); else xpWakeConditionVariable(variable);
}

void WINAPI wacWakeAllConditionVariable(void** variable) __asm__("_WakeAllConditionVariable@4");
void WINAPI wacWakeAllConditionVariable(void** variable) {
	using Real = void (WINAPI*)(void**);
	static Lookup lookup6;
	const Real real = systemFunction<Real>(lookup6, L"kernel32.dll", "WakeAllConditionVariable");
	if (real) real(variable); else xpWakeAllConditionVariable(variable);
}

DWORD WINAPI wacGetThreadId(HANDLE thread) __asm__("_GetThreadId@4");
DWORD WINAPI wacGetThreadId(HANDLE thread) {
	using Real = DWORD (WINAPI*)(HANDLE);
	static Lookup lookup7;
	const Real real = systemFunction<Real>(lookup7, L"kernel32.dll", "GetThreadId");
	return real ? real(thread) : xpGetThreadId(thread);
}

ULONGLONG WINAPI wacGetTickCount64(void) __asm__("_GetTickCount64@0");
ULONGLONG WINAPI wacGetTickCount64(void) {
	using Real = ULONGLONG (WINAPI*)(void);
	static Lookup lookup8;
	const Real real = systemFunction<Real>(lookup8, L"kernel32.dll", "GetTickCount64");
	// Under XP, the 32-bit counter: it wraps after 49.7 days of uptime, which the boot-time estimate states.
	return real ? real() : GetTickCount();
}

int WINAPI wacCompareStringOrdinal(LPCWCH first, int firstLength, LPCWCH second, int secondLength, BOOL ignoreCase) __asm__("_CompareStringOrdinal@20");
int WINAPI wacCompareStringOrdinal(LPCWCH first, int firstLength, LPCWCH second, int secondLength, BOOL ignoreCase) {
	using Real = int (WINAPI*)(LPCWCH, int, LPCWCH, int, BOOL);
	static Lookup lookup9;
	const Real real = systemFunction<Real>(lookup9, L"kernel32.dll", "CompareStringOrdinal");
	return real ? real(first, firstLength, second, secondLength, ignoreCase)
	            : xpCompareStringOrdinal(first, firstLength, second, secondLength, ignoreCase);
}

// msvcrt.dll's of XP has no wcsncpy_s: WAC's own, on every Windows — the same result whatever the C library.
int __cdecl wacWcsncpyS(wchar_t* destination, size_t size, const wchar_t* source, size_t count) __asm__("_wcsncpy_s");
int __cdecl wacWcsncpyS(wchar_t* destination, size_t size, const wchar_t* source, size_t count) {
	return xpWcsncpyS(destination, size, source, count);
}

/* bcrypt.dll (AES and DES of the SAM's hashes, at the conversion): loaded when
   first needed, from System32. Under XP it does not exist: each call answers
   STATUS_NOT_SUPPORTED, and the conversion — which is not made on the
   examined machine — says the hashes were not decrypted. */
LONG WINAPI wacBCryptOpenAlgorithmProvider(void** algorithm, LPCWSTR identifier, LPCWSTR implementation, ULONG flags) __asm__("_BCryptOpenAlgorithmProvider@16");
LONG WINAPI wacBCryptOpenAlgorithmProvider(void** algorithm, LPCWSTR identifier, LPCWSTR implementation, ULONG flags) {
	using Real = LONG (WINAPI*)(void**, LPCWSTR, LPCWSTR, ULONG);
	static Lookup bcrypt1;
	const Real real = bcryptFunction<Real>(bcrypt1, "BCryptOpenAlgorithmProvider");
	return real ? real(algorithm, identifier, implementation, flags) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptSetProperty(void* object, LPCWSTR property, PUCHAR input, ULONG inputSize, ULONG flags) __asm__("_BCryptSetProperty@20");
LONG WINAPI wacBCryptSetProperty(void* object, LPCWSTR property, PUCHAR input, ULONG inputSize, ULONG flags) {
	using Real = LONG (WINAPI*)(void*, LPCWSTR, PUCHAR, ULONG, ULONG);
	static Lookup bcrypt2;
	const Real real = bcryptFunction<Real>(bcrypt2, "BCryptSetProperty");
	return real ? real(object, property, input, inputSize, flags) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptGetProperty(void* object, LPCWSTR property, PUCHAR output, ULONG outputSize, ULONG* resultSize,
                                 ULONG flags) __asm__("_BCryptGetProperty@24");
LONG WINAPI wacBCryptGetProperty(void* object, LPCWSTR property, PUCHAR output, ULONG outputSize, ULONG* resultSize,
                                 ULONG flags) {
	using Real = LONG (WINAPI*)(void*, LPCWSTR, PUCHAR, ULONG, ULONG*, ULONG);
	static Lookup bcrypt7;
	const Real real = bcryptFunction<Real>(bcrypt7, "BCryptGetProperty");
	return real ? real(object, property, output, outputSize, resultSize, flags) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptGenerateSymmetricKey(void* algorithm, void** key, PUCHAR keyObject, ULONG keyObjectSize,
                                          PUCHAR secret, ULONG secretSize, ULONG flags) __asm__("_BCryptGenerateSymmetricKey@28");
LONG WINAPI wacBCryptGenerateSymmetricKey(void* algorithm, void** key, PUCHAR keyObject, ULONG keyObjectSize,
                                          PUCHAR secret, ULONG secretSize, ULONG flags) {
	using Real = LONG (WINAPI*)(void*, void**, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
	static Lookup bcrypt3;
	const Real real = bcryptFunction<Real>(bcrypt3, "BCryptGenerateSymmetricKey");
	return real ? real(algorithm, key, keyObject, keyObjectSize, secret, secretSize, flags) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptDecrypt(void* key, PUCHAR input, ULONG inputSize, void* padding, PUCHAR iv, ULONG ivSize,
                             PUCHAR output, ULONG outputSize, ULONG* resultSize, ULONG flags) __asm__("_BCryptDecrypt@40");
LONG WINAPI wacBCryptDecrypt(void* key, PUCHAR input, ULONG inputSize, void* padding, PUCHAR iv, ULONG ivSize,
                             PUCHAR output, ULONG outputSize, ULONG* resultSize, ULONG flags) {
	using Real = LONG (WINAPI*)(void*, PUCHAR, ULONG, void*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
	static Lookup bcrypt4;
	const Real real = bcryptFunction<Real>(bcrypt4, "BCryptDecrypt");
	return real ? real(key, input, inputSize, padding, iv, ivSize, output, outputSize, resultSize, flags) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptDestroyKey(void* key) __asm__("_BCryptDestroyKey@4");
LONG WINAPI wacBCryptDestroyKey(void* key) {
	using Real = LONG (WINAPI*)(void*);
	static Lookup bcrypt5;
	const Real real = bcryptFunction<Real>(bcrypt5, "BCryptDestroyKey");
	return real ? real(key) : NOT_SUPPORTED;
}

LONG WINAPI wacBCryptCloseAlgorithmProvider(void* algorithm, ULONG flags) __asm__("_BCryptCloseAlgorithmProvider@8");
LONG WINAPI wacBCryptCloseAlgorithmProvider(void* algorithm, ULONG flags) {
	using Real = LONG (WINAPI*)(void*, ULONG);
	static Lookup bcrypt6;
	const Real real = bcryptFunction<Real>(bcrypt6, "BCryptCloseAlgorithmProvider");
	return real ? real(algorithm, flags) : NOT_SUPPORTED;
}

// The import pointers, for the callers compiled against the DLL declarations (`call *__imp__Name@N`).
void* wacImportInitializeConditionVariable __asm__("__imp__InitializeConditionVariable@4") = reinterpret_cast<void*>(wacInitializeConditionVariable);
void* wacImportSleepConditionVariableCS __asm__("__imp__SleepConditionVariableCS@12") = reinterpret_cast<void*>(wacSleepConditionVariableCS);
void* wacImportWakeConditionVariable __asm__("__imp__WakeConditionVariable@4") = reinterpret_cast<void*>(wacWakeConditionVariable);
void* wacImportWakeAllConditionVariable __asm__("__imp__WakeAllConditionVariable@4") = reinterpret_cast<void*>(wacWakeAllConditionVariable);
void* wacImportGetThreadId __asm__("__imp__GetThreadId@4") = reinterpret_cast<void*>(wacGetThreadId);
void* wacImportGetTickCount64 __asm__("__imp__GetTickCount64@0") = reinterpret_cast<void*>(wacGetTickCount64);
void* wacImportCompareStringOrdinal __asm__("__imp__CompareStringOrdinal@20") = reinterpret_cast<void*>(wacCompareStringOrdinal);
void* wacImportWcsncpyS __asm__("__imp__wcsncpy_s") = reinterpret_cast<void*>(wacWcsncpyS);

} // extern "C"

#endif // 32-bit Windows
