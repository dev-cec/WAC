/*! \file
 *  \brief Stand-in for propsys.dll, for WAC's test harnesses under Wine only.
 *
 *  WHY. Wine does not implement PSGetNameFromPropertyKey: its propsys.dll
 *  aborts the process when the function is called. WAC calls it to name the
 *  properties of a property store, which real shortcuts carry — so lnk_test
 *  died on them for a reason that has nothing to do with the parser. This DLL
 *  answers "no name", as Windows does for a key it does not know; WAC then
 *  keeps the raw key. Never shipped: WAC.exe uses the system's propsys.dll.
 *
 *  Use: place propsys.dll next to the test exe, and run with
 *  WINEDLLOVERRIDES="propsys=n".
 */
#include <windows.h>

/*! Layout of PROPERTYKEY, declared here to depend on no header. */
typedef struct { GUID fmtid; DWORD pid; } WacPropertyKey;

/*! Always "not found".
 *  @param key the property key (unused)
 *  @param name receives NULL
 *  @return TYPE_E_ELEMENTNOTFOUND */
__declspec(dllexport) HRESULT WINAPI PSGetNameFromPropertyKey(const WacPropertyKey* key, PWSTR* name) {
	(void)key;
	if (name) *name = NULL;
	return TYPE_E_ELEMENTNOTFOUND;
}
