/* taskschd_missing.h — interfaces Task Scheduler absentes de mingw taskschd.h.
 * À inclure APRÈS <taskschd.h> (a besoin d'IAction).
 * Disposition vtable = IAction + get/put_ClassId + get/put_Data (ordre MS),
 * pour rester binaire-compatible avec la vraie taskschd.dll au runtime.
 * WAC n'utilise que get_ClassId / get_Data via un cast C, pas __uuidof.
 */
#pragma once
#ifndef __IComHandlerAction_INTERFACE_DEFINED__
#define __IComHandlerAction_INTERFACE_DEFINED__
struct IComHandlerAction : public IAction {
    virtual HRESULT STDMETHODCALLTYPE get_ClassId(BSTR *pClassId) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_ClassId(BSTR classId) = 0;
    virtual HRESULT STDMETHODCALLTYPE get_Data(BSTR *pData) = 0;
    virtual HRESULT STDMETHODCALLTYPE put_Data(BSTR data) = 0;
};
#endif
