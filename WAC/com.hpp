//com.hpp
#pragma once

#define _WIN32_DCOM
#include <iostream>
#include <comdef.h>
#include <string>
#include "tools.h"



/*! structure permettant de se connecter sur le système pour par la suite exécuter des requête WMI et WIN32 API
*/
struct COM {
public:

    /*! Connexion au service WMI
    */
    HRESULT connect() {
        log(0, L"*******************************************************************************************************************");
        log(0, L"ℹ️ COM COMPONENT");
        log(0, L"*******************************************************************************************************************");


        // Step 1: --------------------------------------------------
        // Initialize COM. ------------------------------------------
        HRESULT hres;
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres))
        {
            log(1,L"Failed to initialize COM library", hres);
            return hres;                  // Program has failed.
        }

        // Step 2: --------------------------------------------------
        // Set general COM security levels --------------------------

        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities 
            NULL                         // Reserved
        );

        if (FAILED(hres))
        {
            log(1, L"🔥 Failed to initialize security", hres);
            clear();
            return hres;                    // Program has failed.
        }

        return ERROR_SUCCESS;
    }

    void clear() {
        CoUninitialize();
    }
};
