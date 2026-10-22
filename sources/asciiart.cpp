/*! \file
 *  \brief WAC's console banner.
 */
#include "asciiart.h"
#include "tools.h"

//! Prints WAC's banner on the console.
void asciiart() {
	/* In "#" only: the former banner's block and box-drawing characters
	   ("ANSI Shadow") came out unreadable in the default font of Windows 7's
	   console, and of older ones. Plain ASCII shows the same everywhere. */
	wprintf(L"%hs", R"(

	#   #  ###  #   #  ####    ###   #   #   ####
	#   #   #   ##  #  #   #  #   #  #   #  #
	# # #   #   # # #  #   #  #   #  # # #   ###
	## ##   #   #  ##  #   #  #   #  ## ##      #
	#   #  ###  #   #  ####    ###   #   #  ####

	 ###   ####   #####  #####  #####   ###    ####  #####   ####
	#   #  #   #    #    #      #      #   #  #        #    #
	#####  ####     #    ####   ####   #####  #        #     ###
	#   #  #  #     #    #      #      #   #  #        #        #
	#   #  #   #    #    #####  #      #   #   ####    #    ####

	 ####   ###   #      #      #####   ####  #####   ###   ####
	#      #   #  #      #      #      #        #    #   #  #   #
	#      #   #  #      #      ####   #        #    #   #  ####
	#      #   #  #      #      #      #        #    #   #  #  #
	 ####   ###   #####  #####  #####   ####    #     ###   #   #
)");
	// The version, from the executable's version resource (WAC.rc): written in one place only.
	wprintf(L"\t=> V %ls By Reygiss from CEC\n\n", WacVersion().c_str());
}
