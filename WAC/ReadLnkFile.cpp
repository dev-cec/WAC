//*****************************************************************************
// File ..................: ReadLnkFile.cpp
// Description ...........: Decoder for .lnk files on WINDOWS
// Author ................: Peter Thoemmes (http://www.notes-about-cpp.com/)
//-----------------------------------------------------------------------------
// #                  !!! Disclaimer !!!                                      #
// # This source code is provided "AS-IS" basis, without any warranties or    #
// # representations express, implied or statutory; including, without        #
// # limitation, warranties of quality, performance, non-infringement,        #
// # merchantability or fitness for a particular purpose. Peter Thoemmes      #
// # does not warrant that this source code will meet your needs or be free   #
// # from errors.                                                             #
//-----------------------------------------------------------------------------
// Many thanks to Jesse Hager (jessehager@iname.com) for reverse engineering
// the shortcut file format and publishing the document 'The Windows Shortcut
// File Format'.
//-----------------------------------------------------------------------------
// Copyright (c) 2008 Peter Thoemmes, Weinbergstr. 3a, D-54441 Ockfen/Germany
//*****************************************************************************

#include <string>
#include <vector>
using namespace std;

//-----------------------------------------------------------------------------
// Get target file (full local path) from a link file (.lnk):
//-----------------------------------------------------------------------------

string ReadLnkFile(const string& strFullLinkFileName)
{
	//-------------------------------------------------------------------------
	// How to read the target's path from a .lnk-file:
	//-------------------------------------------------------------------------
	// Problem:
	//
	//    The COM interface to shell32.dll IShellLink::GetPath() fails!
	//
	// Solution:
	//
	//   We need to parse the file manually. The path can be found like shown
	//   here, if the shell item id list is present. In case it is not present
	//   we have to assume A = -6, but not to parse/decode byte 76 and 77.
	//
	//  +---------------------+-----------------------------------------------+
	//  | Index               | Description                                   |
	//  +---------------------+-----------------------------------------------+
	//  |                   0 | 'L' (magic value)                             |
	//  +---------------------+-----------------------------------------------+
	//  |                 ... | ...                                           |
	//  +---------------------+-----------------------------------------------+
	//  |                  76 | A_0                                           |
	//  +---------------------+-----------------------------------------------+
	//  |                  77 | A_1 (16 bit) [w/o shell item id list: A = -6] |
	//  +---------------------+-----------------------------------------------+
	//  |                 ... | ...                                           |
	//  +---------------------+-----------------------------------------------+
	//  |         78 + 16 + A | B_0                                           |
	//  +---------------------+-----------------------------------------------+
	//  |     78 + 16 + A + 1 | B_1                                           |
	//  +---------------------+-----------------------------------------------+
	//  |     78 + 16 + A + 2 | B_2                                           |
	//  +---------------------+-----------------------------------------------+
	//  |     78 + 16 + A + 3 | B_3 (32 bit)                                  |
	//  +---------------------+-----------------------------------------------+
	//  |                 ... | ...                                           |
	//  +---------------------+-----------------------------------------------+
	//  |          78 + A + B | PATH_STR_0                                    |
	//  +---------------------+-----------------------------------------------+
	//  |      78 + A + B + 1 | PATH_STR_1                                    |
	//  +---------------------+-----------------------------------------------+
	//  |      78 + A + B + 2 | PATH_STR_2                                    |
	//  +---------------------+-----------------------------------------------+
	//  |                 ... | ...                                           |
	//  +---------------------+-----------------------------------------------+
	//  |                 ... | 0x00                                          |
	//  +---------------------+-----------------------------------------------+
	//-------------------------------------------------------------------------

	//-------------------------------------------------------------------------
	// Get the .lnk-file content:
	//-------------------------------------------------------------------------

	FILE* pFile = fopen(strFullLinkFileName.c_str(),"rb");
	if(!pFile)
		return string("");
	vector<unsigned char> vectBuffer;
	unsigned char byte = '?';
	while((byte = (unsigned char) fgetc(pFile)) != (unsigned char) EOF)
		vectBuffer.push_back(byte);
	fclose(pFile);

	//-------------------------------------------------------------------------
	// Check the magic value (first byte) and the GUID (16 byte from 5th byte):
	//-------------------------------------------------------------------------
	// The GUID is telling the version of the .lnk-file format. We expect the
	// following GUID (HEX): 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46.
	//-------------------------------------------------------------------------

	if(vectBuffer.size() < 20)
		return string("");
	if(vectBuffer[0] != (unsigned char) 'L') //test the magic value
		return string("");
	if((vectBuffer[4] != 0x01) || //test the GUID
	   (vectBuffer[5] != 0x14) ||
	   (vectBuffer[6] != 0x02) ||
	   (vectBuffer[7] != 0x00) ||
	   (vectBuffer[8] != 0x00) ||
	   (vectBuffer[9] != 0x00) ||
	   (vectBuffer[10] != 0x00) ||
	   (vectBuffer[11] != 0x00) ||
	   (vectBuffer[12] != 0xC0) ||
	   (vectBuffer[13] != 0x00) ||
	   (vectBuffer[14] != 0x00) ||
	   (vectBuffer[15] != 0x00) ||
	   (vectBuffer[16] != 0x00) ||
	   (vectBuffer[17] != 0x00) ||
	   (vectBuffer[18] != 0x00) ||
	   (vectBuffer[19] != 0x46))
	{
		return string("");
	}

	//-------------------------------------------------------------------------
	// Get the flags (4 byte from 21st byte):
	//-------------------------------------------------------------------------
	// Check if it points to a file or directory!
	//-------------------------------------------------------------------------
	// Flags (4 byte little endian):
	//		Bit 0 -> has shell item id list
	//		Bit 1 -> points to file or directory
	//		Bit 2 -> has description
	//		Bit 3 -> has relative path
	//		Bit 4 -> has working directory
	//		Bit 5 -> has commandline arguments
	//		Bit 6 -> has custom icon
	//-------------------------------------------------------------------------

	unsigned int i = 20;
	if(vectBuffer.size() < (i + 4))
		return string("");
	unsigned int dwFlags = (unsigned int) vectBuffer[i]; //little endian format
	dwFlags |= (((unsigned int) vectBuffer[++i]) << 8);
	dwFlags |= (((unsigned int) vectBuffer[++i]) << 16);
	dwFlags |= (((unsigned int) vectBuffer[++i]) << 24);

	bool bHasShellItemIdList = (dwFlags & 0x00000001) ? true : false;
	bool bPointsToFileOrDir = (dwFlags & 0x00000002) ? true : false;
	
	if(!bPointsToFileOrDir)
		return string("");

	//-------------------------------------------------------------------------
	// Shell item id list (starts at 76 with 2 byte length -> so we can skip):
	//-------------------------------------------------------------------------

	int32 A = -6;
	if(bHasShellItemIdList)
	{
		i = 76;
		if(vectBuffer.size() < (i + 2))
			return string("");
		A = (unsigned char) vectBuffer[i]; //little endian format
		A |= (((unsigned char) vectBuffer[++i]) << 8);
	}

	//-------------------------------------------------------------------------
	// File location info:
	//-------------------------------------------------------------------------
	// Follows the shell item id list and starts with 4 byte structure length,
	// followed by 4 byte offset for skipping.
	//-------------------------------------------------------------------------

	i = 78 + 4 + A;
	if(vectBuffer.size() < (i + 4))
		return string("");
	unsigned int B = (unsigned int) vectBuffer[i]; //little endian format
	B |= (((unsigned int) vectBuffer[++i]) << 8);
	B |= (((unsigned int) vectBuffer[++i]) << 16);
	B |= (((unsigned int) vectBuffer[++i]) << 24);

	//-------------------------------------------------------------------------
	// Local volume table:
	//-------------------------------------------------------------------------
	// Follows the file location info and starts with 4 byte table length for
	// skipping the actual table and moving to the local path string.
	//-------------------------------------------------------------------------

	i = 78 + A + B;
	if(vectBuffer.size() < (i + 4))
		return string("");
	unsigned int C = (unsigned int) vectBuffer[i]; //little endian format
	C |= (((unsigned int) vectBuffer[++i]) << 8);
	C |= (((unsigned int) vectBuffer[++i]) << 16);
	C |= (((unsigned int) vectBuffer[++i]) << 24);

	//-------------------------------------------------------------------------
	// Local path string (ending with 0x00):
	//-------------------------------------------------------------------------

	i = 78 + A + B + C;
	if(vectBuffer.size() < (i + 1))
		return string("");

	string strLinkedTarget = "";
	for(;i < vectBuffer.size();++i)
	{
		strLinkedTarget.append(1,(char) vectBuffer[i]);
		if(!vectBuffer[i])
			break;
	}

	//Return if empty:
	if(strLinkedTarget.empty())
		return string("");

	//-------------------------------------------------------------------------
	// Convert the target path into the long format (format without ~):
	//-------------------------------------------------------------------------
	// GetLongPathNameA() fails it the target file doesn't exist!
	//-------------------------------------------------------------------------

	char* szLinkedTargetLongFormat = new char[MAX_PATH + 1];
	if(!szLinkedTargetLongFormat)
		return string("");
	if(!::GetLongPathNameA(
				strLinkedTarget.c_str(),
				szLinkedTargetLongFormat,
				MAX_PATH))
	{
		return strLinkedTarget; //file doesn't exist
	}
	string strLinkedTargetLongFormat(szLinkedTargetLongFormat);
	delete[] szLinkedTargetLongFormat;

	return strLinkedTargetLongFormat;
}
