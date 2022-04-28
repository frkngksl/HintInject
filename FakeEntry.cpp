#include <Windows.h>
#include <iostream>
#include <cmath>
#include <set>
#include "DllNamesForFakeImports.h"
#include "Utils.h"
#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))

LPCSTR* nameArray = NULL;

DWORD Rva2Offset(DWORD dwRva, PBYTE uiBaseAddress) {
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

LPCSTR* GetImportNamesFromIndex(PBYTE dllBuffer, int* selectedIndexes, int indexArraySize) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBuffer + Rva2Offset(imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllBuffer));
	PDWORD nameArray = (PDWORD)(dllBuffer + Rva2Offset(imageExportDirectory->AddressOfNames,dllBuffer));
	LPCSTR *returnArrayAddr = (LPCSTR *) HeapAlloc(GetProcessHeap(), 0, indexArraySize * sizeof(LPCSTR));
	if (returnArrayAddr == NULL) {
		std::cout << "[!] Error on heap allocation !" << std::endl;
		return NULL;
	}
	PCHAR tmpNamePtr = NULL;
	int selectedIndex = 0;
	DWORD rvaOfName = 0;
	for (int i = 0; i < indexArraySize; i++) {
		selectedIndex = selectedIndexes[i];
		rvaOfName = nameArray[selectedIndex];
		tmpNamePtr = (PCHAR)(dllBuffer + Rva2Offset(rvaOfName, dllBuffer));
		returnArrayAddr[i] = (LPCSTR)HeapAlloc(GetProcessHeap(), 0, strlen(tmpNamePtr)+1);
		if (returnArrayAddr[i] == NULL) {
			std::cout << "[!] Error on heap allocation !" << std::endl;
			return NULL;
		}
		memset((void *) returnArrayAddr[i], 0x00, strlen(tmpNamePtr) + 1);
		memcpy((void*) returnArrayAddr[i], tmpNamePtr, strlen(tmpNamePtr));
	}
	return returnArrayAddr;
}

LPCSTR* SelectDLLEntries(LPCSTR dllName, uint64_t numberOfDesiredFunctions) {
	char dllPath[MAX_PATH] = { 0x00 };
	uint64_t dllSize = 0;
	sprintf_s(dllPath, "C:\\Windows\\System32\\%s", dllName);
	PBYTE dllBuffer = ReadFileFromDisk(dllPath, dllSize);
	if (dllBuffer == NULL || dllSize == 0) {
		std::cout << "[!] Error on dll read" << std::endl;
		return NULL;
	}
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBuffer + Rva2Offset(imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,dllBuffer));
	DWORD numberOfNames = imageExportDirectory->NumberOfNames;
	PDWORD nameArray = (PDWORD)(dllBuffer + imageExportDirectory->AddressOfNames);
	int *selectedIndexes = (int *)HeapAlloc(GetProcessHeap(), 0, numberOfDesiredFunctions *sizeof(int));
	if (selectedIndexes == NULL) {
		std::cout << "[!] Error on heap allocation !" << std::endl;
		return NULL;
	}
	std::set<int> indexes;
	while (indexes.size() < numberOfDesiredFunctions) {
		indexes.insert(GetRandomNumber(0,numberOfNames-1));
	}
	int indexCounter = 0;
	for (std::set<int>::iterator it = indexes.begin(); it != indexes.end(); ++it,indexCounter++) {
		selectedIndexes[indexCounter] = *it; // Note the "*" here
	}
	LPCSTR* returnValue = GetImportNamesFromIndex(dllBuffer,selectedIndexes,numberOfDesiredFunctions);
	HeapFree(GetProcessHeap(), MEM_RELEASE, dllBuffer);
	HeapFree(GetProcessHeap(), MEM_RELEASE, selectedIndexes);
	return returnValue;
}

PBYTE AddNewSection(PBYTE oldFileBuffer, uint64_t oldFileSize, uint64_t numberOfChunks, uint64_t& newFileSize) {
	PIMAGE_DOS_HEADER imageDosHeader;
	PIMAGE_NT_HEADERS imageNtHeader;
	PIMAGE_NT_HEADERS newImageNtHeader;
	IMAGE_NT_HEADERS backupNtHeader;
	DWORD dwExistingImportDescriptorEntryCount;
	DWORD dwNewImportDescriptorEntryCount;
	PIMAGE_IMPORT_DESCRIPTOR existingImportDescriptorAddr;
	PIMAGE_SECTION_HEADER sectionHeaderArray;
	PIMAGE_SECTION_HEADER newSectionHeaderArray;
	PBYTE newFileBuffer = NULL;
	imageDosHeader = (PIMAGE_DOS_HEADER)oldFileBuffer;
	imageNtHeader = (PIMAGE_NT_HEADERS)(oldFileBuffer + imageDosHeader->e_lfanew);
	sectionHeaderArray = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNtHeader) + sizeof(IMAGE_NT_HEADERS));
	uint64_t functionStringLengths = 0;
	// calculate existing number of imported dll modules
	dwExistingImportDescriptorEntryCount = imageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// Actually on my computer, it is just 1.
	if (dwExistingImportDescriptorEntryCount == 0){
		// the target process doesn't have any imported dll entries - 1 for last and 1 for new
		dwNewImportDescriptorEntryCount = 2;
	}
	else{
		// add one extra dll entry
		dwNewImportDescriptorEntryCount = dwExistingImportDescriptorEntryCount + 1;
	}
	nameArray = SelectDLLEntries(dllNames[0], numberOfChunks);
	if (nameArray == NULL) {
		std::cout << "[!] Error on reading DLL imports !" << std::endl;
		return NULL;
	}
	for (int i = 0; i < numberOfChunks; i++) {
		std::cout << nameArray[i] << std::endl;
		functionStringLengths += strlen(nameArray[i]);
		functionStringLengths++;
	}
	// Region for DLL Name + RVAs for Strings + ILT and IAT --> 2* NumberOfChunks+1 (+1 means null entry) * sizeof THUNK + Import Directory entries
	uint64_t totalLengthForSection = strlen(dllNames[0]) + 1 + functionStringLengths + sizeof(WORD) * numberOfChunks + 2 * (numberOfChunks + 1) * sizeof(IMAGE_THUNK_DATA) + dwNewImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	int numberOfSections = imageNtHeader->FileHeader.NumberOfSections;
	size_t newSectionOffset = sectionHeaderArray[numberOfSections - 1].PointerToRawData + sectionHeaderArray[numberOfSections - 1].SizeOfRawData;
	//Area after the last element in the section header array
	PIMAGE_SECTION_HEADER newSectionHeader = &sectionHeaderArray[numberOfSections];
	bool checkBoundary = ((PBYTE)newSectionHeader + sizeof(IMAGE_SECTION_HEADER) - oldFileBuffer) < sectionHeaderArray[0].PointerToRawData;
	if (checkBoundary) {
		memcpy(newSectionHeader->Name, ".rrdata", IMAGE_SIZEOF_SHORT_NAME);
		newSectionHeader->VirtualAddress = P2ALIGNUP(
			sectionHeaderArray[numberOfSections - 1].VirtualAddress + sectionHeaderArray[numberOfSections - 1].Misc.VirtualSize,
			imageNtHeader->OptionalHeader.SectionAlignment
		);
		//File alignment for PE File, same alignment problem but this is for disk
		newSectionHeader->SizeOfRawData = P2ALIGNUP(totalLengthForSection, imageNtHeader->OptionalHeader.FileAlignment);
		//Section alignment for memory
		newSectionHeader->Misc.VirtualSize = P2ALIGNUP((totalLengthForSection), imageNtHeader->OptionalHeader.SectionAlignment);
		newSectionHeader->Characteristics = 0xC0000040;
		//Offset for file
		newSectionHeader->PointerToRawData = newSectionOffset;
		// Section Alignment trick and put correct address wrt last section
		imageNtHeader->FileHeader.NumberOfSections += 1;
		//Now it has new section size
		newFileSize = P2ALIGNUP(totalLengthForSection, imageNtHeader->OptionalHeader.FileAlignment) + newSectionOffset;
		//New Section Offset is actually end of the file
		newFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, newFileSize);
		if (!newFileBuffer) {
			std::cout << ("[!] Failed to allocate new memory for the new file\n");
			return NULL;
		}
		// Copy until end of the NT Headers
		memcpy(newFileBuffer, oldFileBuffer, newSectionOffset);
		newImageNtHeader = (PIMAGE_NT_HEADERS)(newFileBuffer + imageDosHeader->e_lfanew);
		newSectionHeaderArray = (PIMAGE_SECTION_HEADER)(((PBYTE)newImageNtHeader) + sizeof(IMAGE_NT_HEADERS));
		newImageNtHeader->OptionalHeader.SizeOfImage =
			newSectionHeaderArray[newImageNtHeader->FileHeader.NumberOfSections - 1].VirtualAddress +
			newSectionHeaderArray[newImageNtHeader->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
	}
	else {
		std::cout << "[!] No room left for new section header array !" << std::endl;
	}
	return newFileBuffer;
}


void AddNewImportEntry(PBYTE fileBuffer,PWORD hintArray,uint64_t numberOfChunks) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeaderArray = (PIMAGE_SECTION_HEADER)(((PBYTE)ntHeaders) + sizeof(IMAGE_NT_HEADERS));
	PBYTE sectionStart = fileBuffer + sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].PointerToRawData;
	PIMAGE_THUNK_DATA ImportLookupTable = (PIMAGE_THUNK_DATA)HeapAlloc(GetProcessHeap(), 0, sizeof(IMAGE_THUNK_DATA) * (numberOfChunks + 1));
	IMAGE_IMPORT_DESCRIPTOR newDllImportDescriptors[2];
	PIMAGE_IMPORT_DESCRIPTOR oldDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuffer + Rva2Offset(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, fileBuffer));
	DWORD dwExistingImportDescriptorEntryCount = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD dwNewImportDescriptorEntryCount = 0;
	uint64_t functionStringLengths = 0;
	for (int i = 0; i < numberOfChunks; i++) {
		functionStringLengths += strlen(nameArray[i]);
		functionStringLengths++;
	}
	if (dwExistingImportDescriptorEntryCount == 0)
	{
		// the target process doesn't have any imported dll entries - 1 for last and 1 for new
		dwNewImportDescriptorEntryCount = 2;
	}
	else
	{
		// add one extra dll entry
		dwNewImportDescriptorEntryCount = dwExistingImportDescriptorEntryCount + 1;
	}
	DWORD dwNewImportDescriptorListDataLength = dwNewImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	PBYTE freeMemoryStartAfterDir = sectionStart + dwNewImportDescriptorListDataLength;
	PBYTE freeMemoryStartAfterString = freeMemoryStartAfterDir + strlen(dllNames[0]) + functionStringLengths + 1 + sizeof(WORD) * numberOfChunks;
	memset(freeMemoryStartAfterDir, 0x00, strlen(dllNames[0]) + functionStringLengths + 1 + sizeof(WORD) * numberOfChunks);
	memcpy(freeMemoryStartAfterDir, dllNames[0], strlen(dllNames[0]));
	// Put shellcodes
	PIMAGE_IMPORT_BY_NAME hintNameEntries = (PIMAGE_IMPORT_BY_NAME)(freeMemoryStartAfterDir + strlen(dllNames[0])+1);
	for (int i = 0, offset = 2; i < numberOfChunks; i++) {
		memcpy(&hintNameEntries->Hint, &hintArray[i], sizeof(WORD));
		memcpy(&hintNameEntries->Name , nameArray[i], strlen(nameArray[i]));
		//offset = offset + strlen(flagValues[i]) + 1 + sizeof(WORD);
		hintNameEntries = (PIMAGE_IMPORT_BY_NAME)(((PBYTE)hintNameEntries) + sizeof(WORD) + strlen(nameArray[i])+1);
	}

	PBYTE thunkAddress = freeMemoryStartAfterDir + strlen(dllNames[0]) + 1;
	DWORD sectionStartOffset = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].PointerToRawData;
	DWORD sectionRVA = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress;

	// set import lookup table values (import ordinal #1)
	// last one
	ImportLookupTable[numberOfChunks].u1.AddressOfData = 0;
	ImportLookupTable[0].u1.AddressOfData = (sectionRVA - sectionStartOffset + (thunkAddress - fileBuffer));
	uint64_t cursorOffset = 0;
	for (int i = 1; i < numberOfChunks; i++) {
		cursorOffset = cursorOffset + sizeof(WORD) + strlen(nameArray[i - 1]) + 1;
		ImportLookupTable[i].u1.AddressOfData = (DWORD)(sectionRVA - sectionStartOffset + (thunkAddress + cursorOffset - fileBuffer));
	}
	memcpy(freeMemoryStartAfterString, ImportLookupTable, sizeof(IMAGE_THUNK_DATA) * (numberOfChunks + 1));
	memcpy(freeMemoryStartAfterString + sizeof(IMAGE_THUNK_DATA) * (numberOfChunks + 1), ImportLookupTable, sizeof(IMAGE_THUNK_DATA) * (numberOfChunks + 1));
	memcpy(sectionStart, oldDirectory, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	// We need one for Import Lookup Table, one for Import Address Table - OriginalFirstThunk and FirstThunk
	// set import descriptor values for injected dll
	newDllImportDescriptors[0].OriginalFirstThunk = (DWORD)(freeMemoryStartAfterString - fileBuffer - sectionStartOffset + sectionRVA);
	newDllImportDescriptors[0].TimeDateStamp = 0;
	newDllImportDescriptors[0].ForwarderChain = 0;
	newDllImportDescriptors[0].Name = (DWORD)(freeMemoryStartAfterDir - fileBuffer - sectionStartOffset + sectionRVA);
	newDllImportDescriptors[0].FirstThunk = (DWORD)(freeMemoryStartAfterString - fileBuffer - sectionStartOffset + sectionRVA + sizeof(IMAGE_THUNK_DATA) * (numberOfChunks + 1));

	// end of import descriptor chain
	newDllImportDescriptors[1].OriginalFirstThunk = 0;
	newDllImportDescriptors[1].TimeDateStamp = 0;
	newDllImportDescriptors[1].ForwarderChain = 0;
	newDllImportDescriptors[1].Name = 0;
	newDllImportDescriptors[1].FirstThunk = 0;
	memcpy(sectionStart + dwNewImportDescriptorListDataLength - sizeof(newDllImportDescriptors), newDllImportDescriptors, sizeof(newDllImportDescriptors));
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress;
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwNewImportDescriptorListDataLength;
	
}
