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
	sprintf_s(removedDir2, "%sHintInject\\x64\\", SOLUTIONDIR);
	if (DirectoryExists(removedDir1)) {
		DeleteDirectory(removedDir1);
	}
	if (DirectoryExists(removedDir2)) {
		DeleteDirectory(removedDir2);
	}
}

char* CompileLoader() {
	ClearDirectory();
	LPCSTR vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[MAX_PATH] = { 0 };
		char loaderBinaryPath[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			sprintf_s(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\HintInject.sln /t:HintInjectLoader /property:Configuration=JustLoader /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
			sprintf_s(loaderBinaryPath, "%sx64\\JustLoader\\HintInjectLoader.exe", SOLUTIONDIR);
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
	HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cout << ("Failed to open the file\n");
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