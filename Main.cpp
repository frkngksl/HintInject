#include <Windows.h>
#include <iostream>
#include <time.h>
#include "Utils.h"
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
	std::cout << "[+] Usage: " << exeName << "<Shellcode File> <Output Name>";
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
	return 0;
}