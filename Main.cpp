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
	std::cout << "Usage: " << exeName << "<Shellcode File> <Output Name>";
}


int main(int argc, char* argv[]) {
	PrintBanner();
	if (argc != 3) {
		PrintHelp(argv[0]);
		return -1;
	}
	srand(time(NULL));
	size_t fileSize = 0;
	PBYTE shellcodeContent = ReadFileFromDisk(argv[1], fileSize);
	if (shellcodeContent == NULL || fileSize == 0) {
		std::cout << "[!] Error on reading the exe file !" << std::endl;
		return 0;
	}
	std::cout << CompileLoader() << std::endl;
	return 0;
}