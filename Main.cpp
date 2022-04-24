#include <Windows.h>
#include <iostream>


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
	return 0;
}