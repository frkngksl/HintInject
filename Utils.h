#pragma once
char* CompileLoader();
PBYTE ReadFileFromDisk(LPCSTR fileName, uint64_t& fileSize);
PBYTE SplitShellcode(PBYTE shellcodeBuffer, uint64_t sizeOfShellcode, uint64_t& numberOfChunks);
int GetRandomNumber(int min, int max);
bool WriteNewPE(LPCSTR fileName, PBYTE buffer, uint64_t size);