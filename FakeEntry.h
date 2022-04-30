#pragma once
PBYTE AddNewSection(PBYTE oldFileBuffer, uint64_t oldFileSize, uint64_t numberOfChunks, uint64_t& newFileSize);
bool AddNewImportEntry(PBYTE fileBuffer, PWORD hintArray, uint64_t numberOfChunks);