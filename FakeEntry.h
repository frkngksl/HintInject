#pragma once
PBYTE AddNewSection(PBYTE oldFileBuffer, uint64_t oldFileSize, uint64_t numberOfChunks, uint64_t& newFileSize);
void AddNewImportEntry(PBYTE fileBuffer);