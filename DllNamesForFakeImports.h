#pragma once
// I added these for the fake entries. If your shellcode is bigger than the size that those dlls provide, you can add it to this list.
static LPCSTR dllNames[] = {"user32.dll","advapi32.dll","gdi32.dll","wininet.dll","comctl32.dll","shell32.dll","wsock32.dll","oleaut32.dll","ws2_32.dll","urlmon.dll"};
static int numberOfDllNames = sizeof(dllNames) / sizeof(LPCSTR);