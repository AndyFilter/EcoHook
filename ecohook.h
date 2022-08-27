#pragma once

#include <Windows.h>

namespace Hook
{
	bool HookFunc(LPVOID targetFunc, LPVOID detourFunc, LPVOID* originalFunc, unsigned int len);

	//typedef bool CustomWriteMemFunc(LPVOID lpAddress, LPVOID lpData, size_t size, SIZE_T* lpBytesWritten);
	typedef bool CustomRWFunc(LPVOID, LPVOID, size_t, SIZE_T*);

	inline CustomRWFunc* CustomWriteMem;
	inline CustomRWFunc* CustomReadMem;

	inline bool isPriviliged = false;
}