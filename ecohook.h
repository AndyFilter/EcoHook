#pragma once

#include <Windows.h>

/*

ToDo:
- Add unhooking functionality... cuh...

*/

namespace Hook
{
	bool HookFunc(LPVOID targetFunc, LPVOID detourFunc, LPVOID* originalFunc, unsigned int len);
	bool UnHookFunc(LPVOID targetFunc);

	//typedef bool CustomWriteMemFunc(LPVOID lpAddress, LPVOID lpData, size_t size, SIZE_T* lpBytesWritten);
	typedef bool CustomRWFunc(LPVOID, LPVOID, size_t, SIZE_T*);

	inline CustomRWFunc* CustomWriteMem;
	inline CustomRWFunc* CustomReadMem;

	inline bool isPriviliged = false;
}