#include <string>
#include <iostream>
#include <string.h>

#include "ecohook.h"

using namespace Hook;

#if defined(_M_X64) || defined(__x86_64__)
const bool is_x86 = false;
#else
const bool is_x86 = true;
#endif

// Requires at least PROCESS_VM_READ on the funcAddress of size 5
LPVOID GetRealFunctionAddress(LPVOID funcAddress)
{
    byte codeBuffer[6]{ 0 };
    bool succ = false;
    if (Hook::CustomReadMem)
        succ = Hook::CustomReadMem(funcAddress, codeBuffer, sizeof(codeBuffer), NULL);
    else
        succ = ReadProcessMemory(GetCurrentProcess(), funcAddress, codeBuffer, sizeof(codeBuffer), NULL);

    if (!succ)
        return nullptr;

    uint32_t funcOffset = 0x0;

    // This is only a list of functions, that contains a jmp (E9) instruction to the correct function's definition
    if (codeBuffer[0] == 0xE9 && codeBuffer[5] == 0xE9)
    {
        memcpy(&funcOffset, codeBuffer + 1, sizeof(int));

        printf("Func offset is: 0x%04x\n", funcOffset);

        uint64_t finalFuncAddy = (funcOffset + (uint64_t)funcAddress + 5);

        printf("End Func at: 0x%p\n", (void*)finalFuncAddy);
        //printf("End Func at: 0x%I64X\n", finalFuncAddy);

        return (LPVOID)finalFuncAddy;
    }

    return funcAddress;
}

int SearchByteArray(byte* src, byte* pattern, size_t srcLen, size_t patternLen, int* foundOffsets, int startingIndex = 0, int byteOffset = 0)
{
    int foundPatterns = 0;
    int maxFirstCharSlot = srcLen - patternLen + 1;
    for (int i = 0; i < maxFirstCharSlot; i++)
    {
        if (src[i] != pattern[0]) // compare only first byte
            continue;

        // found a match on first byte, now try to match rest of the detourPattern
        for (int j = patternLen - 1; j >= 1; j--)
        {
            if (src[i + j] != pattern[j]) break;
            if (j == 1)
            {
                foundOffsets[foundPatterns + startingIndex] = i + byteOffset;
                foundPatterns++;
                i += patternLen - 1;
                break;
            }
        }
    }
    return foundPatterns;
}

// Argument len has to be at least 5
bool Hook::HookFunc(LPVOID targetFunc, LPVOID detourFunc, LPVOID* originalFunc, unsigned int len)
{
    if (len < 5)
        return false;

    // If there is no available space in 0xFFFF range -> give up
    const size_t ReadSize = 0xFFFF;
    const size_t ChunkSize = 0xFF;

    const int detourMaxSpaces = 4;
    const int trampolineMaxSpaces = 10;

    DWORD prot = 0, tempProt = 0;

#ifdef _DEBUG

    if (CustomWriteMem)
        printf("Using a custom Write Func\n");
    else
        printf("Custom func: 0x%p\n", CustomWriteMem);

#endif // _DEBUG

    auto realTgAddress = is_x86 ? targetFunc : GetRealFunctionAddress(targetFunc);

    if (realTgAddress == nullptr)
        return false;

#ifdef _DEBUG
    printf("Real Target address: 0x%p\n", realTgAddress);
#endif

    // Make the memory around the target function readable
    if (!isPriviliged)
    {
        VirtualProtect((LPVOID)((uint64_t)realTgAddress - (ReadSize / 2)), ReadSize + 1, PAGE_EXECUTE_READWRITE, &prot);
    }

    BYTE* startInstructions = new BYTE[len];
    ZeroMemory(startInstructions, len);
    bool readStatus = false;
    if (CustomReadMem)
        readStatus = CustomReadMem(realTgAddress, startInstructions, len, NULL);
    else
        readStatus = ReadProcessMemory(GetCurrentProcess(), realTgAddress, startInstructions, len, NULL);

    if (!readStatus)
        return false;

#ifdef _DEBUG
    printf("Default instructions: 0x%1X, 0x%1X, 0x%1X, 0x%1X, 0x%1X\n", startInstructions[0], startInstructions[1], startInstructions[2], startInstructions[3], startInstructions[4]);
#endif

    const size_t detourPatternSize = is_x86 ? 5 : 14;
    // Changing the first byte to 0xC3 (ret) might not be a bad idea
    BYTE detourPattern[] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };

    int foundOffsets[ChunkSize / detourPatternSize]{ -1 };
    int possibleSpaces = 0;

    size_t trampolinePatternSize = 5 + len;
    // Changing the first byte to 0xC3 (ret) might not be a bad idea
    BYTE trampolinePattern[] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };

    int* foundTrampolineOffsets = new int[ReadSize / trampolinePatternSize];
    int possibleTrampolineSpaces = 0;

    int scanIndex = 1;

    // Issue here is that the Read can end at 0xCC in which case it will split it in half not really getting it's real size. But we can just use a buffer of twice the size and just add 2 reads
    // This code just looks for available spaces in the neighbouring chunks.
    while ((!(possibleSpaces >= detourMaxSpaces) || !(possibleTrampolineSpaces >= trampolineMaxSpaces)) && (scanIndex * ChunkSize) < ReadSize)
    {
        // how far away from the target function are we going to look for
        auto positiveByteOffset = (scanIndex - 1) * ChunkSize;

        BYTE spaceBufferDown[ChunkSize]{ 0 };
        SIZE_T bytesReadDown = 0;
        if (CustomReadMem)
            readStatus = CustomReadMem((void*)((uint64_t)realTgAddress + positiveByteOffset), spaceBufferDown, ChunkSize, &bytesReadDown);
        else
        ReadProcessMemory(GetCurrentProcess(), (void*)((uint64_t)realTgAddress + positiveByteOffset), spaceBufferDown, ChunkSize, &bytesReadDown);

        BYTE spaceBufferUp[ChunkSize]{ 0 };
        SIZE_T bytesReadUp = 0;
        if (CustomReadMem)
            readStatus = CustomReadMem((void*)((uint64_t)realTgAddress - (positiveByteOffset + ChunkSize)), spaceBufferUp, ChunkSize, &bytesReadUp);
        else
        ReadProcessMemory(GetCurrentProcess(), (void*)((uint64_t)realTgAddress - (positiveByteOffset + ChunkSize)), spaceBufferUp, ChunkSize, &bytesReadUp);

        // find empty space for detour
        if (possibleSpaces < detourMaxSpaces)
        {
            possibleSpaces += SearchByteArray(spaceBufferDown, detourPattern, ChunkSize, detourPatternSize, foundOffsets, possibleSpaces, positiveByteOffset);
            possibleSpaces += SearchByteArray(spaceBufferUp, detourPattern, ChunkSize, detourPatternSize, foundOffsets, possibleSpaces, (positiveByteOffset + ChunkSize) * -1);
        }

        // find empty space for trampoline
        if (possibleTrampolineSpaces < trampolineMaxSpaces)
        {
            possibleTrampolineSpaces += SearchByteArray(spaceBufferDown, trampolinePattern, ChunkSize, trampolinePatternSize, foundTrampolineOffsets, possibleTrampolineSpaces, positiveByteOffset);
            possibleTrampolineSpaces += SearchByteArray(spaceBufferUp, trampolinePattern, ChunkSize, trampolinePatternSize, foundTrampolineOffsets, possibleTrampolineSpaces, (positiveByteOffset + ChunkSize) * -1);
        }

        scanIndex++;
    }

#ifdef _DEBUG
    for (int i = 0; i < possibleSpaces; i++)
    {
        printf("Found free detour space at: 0x%p (%i), index: %i\n", (void*)((uint64_t)realTgAddress + foundOffsets[i]), foundOffsets[i], i);
    }

    for (int i = 0; i < possibleTrampolineSpaces; i++)
    {
        printf("Found free tramp space at: 0x%p (%i), index: %i\n", (void*)((uint64_t)realTgAddress + foundTrampolineOffsets[i]), foundTrampolineOffsets[i], i);
    }
#endif

    // We need to jmp 2 functions: detour and the new original (+5), so we need at least 2 free places to put them
    if (possibleSpaces >= detourMaxSpaces && possibleTrampolineSpaces >= trampolineMaxSpaces)
    {
#ifdef _DEBUG
        printf("Space found, detours: %i, trampoline: %i\n", possibleSpaces, possibleTrampolineSpaces);
#endif

        // randomize index of foundOffsets :imp: and make sure that foundOffsets is not the same as foundTrampolineOffsets
        auto detourSpaceAddy = (void*)((uint64_t)realTgAddress + (foundOffsets[0]));
        auto originalStartSpaceAddy = (void*)0; // Place where to put the original n bytes of the function + jmp to the rest
        for (int i = 0; i < possibleTrampolineSpaces; i++)
        {
            if (abs(foundOffsets[0] - foundTrampolineOffsets[i]) > 16)
            {
                originalStartSpaceAddy = (void*)((uint64_t)realTgAddress + (foundTrampolineOffsets[i]));
                break;
            }
        }

        if (originalStartSpaceAddy == 0)
            goto CleanUp; // Exit Should return false

#ifdef _DEBUG
        printf("Selected Original Space Addy: 0x%p\n", originalStartSpaceAddy);
#endif

#if defined(_M_X64) || defined(__x86_64__)

        BYTE detour_shell_code[] = { 0xFF, 0x25, 0x00 , 0x00 , 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        // 0xFF is JMP, 0x25 (0b00100101) is a MOD R/M to get 0xFF/5, which is absolute, far indirect jump. (https://www.felixcloutier.com/x86/jmp). 5 - 0101

        auto toHookAddy = (uint64_t)detourFunc;
        memcpy(detour_shell_code + 6, &toHookAddy, sizeof(void*));

        if (CustomWriteMem)
            CustomWriteMem(detourSpaceAddy, detourSpaceAddy, sizeof(detour_shell_code), NULL);
        else
            WriteProcessMemory(GetCurrentProcess(), detourSpaceAddy, detour_shell_code, sizeof(detour_shell_code), NULL);


        BYTE* original_shell_code = new BYTE[trampolinePatternSize];
        memset(original_shell_code, 0x90, trampolinePatternSize);
        original_shell_code[len] = 0xE9;

        memcpy(original_shell_code, startInstructions, len);

        int hookedJmpRelativeAddy = ((uint64_t)realTgAddress) - (uint64_t)originalStartSpaceAddy - len;
        memcpy(original_shell_code + len + 1, &hookedJmpRelativeAddy, sizeof(int));
        // original_shell_code should now be equal to original {len} bytes of the target function + 0xE9 (JMP) + relative address (from the current addy)
        // of the continuation of the target function (realTgAddress + len). You call this addy when u want to call the original function as a whole

#ifdef _DEBUG
        printf("jmp Relative addy : 0x%4X\n", hookedJmpRelativeAddy);
#endif

        if (CustomWriteMem)
            CustomWriteMem(originalStartSpaceAddy, original_shell_code, trampolinePatternSize, NULL);
        else
            WriteProcessMemory(GetCurrentProcess(), originalStartSpaceAddy, original_shell_code, trampolinePatternSize, NULL);


        BYTE* trampoline_shell_code = new BYTE[len]; // relative JMP to the code that jumps to our function 
        memset(trampoline_shell_code, 0x90, len); // fill it with 0x90 (NOP) - no operation, so that if the just is shorter than len, it will just do nothing.
        trampoline_shell_code[0] = 0xE9;

        int relativeAddress = (uint64_t)detourSpaceAddy - ((uint64_t)realTgAddress) - len;

#ifdef _DEBUG
        printf("Relative addy : 0x%4X\n", relativeAddress);
#endif

        memcpy(trampoline_shell_code + 1, &relativeAddress, sizeof(int));

#ifdef _DEBUG
        printf("Trampoline hook: 0x%1X, 0x%1X, 0x%1X, 0x%1X, 0x%1X\n", trampoline_shell_code[0], trampoline_shell_code[1], trampoline_shell_code[2], trampoline_shell_code[3], trampoline_shell_code[4]);
#endif

        if (CustomWriteMem)
            CustomWriteMem(realTgAddress, trampoline_shell_code, len, NULL);
        else
            WriteProcessMemory(GetCurrentProcess(), realTgAddress, trampoline_shell_code, len, NULL);


        *originalFunc = originalStartSpaceAddy;

        delete[] trampoline_shell_code;
        delete[] original_shell_code;
#else

        BYTE* original_shell_code = new BYTE[trampolinePatternSize];
        memset(original_shell_code, 0x90, trampolinePatternSize);
        original_shell_code[len] = 0xE9;

        memcpy(original_shell_code, startInstructions, len);

        int hookedJmpRelativeAddy = ((uint64_t)realTgAddress) - (uint64_t)originalStartSpaceAddy - 5;
        memcpy(original_shell_code + len + 1, &hookedJmpRelativeAddy, sizeof(int));

#ifdef _DEBUG
        printf("jmp Relative addy : 0x%4X\n", hookedJmpRelativeAddy);
#endif

        if (CustomWriteMem)
            CustomWriteMem(originalStartSpaceAddy, original_shell_code, trampolinePatternSize, NULL);
        else
            WriteProcessMemory(GetCurrentProcess(), originalStartSpaceAddy, original_shell_code, trampolinePatternSize, NULL);


        BYTE* trampoline_shell_code = new BYTE[len];
        memset(trampoline_shell_code, 0x90, len);
        trampoline_shell_code[0] = 0xE9;

        int relativeAddress = (uint64_t)detourFunc - ((uint64_t)realTgAddress) - 5;

#ifdef _DEBUG
        printf("Relative addy : 0x%4X\n", relativeAddress);
#endif

        memcpy(trampoline_shell_code + 1, &relativeAddress, sizeof(int));

#ifdef _DEBUG
        printf("Trampoline hook: 0x%1X, 0x%1X, 0x%1X, 0x%1X, 0x%1X\n", trampoline_shell_code[0], trampoline_shell_code[1], trampoline_shell_code[2], trampoline_shell_code[3], trampoline_shell_code[4]);
#endif

        if (CustomWriteMem)
            CustomWriteMem(realTgAddress, trampoline_shell_code, len, NULL);
        else
            WriteProcessMemory(GetCurrentProcess(), realTgAddress, trampoline_shell_code, len, NULL);


        *originalFunc = originalStartSpaceAddy;

        delete[] trampoline_shell_code;
        delete[] original_shell_code;
#endif
    }
    else
    {
#ifdef _DEBUG
        printf("Not enough Space, detours: %i, original: %i\n", possibleSpaces, possibleTrampolineSpaces);

        if (!isPriviliged)
        {
            VirtualProtect((LPVOID)((uint64_t)realTgAddress - (ReadSize / 2)), ReadSize + 1, prot, &tempProt);
        }

        delete[] startInstructions;
        delete[] foundTrampolineOffsets;

        return false;
#endif
    }

    // As the name suggests, Clean-up
CleanUp:

    if (!isPriviliged)
    {
        VirtualProtect((LPVOID)((uint64_t)realTgAddress - (ReadSize / 2)), ReadSize + 1, prot, &tempProt);
    }

    delete[] startInstructions;
    delete[] foundTrampolineOffsets;

    return true;
}
