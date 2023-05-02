#include <Windows.h>

#include <cstdio>

#include "oneapi/tbb/scalable_allocator.h"

typedef enum {
    FRR_OK,     /* Succeeded in replacing the function */
    FRR_NODLL,  /* The requested DLL was not found */
    FRR_NOFUNC, /* The requested function was not found */
    FRR_FAILED, /* The function replacement request failed */
} FRR_TYPE;

typedef enum {
    FRR_FAIL,     /* Required function */
    FRR_IGNORE,   /* optional function */
} FRR_ON_ERROR;

typedef void (*FUNCPTR)();

// The information about a standard memory allocation function for the replacement log
struct FunctionInfo {
    const char* funcName;
    const char* dllName;
};

union Int2Ptr {
    UINT_PTR uip;
    LPVOID lpv;
};

inline UINT_PTR Ptr2Addrint(LPVOID ptr);
inline LPVOID Addrint2Ptr(UINT_PTR ptr);

// The size of a trampoline region
const unsigned MAX_PROBE_SIZE = 32;

// The size of a jump relative instruction "e9 00 00 00 00"
const unsigned SIZE_OF_RELJUMP = 5;

// The size of jump RIP relative indirect "ff 25 00 00 00 00"
const unsigned SIZE_OF_INDJUMP = 6;

// The size of address we put in the location (in Intel64)
const unsigned SIZE_OF_ADDRESS = 8;

// The size limit (in bytes) for an opcode pattern to fit into a trampoline
// There should be enough space left for a relative jump; +1 is for the extra pattern byte.
const unsigned MAX_PATTERN_SIZE = MAX_PROBE_SIZE - SIZE_OF_RELJUMP + 1;

// The max distance covered in 32 bits: 2^31 - 1 - C
// where C should not be smaller than the size of a probe.
// The latter is important to correctly handle "backward" jumps.
const __int64 MAX_DISTANCE = (((__int64)1 << 31) - 1) - MAX_PROBE_SIZE;

// The maximum number of distinct buffers in memory
const ptrdiff_t MAX_NUM_BUFFERS = 256;

inline UINT_PTR Ptr2Addrint(LPVOID ptr)
{
    Int2Ptr i2p;
    i2p.lpv = ptr;
    return i2p.uip;
}

inline LPVOID Addrint2Ptr(UINT_PTR ptr)
{
    Int2Ptr i2p;
    i2p.uip = ptr;
    return i2p.lpv;
}

// Is the distance between addr1 and addr2 smaller than dist
inline bool IsInDistance(UINT_PTR addr1, UINT_PTR addr2, __int64 dist)
{
    __int64 diff = addr1>addr2 ? addr1-addr2 : addr2-addr1;
    return diff<dist;
}


// Modify offsets in original code after moving it to a trampoline.
// We do not have more than one offset to correct in existing opcode patterns.
static void CorrectOffset( UINT_PTR address, const char* pattern, UINT distance )
{
    const char* pos = strstr(pattern, "#*******");
    if( pos ) {
        address += (pos - pattern)/2; // compute the offset position
        UINT value;
        // UINT assignment is not used to avoid potential alignment issues
        memcpy(&value, Addrint2Ptr(address), sizeof(value));
        value += distance;
        memcpy(Addrint2Ptr(address), &value, sizeof(value));
    }
}

/*
 * When inserting a probe in 64 bits process the distance between the insertion
 * point and the target may be bigger than 2^32. In this case we are using
 * indirect jump through memory where the offset to this memory location
 * is smaller than 2^32 and it contains the absolute address (8 bytes).
 *
 * This class is used to hold the pages used for the above trampolines.
 * Since this utility will be used to replace malloc functions this implementation
 * doesn't allocate memory dynamically.
 *
 * The struct MemoryBuffer holds the data about a page in the memory used for
 * replacing functions in 64-bit code where the target is too far to be replaced
 * with a short jump. All the calculations of m_base and m_next are in a multiple
 * of SIZE_OF_ADDRESS (which is 8 in Win64).
 */
class MemoryProvider {
private:
    struct MemoryBuffer {
        UINT_PTR m_base;    // base address of the buffer
        UINT_PTR m_next;    // next free location in the buffer
        DWORD    m_size;    // size of buffer

        // Default constructor
        MemoryBuffer() : m_base(0), m_next(0), m_size(0) {}

        // Constructor
        MemoryBuffer(void *base, DWORD size)
        {
            m_base = Ptr2Addrint(base);
            m_next = m_base;
            m_size = size;
        }
    };

MemoryBuffer *CreateBuffer(UINT_PTR addr)
    {
        // No more room in the pages database
        if (m_lastBuffer - m_pages == MAX_NUM_BUFFERS)
            return 0;

        void *newAddr = Addrint2Ptr(addr);
        // Get information for the region which the given address belongs to
        MEMORY_BASIC_INFORMATION memInfo;
        if (VirtualQuery(newAddr, &memInfo, sizeof(memInfo)) != sizeof(memInfo))
            return 0;

        for(;;) {
            // The new address to check is beyond the current region and aligned to allocation size
            newAddr = Addrint2Ptr( (Ptr2Addrint(memInfo.BaseAddress) + memInfo.RegionSize + m_allocSize) & ~(UINT_PTR)(m_allocSize-1) );

            // Check that the address is in the right distance.
            // VirtualAlloc can only round the address down; so it will remain in the right distance
            if (!IsInDistance(addr, Ptr2Addrint(newAddr), MAX_DISTANCE))
                break;

            if (VirtualQuery(newAddr, &memInfo, sizeof(memInfo)) != sizeof(memInfo))
                break;

            if (memInfo.State == MEM_FREE && memInfo.RegionSize >= m_allocSize)
            {
                // Found a free region, try to allocate a page in this region
                void *newPage = VirtualAlloc(newAddr, m_allocSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                if (!newPage)
                    break;

                // Add the new page to the pages database
                MemoryBuffer *pBuff = new (m_lastBuffer) MemoryBuffer(newPage, m_allocSize);
                ++m_lastBuffer;
                return pBuff;
            }
        }

        // Failed to find a buffer in the distance
        return 0;
    }

public:
    MemoryProvider()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_allocSize = sysInfo.dwAllocationGranularity;
        m_lastBuffer = &m_pages[0];
    }

    // We can't free the pages in the destructor because the trampolines
    // are using these memory locations and a replaced function might be called
    // after the destructor was called.
    ~MemoryProvider()
    {
    }

    // Return a memory location in distance less than 2^31 from input address
    UINT_PTR GetLocation(UINT_PTR addr)
    {
        MemoryBuffer *pBuff = m_pages;
        for (; pBuff<m_lastBuffer && IsInDistance(pBuff->m_next, addr, MAX_DISTANCE); ++pBuff)
        {
            if (pBuff->m_next < pBuff->m_base + pBuff->m_size)
            {
                UINT_PTR loc = pBuff->m_next;
                pBuff->m_next += MAX_PROBE_SIZE;
                return loc;
            }
        }

        pBuff = CreateBuffer(addr);
        if(!pBuff)
            return 0;

        UINT_PTR loc = pBuff->m_next;
        pBuff->m_next += MAX_PROBE_SIZE;
        return loc;
    }

private:
    MemoryBuffer m_pages[MAX_NUM_BUFFERS];
    MemoryBuffer *m_lastBuffer;
    DWORD m_allocSize;
};

static MemoryProvider memProvider;

// Compare opcodes from dictionary (str1) and opcodes from code (str2)
// str1 might contain '*' to mask addresses
// RETURN: 0 if opcodes did not match, 1 on success
static size_t compareStrings( const char *str1, const char *str2 )
{
   for (size_t i=0; str1[i]!=0; i++){
       if( str1[i]!='*' && str1[i]!='#' && str1[i]!=str2[i] ) return 0;
   }
   return 1;
}

// Check function prologue with known prologues from the dictionary
// opcodes - dictionary
// inpAddr - pointer to function prologue
// Dictionary contains opcodes for several full asm instructions
// + one opcode byte for the next asm instruction for safe address processing
// RETURN: 1 + the index of the matched pattern, or 0 if no match found.
static UINT CheckOpcodes( const char ** opcodes, void *inpAddr, bool abortOnError, const FunctionInfo* functionInfo = nullptr)
{
    static size_t opcodesStringsCount = 0;
    static size_t maxOpcodesLength = 0;
    static size_t opcodes_pointer = (size_t)opcodes;
    char opcodeString[2*MAX_PATTERN_SIZE+1];
    size_t i;
    size_t result = 0;

    // Get the values for static variables
    // max length and number of patterns
    if( !opcodesStringsCount || opcodes_pointer != (size_t)opcodes ){
        while( *(opcodes + opcodesStringsCount)!= nullptr ){
            if( (i=strlen(*(opcodes + opcodesStringsCount))) > maxOpcodesLength )
                maxOpcodesLength = i;
            opcodesStringsCount++;
        }
        opcodes_pointer = (size_t)opcodes;
        __TBB_ASSERT( maxOpcodesLength/2 <= MAX_PATTERN_SIZE, "Pattern exceeded the limit of 28 opcodes/56 symbols" );
    }

    // Translate prologue opcodes to string format to compare
    for( i=0; i<maxOpcodesLength/2 && i<MAX_PATTERN_SIZE; ++i ){
        sprintf( opcodeString + 2*i, "%.2X", *((unsigned char*)inpAddr+i) );
    }
    opcodeString[2*i] = 0;

    // Compare translated opcodes with patterns
    for( UINT idx=0; idx<opcodesStringsCount; ++idx ){
        result = compareStrings( opcodes[idx],opcodeString );
        if( result ) {
            if (functionInfo) {
//                Log::record(*functionInfo, opcodeString, /*status*/ true);
            }
            return idx + 1; // avoid 0 which indicates a failure
        }
    }
    if (functionInfo) {
//        Log::record(*functionInfo, opcodeString, /*status*/ false);
    }
    if (abortOnError) {
        // Impossibility to find opcodes in the dictionary is a serious issue,
        // as if we unable to call original function, leak or crash is expected result.
        __TBB_ASSERT_RELEASE( false, "CheckOpcodes failed" );
    }
    return 0;
}

// Insert jump relative instruction to the input address
// RETURN: the size of the trampoline or 0 on failure
static DWORD InsertTrampoline32(void *inpAddr, void *targetAddr, const char* pattern, void** storedAddr)
{
    size_t bytesToMove = SIZE_OF_RELJUMP;
    UINT_PTR srcAddr = Ptr2Addrint(inpAddr);
    UINT_PTR tgtAddr = Ptr2Addrint(targetAddr);
    // Check that the target fits in 32 bits
    if (!IsInDistance(srcAddr, tgtAddr, MAX_DISTANCE))
        return 0;

    UINT_PTR offset;
    UINT offset32;
    UCHAR *codePtr = (UCHAR *)inpAddr;

    if ( storedAddr ){ // If requested, store original function code
        bytesToMove = strlen(pattern)/2-1; // The last byte matching the pattern must not be copied
        __TBB_ASSERT_RELEASE( bytesToMove >= SIZE_OF_RELJUMP, "Incorrect bytecode pattern?" );
        UINT_PTR trampAddr = memProvider.GetLocation(srcAddr);
        if (!trampAddr)
            return 0;
        *storedAddr = Addrint2Ptr(trampAddr);
        // Set 'executable' flag for original instructions in the new place
        DWORD pageFlags = PAGE_EXECUTE_READWRITE;
        if (!VirtualProtect(*storedAddr, MAX_PROBE_SIZE, pageFlags, &pageFlags)) return 0;
        // Copy original instructions to the new place
        memcpy(*storedAddr, codePtr, bytesToMove);
        offset = srcAddr - trampAddr;
        offset32 = (UINT)(offset & 0xFFFFFFFF);
        CorrectOffset( trampAddr, pattern, offset32 );
        // Set jump to the code after replacement
        offset32 -= SIZE_OF_RELJUMP;
        *(UCHAR*)(trampAddr+bytesToMove) = 0xE9;
        memcpy((UCHAR*)(trampAddr+bytesToMove+1), &offset32, sizeof(offset32));
    }

    // The following will work correctly even if srcAddr>tgtAddr, as long as
    // address difference is less than 2^31, which is guaranteed by IsInDistance.
    offset = tgtAddr - srcAddr - SIZE_OF_RELJUMP;
    offset32 = (UINT)(offset & 0xFFFFFFFF);
    // Insert the jump to the new code
    *codePtr = 0xE9;
    memcpy(codePtr+1, &offset32, sizeof(offset32));

    // Fill the rest with NOPs to correctly see disassembler of old code in debugger.
    for( unsigned i=SIZE_OF_RELJUMP; i<bytesToMove; i++ ){
        *(codePtr+i) = 0x90;
    }

    return SIZE_OF_RELJUMP;
}

// This function is called when the offset doesn't fit in 32 bits
// 1  Find and allocate a page in the small distance (<2^31) from input address
// 2  Put jump RIP relative indirect through the address in the close page
// 3  Put the absolute address of the target in the allocated location
// RETURN: the size of the trampoline or 0 on failure
static DWORD InsertTrampoline64(void *inpAddr, void *targetAddr, const char* pattern, void** storedAddr)
{
    size_t bytesToMove = SIZE_OF_INDJUMP;

    UINT_PTR srcAddr = Ptr2Addrint(inpAddr);
    UINT_PTR tgtAddr = Ptr2Addrint(targetAddr);

    // Get a location close to the source address
    UINT_PTR location = memProvider.GetLocation(srcAddr);
    if (!location)
        return 0;

    UINT_PTR offset;
    UINT offset32;
    UCHAR *codePtr = (UCHAR *)inpAddr;

    // Fill the location
    UINT_PTR *locPtr = (UINT_PTR *)Addrint2Ptr(location);
    *locPtr = tgtAddr;

    if ( storedAddr ){ // If requested, store original function code
        bytesToMove = strlen(pattern)/2-1; // The last byte matching the pattern must not be copied
        __TBB_ASSERT_RELEASE( bytesToMove >= SIZE_OF_INDJUMP, "Incorrect bytecode pattern?" );
        UINT_PTR trampAddr = memProvider.GetLocation(srcAddr);
        if (!trampAddr)
            return 0;
        *storedAddr = Addrint2Ptr(trampAddr);
        // Set 'executable' flag for original instructions in the new place
        DWORD pageFlags = PAGE_EXECUTE_READWRITE;
        if (!VirtualProtect(*storedAddr, MAX_PROBE_SIZE, pageFlags, &pageFlags)) return 0;
        // Copy original instructions to the new place
        memcpy(*storedAddr, codePtr, bytesToMove);
        offset = srcAddr - trampAddr;
        offset32 = (UINT)(offset & 0xFFFFFFFF);
        CorrectOffset( trampAddr, pattern, offset32 );
        // Set jump to the code after replacement. It is within the distance of relative jump!
        offset32 -= SIZE_OF_RELJUMP;
        *(UCHAR*)(trampAddr+bytesToMove) = 0xE9;
        memcpy((UCHAR*)(trampAddr+bytesToMove+1), &offset32, sizeof(offset32));
    }

    // Fill the buffer
    offset = location - srcAddr - SIZE_OF_INDJUMP;
    offset32 = (UINT)(offset & 0xFFFFFFFF);
    *(codePtr) = 0xFF;
    *(codePtr+1) = 0x25;
    memcpy(codePtr+2, &offset32, sizeof(offset32));

    // Fill the rest with NOPs to correctly see disassembler of old code in debugger.
    for( unsigned i=SIZE_OF_INDJUMP; i<bytesToMove; i++ ){
        *(codePtr+i) = 0x90;
    }

    return SIZE_OF_INDJUMP;
}


// Insert a jump instruction in the inpAddr to the targetAddr
// 1. Get the memory protection of the page containing the input address
// 2. Change the memory protection to writable
// 3. Call InsertTrampoline32 or InsertTrampoline64
// 4. Restore memory protection
// RETURN: FALSE on failure, TRUE on success
static bool InsertTrampoline(void *inpAddr, void *targetAddr, const char ** opcodes, void** origFunc)
{
    DWORD probeSize;
    // Change page protection to EXECUTE+WRITE
    DWORD origProt = 0;
    if (!VirtualProtect(inpAddr, MAX_PROBE_SIZE, PAGE_EXECUTE_WRITECOPY, &origProt))
        return FALSE;

    const char* pattern = nullptr;
    if ( origFunc ){ // Need to store original function code
        UCHAR * const codePtr = (UCHAR *)inpAddr;
        if ( *codePtr == 0xE9 ){ // JMP relative instruction
            // For the special case when a system function consists of a single near jump,
            // instead of moving it somewhere we use the target of the jump as the original function.
            unsigned offsetInJmp = *(unsigned*)(codePtr + 1);
            *origFunc = (void*)(Ptr2Addrint(inpAddr) + offsetInJmp + SIZE_OF_RELJUMP);
            origFunc = nullptr; // now it must be ignored by InsertTrampoline32/64
        } else {
            // find the right opcode pattern
            UINT opcodeIdx = CheckOpcodes( opcodes, inpAddr, /*abortOnError=*/true );
            __TBB_ASSERT( opcodeIdx > 0, "abortOnError ignored in CheckOpcodes?" );
            pattern = opcodes[opcodeIdx-1];  // -1 compensates for +1 in CheckOpcodes
        }
    }

    probeSize = InsertTrampoline32(inpAddr, targetAddr, pattern, origFunc);
    if (!probeSize)
        probeSize = InsertTrampoline64(inpAddr, targetAddr, pattern, origFunc);

    // Restore original protection
    VirtualProtect(inpAddr, MAX_PROBE_SIZE, origProt, &origProt);

    if (!probeSize)
        return FALSE;

    FlushInstructionCache(GetCurrentProcess(), inpAddr, probeSize);
    FlushInstructionCache(GetCurrentProcess(), origFunc, probeSize);

    return TRUE;
}

// Routine to replace the functions
// TODO: replace opcodesNumber with opcodes and opcodes number to check if we replace right code.
static FRR_TYPE ReplaceFunctionA(const char *dllName, const char *funcName, FUNCPTR newFunc, const char ** opcodes, FUNCPTR* origFunc)
{
    // Cache the results of the last search for the module
    // Assume that there was no DLL unload between
    static char cachedName[MAX_PATH+1];
    static HMODULE cachedHM = 0;

    if (!dllName || !*dllName)
        return FRR_NODLL;

    if (!cachedHM || strncmp(dllName, cachedName, MAX_PATH) != 0)
    {
        // Find the module handle for the input dll
        HMODULE hModule = GetModuleHandleA(dllName);
        if (hModule == 0)
        {
            // Couldn't find the module with the input name
            cachedHM = 0;
            return FRR_NODLL;
        }

        cachedHM = hModule;
        strncpy(cachedName, dllName, MAX_PATH);
    }

    FARPROC inpFunc = GetProcAddress(cachedHM, funcName);
    if (inpFunc == 0)
    {
        // Function was not found
        return FRR_NOFUNC;
    }

    if (!InsertTrampoline((void*)inpFunc, (void*)newFunc, opcodes, (void**)origFunc)){
        // Failed to insert the trampoline to the target address
        return FRR_FAILED;
    }

    return FRR_OK;
}

//static void myPrint(const char* str) {
//  auto out = GetStdHandle(STD_ERROR_HANDLE);
//  if(out && out!=INVALID_HANDLE_VALUE) {
//      DWORD written = 0;
//      WriteFile(out, str, strlen(str), &written, nullptr);
//      FlushFileBuffers(out);
//  }
//}

static void ReplaceFunctionWithStore( const char *dllName, const char *funcName, FUNCPTR newFunc, const char ** opcodes, FUNCPTR* origFunc,  FRR_ON_ERROR on_error = FRR_FAIL )
{
    FRR_TYPE res = ReplaceFunctionA( dllName, funcName, newFunc, opcodes, origFunc );

    if (res == FRR_OK || res == FRR_NODLL || (res == FRR_NOFUNC && on_error == FRR_IGNORE))
        return;

    fprintf(stderr, "Failed to %s function %s in module %s\n",
            res==FRR_NOFUNC? "find" : "replace", funcName, dllName);

    // Unable to replace a required function
    // Aborting because incomplete replacement of memory management functions
    // may leave the program in an invalid state
    abort();
}

const char* known_bytecodes[] = {
#if _WIN64
//  "========================================================" - 56 symbols
    "4883EC284885C974",       // release free()
    "4883EC284885C975",       // release _msize()
    "4885C974375348",         // release free() 8.0.50727.42, 10.0
    "E907000000CCCC",         // release _aligned_msize(), _aligned_free() ucrtbase.dll
    "C7442410000000008B",     // release free() ucrtbase.dll 10.0.14393.33
    "E90B000000CCCC",         // release _msize() ucrtbase.dll 10.0.14393.33
    "48895C24085748",         // release _aligned_msize() ucrtbase.dll 10.0.14393.33
    "E903000000CCCC",         // release _aligned_msize() ucrtbase.dll 10.0.16299.522
    "48894C24084883EC28BA",   // debug prologue
    "4C894424184889542410",   // debug _aligned_msize() 10.0
    "48894C24084883EC2848",   // debug _aligned_free 10.0
    "488BD1488D0D#*******E9", // _o_free(), ucrtbase.dll
 #if __TBB_OVERLOAD_OLD_MSVCR
    "48895C2408574883EC3049", // release _aligned_msize 9.0
    "4883EC384885C975",       // release _msize() 9.0
    "4C8BC1488B0DA6E4040033", // an old win64 SDK
 #endif
#else // _WIN32
//  "========================================================" - 56 symbols
    "8BFF558BEC8B",           // multiple
    "8BFF558BEC83",           // release free() & _msize() 10.0.40219.325, _msize() ucrtbase.dll
    "8BFF558BECFF",           // release _aligned_msize ucrtbase.dll
    "8BFF558BEC51",           // release free() & _msize() ucrtbase.dll 10.0.14393.33
    "558BEC8B450885C074",     // release _aligned_free 11.0
    "558BEC837D08000F",       // release _msize() 11.0.51106.1
    "558BEC837D08007419FF",   // release free() 11.0.50727.1
    "558BEC8B450885C075",     // release _aligned_msize() 11.0.50727.1
    "558BEC6A018B",           // debug free() & _msize() 11.0
    "558BEC8B451050",         // debug _aligned_msize() 11.0
    "558BEC8B450850",         // debug _aligned_free 11.0
    "8BFF558BEC6A",           // debug free() & _msize() 10.0.40219.325
 #if __TBB_OVERLOAD_OLD_MSVCR
    "6A1868********E8",       // release free() 8.0.50727.4053, 9.0
    "6A1C68********E8",       // release _msize() 8.0.50727.4053, 9.0
 #endif
#endif // _WIN64/_WIN32
    nullptr
    };

static decltype(&HeapAlloc) origHeapAlloc;
static decltype(&HeapReAlloc) origHeapReAlloc;
static decltype(&HeapFree) origHeapFree;

static void* WINAPI HeapAllocProxy(HANDLE /*hHeap*/, DWORD dwFlags, SIZE_T dwBytes) {
  void* ptr = scalable_malloc(dwBytes);
  if (dwFlags & HEAP_ZERO_MEMORY)
    std::memset(ptr, 0, dwBytes);
  return ptr;
}

static void* WINAPI HeapReAllocProxy(HANDLE /*hHeap*/, DWORD dwFlags, void* lpMem, SIZE_T dwBytes) {
  void* ptr = scalable_realloc(lpMem, dwBytes);
  if (dwFlags & HEAP_ZERO_MEMORY)
    std::memset(ptr, 0, dwBytes);
  return ptr;
}

static BOOL WINAPI HeapFreeProxy(HANDLE /*hHeap*/, DWORD dwFlags, void* lpMem) {
  scalable_free(lpMem);
  return TRUE;
}

static constexpr const unsigned char mallocSig[] = {0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x83, 0xf9, 0xe0, 0x77, 0x3c, 0x48, 0x85, 0xc9, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x0f, 0x44, 0xd8, 0xeb, 0x15, 0xe8, 0xde, 0xab, 0xff, 0xff, 0x85, 0xc0, 0x74, 0x25, 0x48, 0x8b, 0xcb, 0xe8, 0x2a, 0x82, 0xfe, 0xff, 0x85, 0xc0, 0x74, 0x19, 0x48, 0x8b, 0x0d, 0x13, 0xbe, 0x8f, 0x00, 0x4c, 0x8b, 0xc3, 0x33, 0xd2, 0xff, 0x15, 0xd0, 0x08, 0x0e, 0x00};
static constexpr const size_t mallocSigLen = sizeof(mallocSig);

static constexpr const unsigned char callocSig[] = {0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x8b, 0xc2, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xc9, 0x74, 0x0e, 0x33, 0xd2, 0x48, 0x8d, 0x42, 0xe0, 0x48, 0xf7, 0xf3, 0x49, 0x3b, 0xc0, 0x72, 0x43, 0x49, 0x0f, 0xaf, 0xd8, 0xb8, 0x01, 0x00, 0x00, 0x00, 0x48, 0x85, 0xdb, 0x48, 0x0f, 0x44, 0xd8, 0xeb, 0x15, 0xe8, 0x06, 0xd4, 0xff, 0xff,  0x85, 0xc0, 0x74, 0x28};
static constexpr const size_t callocSigLen = sizeof(callocSig);

static constexpr const unsigned char reallocSig[] = {0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf9, 0x48, 0x85, 0xc9, 0x75, 0x0a, 0x48, 0x8b, 0xca, 0xe8, 0x5f, 0x00, 0x00, 0x00, 0xeb, 0x1f, 0x48, 0x85, 0xdb, 0x75, 0x07, 0xe8, 0xe3, 0xed, 0xff, 0xff, 0xeb, 0x11, 0x48, 0x83, 0xfb, 0xe0, 0x76, 0x2d, 0xe8, 0x76, 0x82, 0xfe, 0xff, 0xc7, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x33, 0xc0, 0x48, 0x8b, 0x5c, 0x24, 0x30};
static constexpr const size_t reallocSigLen = sizeof(reallocSig);

static constexpr const unsigned char freeSig[] = {0x48, 0x85, 0xc9, 0x74, 0x37, 0x53, 0x48, 0x83, 0xec, 0x20, 0x4c, 0x8b, 0xc1, 0x33, 0xd2, 0x48, 0x8b, 0x0d, 0xa6, 0xd0, 0x8f, 0x00, 0xff, 0x15, 0x70, 0x1b, 0x0e, 0x00, 0x85, 0xc0, 0x75, 0x17, 0xe8, 0x7b, 0x94, 0xfe, 0xff, 0x48, 0x8b, 0xd8, 0xff, 0x15, 0xf6, 0x1f, 0x0e, 0x00, 0x8b, 0xc8, 0xe8, 0xb3, 0x93, 0xfe, 0xff, 0x89, 0x03, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3};
static constexpr const size_t freeSigLen = sizeof(freeSig);

static constexpr const unsigned char recallocSig[] = {0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x6c, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xec, 0x20, 0x49, 0x8b, 0xe8, 0x48, 0x8b, 0xda, 0x48, 0x8b, 0xf1, 0x48, 0x85, 0xd2, 0x74, 0x1d, 0x33, 0xd2, 0x48, 0x8d, 0x42, 0xe0, 0x48, 0xf7, 0xf3, 0x49, 0x3b, 0xc0, 0x73, 0x0f, 0xe8, 0x63, 0xfd, 0xfe, 0xff, 0xc7, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x33, 0xc0, 0xeb, 0x41, 0x48, 0x85, 0xf6, 0x74, 0x0a, 0xe8, 0xbf, 0xd2, 0x00, 0x00, 0x48, 0x8b, 0xf8};
static constexpr const size_t recallocSigLen = sizeof(recallocSig);

static void* findSig(void* data, size_t dataSize, const void* sig, size_t sigLen) {
  for (size_t i = 0; i < (dataSize - sigLen); ++i) {
    auto ptr = static_cast<char*>(data) + i;
    if (memcmp(ptr, sig, sigLen) == 0)
      return ptr;
  }
  return nullptr;
}

extern "C" {
__declspec(dllimport) void   __TBB_malloc_safer_free( void *ptr, void (*original_free)(void*));
__declspec(dllimport) void * __TBB_malloc_safer_realloc( void *ptr, size_t, void* );
__declspec(dllimport) void * __TBB_malloc_safer_aligned_realloc( void *ptr, size_t, size_t, void* );
__declspec(dllimport) size_t __TBB_malloc_safer_msize( void *ptr, size_t (*orig_msize_crt80d)(void*));
} // extern "C"

static void* __cdecl malloc_proxy(size_t size) {
  return malloc(size);
//  return scalable_malloc(size);
}

static void* __cdecl calloc_proxy(size_t count, size_t size) {
  return calloc(count, size);
//  return scalable_calloc(count, size);
}

static void* realloc_proxy(void* ptr, size_t size) {
  return realloc(ptr, size);
//  return scalable_realloc(ptr, size);
}

static void free_proxy(void* ptr) {
  free(ptr);
//  __TBB_malloc_safer_free(ptr, &free);
}

static void* __cdecl recalloc_proxy(void* ptr, size_t count, size_t size) {
  auto res = realloc_proxy(ptr, count * size);
  memset(res, 0, count * size);
  return res;
}


extern "C" BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved)
{
  if (fdwReason != DLL_PROCESS_ATTACH)
    return TRUE;

  auto modBase = GetModuleHandleA(nullptr);
  size_t modSize = 31348224;

  auto mallocPtr = findSig(modBase, modSize, mallocSig, mallocSigLen);
  auto callocPtr = findSig(modBase, modSize, callocSig, callocSigLen);
  auto reallocPtr = findSig(modBase, modSize, reallocSig, reallocSigLen);
  auto freePtr = findSig(modBase, modSize, freeSig, freeSigLen);
  auto recallocPtr = findSig(modBase, modSize, recallocSig, recallocSigLen);
  if (!mallocPtr || !callocPtr || !reallocPtr || !freePtr || !recallocPtr)
    abort();

  if (!InsertTrampoline(mallocPtr, (void*)&malloc_proxy, nullptr, nullptr))
    abort();

  if (!InsertTrampoline(callocPtr, (void*)&calloc_proxy, nullptr, nullptr))
    abort();

  if (!InsertTrampoline(reallocPtr, (void*)&realloc_proxy, nullptr, nullptr))
    abort();

  if (!InsertTrampoline(freePtr, (void*)&free_proxy, nullptr, nullptr))
    abort();

  if (!InsertTrampoline(recallocPtr, (void*)&recalloc_proxy, nullptr, nullptr))
    abort();

//  ReplaceFunctionWithStore("Kernel32", "HeapAlloc", (FUNCPTR)HeapAllocProxy, known_bytecodes, nullptr,  FRR_FAIL );
//  ReplaceFunctionWithStore("Kernel32", "HeapReAlloc", (FUNCPTR)HeapReAllocProxy, known_bytecodes, nullptr,  FRR_FAIL );
//  ReplaceFunctionWithStore("Kernel32", "HeapFree", (FUNCPTR)HeapFreeProxy, known_bytecodes, (FUNCPTR*)&origHeapFree,  FRR_FAIL );

  return TRUE;
}
