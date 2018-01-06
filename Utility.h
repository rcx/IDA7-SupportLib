
// ****************************************************************************
// File: Utility.h
// Desc: IDA utility support
// Auth: Sirmabus 2015
// ****************************************************************************
#pragma once

typedef double TIMESTAMP;
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)
#define DAY    (HOUR * 24)

void trace(const char *format, ...);
TIMESTAMP getTimeStamp();
TIMESTAMP getTimeStampLow();
LPCSTR  timeString(TIMESTAMP Time);
LPSTR   prettyNumberString(UINT64 n, __bcount(32) LPSTR buffer);
LPCTSTR byteSizeString(UINT64 uSize);
UINT getChracterLength(int strtype, UINT byteCount);
void getDisasmText(ea_t ea, qstring &s);
void idaFlags2String(flags_t f, __out qstring &s, BOOL withValue = FALSE);
void dumpFlags(ea_t ea, BOOL withValue = FALSE);
BOOL isHexStr(LPCSTR str);
long fsize(FILE *fp);
LPSTR replaceExtInPath(__inout_bcount(MAX_PATH) LPSTR path, __in LPSTR pathNew);

// Returns TRUE if there is a name at address that is unique (I.E. user, or from PDB, etc., and not IDA auto-generated)
inline BOOL hasUniqueName(ea_t ea) { return(has_name(get_flags(ea))); }

// Return TRUE if at address is a string (ASCII, Unicode, etc.)
inline BOOL isString(ea_t ea){ return(is_strlit(get_flags(ea))); }

// Get string type by address
// Should process the result with "get_str_type_code()" to filter any 
// potential string encoding from the base type.
inline int getStringType(ea_t ea)
{
    opinfo_t oi;
    if (get_opinfo(&oi, ea, 0, get_flags(ea)))
        return(oi.strtype);
    else
        return(STRTYPE_C);
}


// Size of string sans terminator
#define SIZESTR(x) (sizeof(x) - 1)

// Data and function alignment
#define ALIGN(_x_) __declspec(align(_x_))

// Tick IDA's Qt message pump to show msg() output
// With my WaitBoxEx* library included
#define refreshUI() WaitBox::processIdaEvents()

#define CATCH() catch (...) { msg("** Exception in %s()! ***\n", __FUNCTION__); }

// Stack alignment trick, based on Douglas Walker's post
// http://www.gamasutra.com/view/feature/3975/data_alignment_part_2_objects_on_.php
#define STACKALIGN(name, type) \
	BYTE space_##name[sizeof(type) + (16-1)]; \
	type &name = *reinterpret_cast<type *>((UINT_PTR) (space_##name + (16-1)) & ~(16-1))

#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(TypeName&) = delete;          \
    void operator=(TypeName) = delete;

template <class T> inline void swap_t(T &a, T &b)
{
    T c = a;
    a = b;
    b = c;
}

// ea_t zero padded hex number format
#ifndef __EA64__
#define EAFORMAT "%08X"
#else
#define EAFORMAT "%016I64X"
#endif


#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC__ __FILE__ "("__STR1__(__LINE__)") : Warning MSG: "
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "
// Now you can use the #pragma message to add the location of the message:
//
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")

// 32 bit flag sequential serializer
struct SBITFLAG
{
    inline SBITFLAG() : Index(0) {}
    inline UINT First(){ Index = 0; return(1 << Index++); }
    inline UINT Next(){ return(1 << Index++); }
    UINT Index;
};

// Simple cache aligned expanding buffer
// For the performance benefit of skipping of alloc/free calls plus base cache alignment
template <class T, const size_t t_reserveElementCount = 0, const size_t t_elementExpandSize = 1024> class SlideBuffer
{
public:
    SlideBuffer() : m_dataPtr(NULL), m_elementCount(0)
    {
        // Initial reserved buffer size if any
        if (t_reserveElementCount)
            get(t_reserveElementCount);
    }
    ~SlideBuffer(){ clear(); }

    // Get buffer expanding the size as needed, or NULL on allocation failure
    T *get(size_t wantedElementCount = 0)
    {
        if (wantedElementCount > m_elementCount)
        {
            // Attempt to create or expand as needed
            wantedElementCount += ((m_dataPtr == NULL) ? 0 : t_elementExpandSize);
            //msg("GrowBuffer: %08X expand from %u to %u element count.\n", m_dataPtr, m_elementCount, wantedElementCount);
            if (T *dataPtr = (T *)_aligned_realloc(m_dataPtr, (sizeof(T) * wantedElementCount), 16))
            {
                m_dataPtr = dataPtr;
                m_elementCount = wantedElementCount;
            }
            else
                clear();
            _ASSERT(m_dataPtr);
        }
        return(m_dataPtr);
    }

    // Free up buffer, a clear/reset operation
    void clear()
    {
        if (m_dataPtr)
            _aligned_free(m_dataPtr);
        m_dataPtr = NULL;
        m_elementCount = 0;
    }

    // Return element size of current buffer
    size_t size(){ return(m_elementCount); }

private:
    DISALLOW_COPY_AND_ASSIGN(SlideBuffer);

    T *m_dataPtr;
    size_t m_elementCount;
};
