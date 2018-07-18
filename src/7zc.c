#include <stdio.h>
#include <string.h>

#include "7z.h"
#include "7zAlloc.h"
#include "7zBuf.h"
#include "7zCrc.h"
#include "7zFile.h"
#include "7zTypes.h"
#include "7zVersion.h"
#include "Compiler.h"
#include "CpuArch.h"
#include "unzip.h"
#include "spinlock.h"
#include <shlwapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "7z.lib")
#endif

extern void __cdecl logmsg(const char *format, ...);

#if defined(NDEBUG)
#define PrintError(str) ((void)0)
#elif defined(DEBUG_LOG)
#define PrintError logmsg
#endif

#define kInputBufSize ((size_t) 1 << 18)

static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

static void
Print(const char *s)
{
    fputs(s, stdout);
}
static void
PrintLF()
{
    Print("\n");
}

#ifndef PrintError
static void
PrintError(char *s,...)
{
    Print("\nERROR: ");
    Print(s);
    PrintLF();
}
#endif

static int
Buf_EnsureSize(CBuf *dest, size_t size)
{
    if (dest->size >= size)
        return 1;
    Buf_Free(dest, &g_Alloc);
    return Buf_Create(dest, size, &g_Alloc);
}

static SRes
Utf16_To_Char(CBuf *buf, const UInt16 *s, UINT codePage)
{
    unsigned len = 0;
    for (len = 0; s[len] != 0; len++)
        ;
    {
        unsigned size = len * 3 + 100;
        if (!Buf_EnsureSize(buf, size))
            return SZ_ERROR_MEM;
        {
            buf->data[0] = 0;
            if (len != 0)
            {
                char defaultChar = '_';
                BOOL defUsed;
                unsigned numChars = 0;
                numChars = WideCharToMultiByte(codePage, 0, s, len, (char *) buf->data, size, &defaultChar, &defUsed);
                if (numChars == 0 || numChars >= size)
                    return SZ_ERROR_FAIL;
                buf->data[numChars] = 0;
            }
            return SZ_OK;
        }
    }
}

#define MY_FILE_CODE_PAGE_PARAM , g_FileCodePage

static WRes
OutFile_OpenUtf16(CSzFile *p, const UInt16 *name)
{
    return OutFile_OpenW(p, name);
}

static SRes
PrintString(const UInt16 *s)
{
    CBuf buf;
    SRes res;
    Buf_Init(&buf);
    res = Utf16_To_Char(&buf, s, CP_OEMCP);
    if (res == SZ_OK)
        Print((const char *) buf.data);
    Buf_Free(&buf, &g_Alloc);
    return res;
}

static void
UInt64ToStr(UInt64 value, char *s, int numDigits)
{
    char temp[32];
    int pos = 0;
    do
    {
        temp[pos++] = (char) ('0' + (unsigned) (value % 10));
        value /= 10;
    } while (value != 0);

    for (numDigits -= pos; numDigits > 0; numDigits--)
        *s++ = ' ';

    do
        *s++ = temp[--pos];
    while (pos);
    *s = '\0';
}

static char *
UIntToStr(char *s, unsigned value, int numDigits)
{
    char temp[16];
    int pos = 0;
    do
        temp[pos++] = (char) ('0' + (value % 10));
    while (value /= 10);

    for (numDigits -= pos; numDigits > 0; numDigits--)
        *s++ = '0';

    do
        *s++ = temp[--pos];
    while (pos);
    *s = '\0';
    return s;
}

static void
UIntToStr_2(char *s, unsigned value)
{
    s[0] = (char) ('0' + (value / 10));
    s[1] = (char) ('0' + (value % 10));
}

#define PERIOD_4 (4 * 365 + 1)
#define PERIOD_100 (PERIOD_4 * 25 - 1)
#define PERIOD_400 (PERIOD_100 * 4 + 1)

static void
ConvertFileTimeToString(const CNtfsFileTime *nt, char *s)
{
    unsigned year, mon, hour, min, sec;
    Byte ms[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    unsigned t;
    UInt32 v;
    UInt64 v64 = nt->Low | ((UInt64) nt->High << 32);
    v64 /= 10000000;
    sec = (unsigned) (v64 % 60);
    v64 /= 60;
    min = (unsigned) (v64 % 60);
    v64 /= 60;
    hour = (unsigned) (v64 % 24);
    v64 /= 24;

    v = (UInt32) v64;

    year = (unsigned) (1601 + v / PERIOD_400 * 400);
    v %= PERIOD_400;

    t = v / PERIOD_100;
    if (t == 4)
        t = 3;
    year += t * 100;
    v -= t * PERIOD_100;
    t = v / PERIOD_4;
    if (t == 25)
        t = 24;
    year += t * 4;
    v -= t * PERIOD_4;
    t = v / 365;
    if (t == 4)
        t = 3;
    year += t;
    v -= t * 365;

    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
        ms[1] = 29;
    for (mon = 0;; mon++)
    {
        unsigned d = ms[mon];
        if (v < d)
            break;
        v -= d;
    }
    s = UIntToStr(s, year, 4);
    *s++ = '-';
    UIntToStr_2(s, mon + 1);
    s[2] = '-';
    s += 3;
    UIntToStr_2(s, (unsigned) v + 1);
    s[2] = ' ';
    s += 3;
    UIntToStr_2(s, hour);
    s[2] = ':';
    s += 3;
    UIntToStr_2(s, min);
    s[2] = ':';
    s += 3;
    UIntToStr_2(s, sec);
    s[2] = 0;
}

static void
GetAttribString(UInt32 wa, Bool isDir, char *s)
{
    s[0] = (char) (((wa & FILE_ATTRIBUTE_DIRECTORY) != 0 || isDir) ? 'D' : '.');
    s[1] = (char) (((wa & FILE_ATTRIBUTE_READONLY) != 0) ? 'R' : '.');
    s[2] = (char) (((wa & FILE_ATTRIBUTE_HIDDEN) != 0) ? 'H' : '.');
    s[3] = (char) (((wa & FILE_ATTRIBUTE_SYSTEM) != 0) ? 'S' : '.');
    s[4] = (char) (((wa & FILE_ATTRIBUTE_ARCHIVE) != 0) ? 'A' : '.');
    s[5] = 0;
}

int WINAPI
extract7z(LPCWSTR srcFile, LPCWSTR dstPath)
{
    ISzAlloc allocImp;
    ISzAlloc allocTempImp;

    CFileInStream archiveStream;
    CLookToRead2 lookStream;
    CSzArEx db;
    SRes res = SZ_OK;
    UInt16 *temp = NULL;
    size_t tempSize = 0;
    FILE   *pf = NULL;
    WCHAR destPath[MAX_PATH + 1] = {
        L'\0',
    };
    WCHAR file_list_log[MAX_PATH + 1] = {
        L'\0',
    };
    Print("\n7z Decoder " MY_VERSION_CPU " : " MY_COPYRIGHT_DATE "\n\n");

    allocImp = g_Alloc;
    allocTempImp = g_Alloc;

    if (InFile_OpenW(&archiveStream.file, srcFile))
    {
        PrintError("can not open input file");
        return 1;
    }

    FileInStream_CreateVTable(&archiveStream);
    LookToRead2_CreateVTable(&lookStream, False);
    lookStream.buf = lookStream.buf = ISzAlloc_Alloc(&allocImp, kInputBufSize);
    if (!lookStream.buf)
        res = SZ_ERROR_MEM;
    else
    {
        lookStream.bufSize = kInputBufSize;
        lookStream.realStream = &archiveStream.vt;
        LookToRead2_Init(&lookStream);
    }

    CrcGenerateTable();

    SzArEx_Init(&db);

    if (res == SZ_OK)
    {
        res = SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp);
    }

    if (res == SZ_OK)
    {
        UInt32 i;

        /*
        if you need cache, use these 3 variables.
        if you use external function, you can make these variable as static.
        */
        UInt32 blockIndex = 0xFFFFFFFF; /* it can have any value before first call (if outBuffer = 0) */
        Byte *outBuffer = 0;            /* it must be 0 before first call for each new archive. */
        size_t outBufferSize = 0;       /* it can have any value before first call (if outBuffer = 0) */
        if (NULL != dstPath)
        {
            create_dir(dstPath);
            wnsprintfW(file_list_log, MAX_PATH, L"%ls\\%ls", dstPath, L"update.log");
        }
        pf = _wfopen(file_list_log, L"wb");
        if (pf != NULL)
        {
            const char *bom = "\xFF\xFE";
            fwrite(bom, 1, strlen(bom), pf);
        }

        for (i = 0; i < db.NumFiles; i++)
        {
            size_t offset = 0;
            size_t outSizeProcessed = 0;
            // const CSzFileItem *f = db.Files + i;
            size_t len;
            unsigned isDir = SzArEx_IsDir(&db, i);
            len = SzArEx_GetFileNameUtf16(&db, i, NULL);

            if (len > tempSize)
            {
                SzFree(NULL, temp);
                tempSize = len;
                temp = (UInt16 *) SzAlloc(NULL, tempSize * sizeof(temp[0]));
                if (!temp)
                {
                    res = SZ_ERROR_MEM;
                    break;
                }
            }

            SzArEx_GetFileNameUtf16(&db, i, temp);
            if (pf != NULL)
            {
                fwrite(temp, sizeof(WCHAR), wcslen(temp), pf);
                fwrite(L"\r\n", sizeof(WCHAR), 2, pf);
            }
            Print("Extracting ");
            res = PrintString(temp);
            if (res != SZ_OK)
                break;

            if (isDir)
                Print("/");
            else
            {
                res = SzArEx_Extract(&db, &lookStream.vt, i, &blockIndex, &outBuffer, &outBufferSize, &offset, &outSizeProcessed, &allocImp, &allocTempImp);
                if (res != SZ_OK)
                    break;
            }

            if (TRUE)
            {
                CSzFile outFile;
                size_t processedSize;
                UInt16 *name = (UInt16 *) temp;
                wcsncpy(destPath, dstPath, MAX_PATH);
                wcsncat(destPath, L"\\", MAX_PATH);
                wcsncat(destPath, name, MAX_PATH);

                if (isDir)
                {
                    create_dir(destPath);
                    PrintLF();
                    continue;
                }
                else if (OutFile_OpenUtf16(&outFile, destPath))
                {
                    PrintError("can not open output file");
                    res = SZ_ERROR_FAIL;
                    break;
                }

                processedSize = outSizeProcessed;

                if (File_Write(&outFile, outBuffer + offset, &processedSize) != 0 || processedSize != outSizeProcessed)
                {
                    PrintError("can not write output file");
                    res = SZ_ERROR_FAIL;
                    break;
                }

                if (File_Close(&outFile))
                {
                    PrintError("can not close output file");
                    res = SZ_ERROR_FAIL;
                    break;
                }

                if (SzBitWithVals_Check(&db.Attribs, i))
                {
                    UInt32 attrib = db.Attribs.Vals[i];
                    /* p7zip stores posix attributes in high 16 bits and adds 0x8000 as marker.
                       We remove posix bits, if we detect posix mode field */
                    if ((attrib & 0xF0000000) != 0)
                        attrib &= 0x7FFF;
                    SetFileAttributesW(destPath, attrib);
                }
            }
            PrintLF();
        }
        ISzAlloc_Free(&allocImp, outBuffer);
    }
    if (pf != NULL)
    {
        fclose(pf);
    }
    SzFree(NULL, temp);
    SzArEx_Free(&db, &allocImp);
    ISzAlloc_Free(&allocImp, lookStream.buf);

    File_Close(&archiveStream.file);

    if (res == SZ_OK)
    {
        Print("\nEverything is Ok\n");
        return 0;
    }

    if (res == SZ_ERROR_UNSUPPORTED)
        PrintError("decoder doesn't support this archive");
    else if (res == SZ_ERROR_MEM)
        PrintError("can not allocate memory");
    else if (res == SZ_ERROR_CRC)
        PrintError("CRC error");
    else
    {
        char s[32];
        UInt64ToStr(res, s, 0);
        PrintError("7z extract fail,error code:%s, we try to unzip it" ,s);
        return unzip_file(srcFile, dstPath, file_list_log);
    }
    return 1;
}
