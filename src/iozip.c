#include <stdio.h>
#include <stdlib.h>

#include "zlib.h"
#include "iozip.h"

#ifndef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (0xFFFFFFFF)
#endif

#ifndef INVALID_SET_FILE_POINTER
#define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif

// see Include/shared/winapifamily.h in the Windows Kit
#if defined(WINAPI_FAMILY_PARTITION) && (!(defined(IOWIN32_USING_WINRT_API)))

#if !defined(WINAPI_FAMILY_ONE_PARTITION)
#define WINAPI_FAMILY_ONE_PARTITION(PartitionSet, Partition) ((WINAPI_FAMILY & PartitionSet) == Partition)
#endif

#if WINAPI_FAMILY_ONE_PARTITION(WINAPI_FAMILY, WINAPI_PARTITION_APP)
#define IOWIN32_USING_WINRT_API 1
#endif
#endif

typedef struct
{
    HANDLE hf;
    int error;
} WIN32FILE_IOWIN;

voidpf call_zopen64 (const zlib_filefunc64_32_def* pfilefunc,const void*filename,int mode)
{
    if (pfilefunc->zfile_func64.zopen64_file != NULL)
        return (*(pfilefunc->zfile_func64.zopen64_file)) (pfilefunc->zfile_func64.opaque,filename,mode);
    else
    {
        return (*(pfilefunc->zopen32_file))(pfilefunc->zfile_func64.opaque,(const WCHAR*)filename,mode);
    }
}

long call_zseek64 (const zlib_filefunc64_32_def* pfilefunc,voidpf filestream, ZPOS64_T offset, int origin)
{
    if (pfilefunc->zfile_func64.zseek64_file != NULL)
        return (*(pfilefunc->zfile_func64.zseek64_file)) (pfilefunc->zfile_func64.opaque,filestream,offset,origin);
    else
    {
        uLong offsetTruncated = (uLong)offset;
        if (offsetTruncated != offset)
            return -1;
        else
            return (*(pfilefunc->zseek32_file))(pfilefunc->zfile_func64.opaque,filestream,offsetTruncated,origin);
    }
}

ZPOS64_T call_ztell64 (const zlib_filefunc64_32_def* pfilefunc,voidpf filestream)
{
    if (pfilefunc->zfile_func64.zseek64_file != NULL)
        return (*(pfilefunc->zfile_func64.ztell64_file)) (pfilefunc->zfile_func64.opaque,filestream);
    else
    {
        uLong tell_uLong = (*(pfilefunc->ztell32_file))(pfilefunc->zfile_func64.opaque,filestream);
        if ((tell_uLong) == MAXU32)
            return (ZPOS64_T)-1;
        else
            return tell_uLong;
    }
}

void fill_zlib_filefunc64_32_def_from_filefunc32(zlib_filefunc64_32_def* p_filefunc64_32,const zlib_filefunc_def* p_filefunc32)
{
    p_filefunc64_32->zfile_func64.zopen64_file = NULL;
    p_filefunc64_32->zopen32_file = p_filefunc32->zopen_file;
    p_filefunc64_32->zfile_func64.zerror_file = p_filefunc32->zerror_file;
    p_filefunc64_32->zfile_func64.zread_file = p_filefunc32->zread_file;
    p_filefunc64_32->zfile_func64.zwrite_file = p_filefunc32->zwrite_file;
    p_filefunc64_32->zfile_func64.ztell64_file = NULL;
    p_filefunc64_32->zfile_func64.zseek64_file = NULL;
    p_filefunc64_32->zfile_func64.zclose_file = p_filefunc32->zclose_file;
    p_filefunc64_32->zfile_func64.zerror_file = p_filefunc32->zerror_file;
    p_filefunc64_32->zfile_func64.opaque = p_filefunc32->opaque;
    p_filefunc64_32->zseek32_file = p_filefunc32->zseek_file;
    p_filefunc64_32->ztell32_file = p_filefunc32->ztell_file;
}

static voidpf ZCALLBACK fopen_file_func (voidpf opaque, const WCHAR* filename, int mode)
{
    FILE* file = NULL;
    const WCHAR* mode_fopen = NULL;
    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
        mode_fopen = L"rb";
    else
    if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
        mode_fopen = L"r+b";
    else
    if (mode & ZLIB_FILEFUNC_MODE_CREATE)
        mode_fopen = L"wb";

    if ((filename!=NULL) && (mode_fopen != NULL))
        file = _wfopen(filename, mode_fopen);
    return file;
}

static voidpf ZCALLBACK fopen64_file_func (voidpf opaque, const WCHAR* filename, int mode)
{
    FILE* file = NULL;
    const WCHAR* mode_fopen = NULL;
    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
        mode_fopen = L"rb";
    else
    if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
        mode_fopen = L"r+b";
    else
    if (mode & ZLIB_FILEFUNC_MODE_CREATE)
        mode_fopen = L"wb";

    if ((filename!=NULL) && (mode_fopen != NULL))
        file = FOPEN_FUNC(filename, mode_fopen);
    return file;
}


static uLong ZCALLBACK fread_file_func (voidpf opaque, voidpf stream, void* buf, uLong size)
{
    uLong ret;
    ret = (uLong)fread(buf, 1, (size_t)size, (FILE *)stream);
    return ret;
}

static uLong ZCALLBACK fwrite_file_func (voidpf opaque, voidpf stream, const void* buf, uLong size)
{
    uLong ret;
    ret = (uLong)fwrite(buf, 1, (size_t)size, (FILE *)stream);
    return ret;
}

static long ZCALLBACK ftell_file_func (voidpf opaque, voidpf stream)
{
    long ret;
    ret = ftell((FILE *)stream);
    return ret;
}


static ZPOS64_T ZCALLBACK ftell64_file_func (voidpf opaque, voidpf stream)
{
    ZPOS64_T ret;
    ret = FTELLO_FUNC((FILE *)stream);
    return ret;
}

static long ZCALLBACK fseek_file_func (voidpf  opaque, voidpf stream, uLong offset, int origin)
{
    int fseek_origin=0;
    long ret;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR :
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END :
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET :
        fseek_origin = SEEK_SET;
        break;
    default: return -1;
    }
    ret = 0;
    if (fseek((FILE *)stream, offset, fseek_origin) != 0)
        ret = -1;
    return ret;
}

static long ZCALLBACK fseek64_file_func (voidpf  opaque, voidpf stream, ZPOS64_T offset, int origin)
{
    int fseek_origin=0;
    long ret;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR :
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END :
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET :
        fseek_origin = SEEK_SET;
        break;
    default: return -1;
    }
    ret = 0;

    if(FSEEKO_FUNC((FILE *)stream, offset, fseek_origin) != 0)
                        ret = -1;

    return ret;
}


static int ZCALLBACK fclose_file_func (voidpf opaque, voidpf stream)
{
    int ret;
    ret = fclose((FILE *)stream);
    return ret;
}

static int ZCALLBACK ferror_file_func (voidpf opaque, voidpf stream)
{
    int ret;
    ret = ferror((FILE *)stream);
    return ret;
}

void fill_fopen_filefunc (zlib_filefunc_def* pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen_file = fopen_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell_file = ftell_file_func;
    pzlib_filefunc_def->zseek_file = fseek_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

void fill_fopen64_filefunc (zlib_filefunc64_def*  pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen64_file = fopen64_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell64_file = ftell64_file_func;
    pzlib_filefunc_def->zseek64_file = fseek64_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

/* ioapi.c end */

/* iowi32.c */
static void win32_translate_open_mode(int mode,
                                      DWORD* lpdwDesiredAccess,
                                      DWORD* lpdwCreationDisposition,
                                      DWORD* lpdwShareMode,
                                      DWORD* lpdwFlagsAndAttributes)
{
    *lpdwDesiredAccess = *lpdwShareMode = *lpdwFlagsAndAttributes = *lpdwCreationDisposition = 0;

    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
    {
        *lpdwDesiredAccess = GENERIC_READ;
        *lpdwCreationDisposition = OPEN_EXISTING;
        *lpdwShareMode = FILE_SHARE_READ;
    }
    else if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
    {
        *lpdwDesiredAccess = GENERIC_WRITE | GENERIC_READ;
        *lpdwCreationDisposition = OPEN_EXISTING;
    }
    else if (mode & ZLIB_FILEFUNC_MODE_CREATE)
    {
        *lpdwDesiredAccess = GENERIC_WRITE | GENERIC_READ;
        *lpdwCreationDisposition = CREATE_ALWAYS;
    }
}

static voidpf win32_build_iowin(HANDLE hFile)
{
    voidpf ret=NULL;

    if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE))
    {
        WIN32FILE_IOWIN w32fiow;
        w32fiow.hf = hFile;
        w32fiow.error = 0;
        ret = malloc(sizeof(WIN32FILE_IOWIN));

        if (ret==NULL)
            CloseHandle(hFile);
        else
            *((WIN32FILE_IOWIN*)ret) = w32fiow;
    }
    return ret;
}

voidpf ZCALLBACK win32_open64_file_func (voidpf opaque,const WCHAR* filename,int mode)
{
    const char* mode_fopen = NULL;
    DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
    HANDLE hFile = NULL;

    win32_translate_open_mode(mode,&dwDesiredAccess,&dwCreationDisposition,&dwShareMode,&dwFlagsAndAttributes);

    if ((filename!=NULL) && (dwDesiredAccess != 0))
    {
        hFile = CreateFileW(filename, dwDesiredAccess, dwShareMode, NULL, dwCreationDisposition, dwFlagsAndAttributes, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            printf("CreateFileW[%ls] failed, cause [%lu]\n", filename, GetLastError());
        }
    }

    return win32_build_iowin(hFile);
}


voidpf ZCALLBACK win32_open64_file_funcA (voidpf opaque,const void* filename,int mode)
{
    const char* mode_fopen = NULL;
    DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
    HANDLE hFile = NULL;

    win32_translate_open_mode(mode,&dwDesiredAccess,&dwCreationDisposition,&dwShareMode,&dwFlagsAndAttributes);

    if ((filename!=NULL) && (dwDesiredAccess != 0))
        hFile = CreateFileA((LPCSTR)filename, dwDesiredAccess, dwShareMode, NULL, dwCreationDisposition, dwFlagsAndAttributes, NULL);
    return win32_build_iowin(hFile);
}


voidpf ZCALLBACK win32_open_file_func (voidpf opaque,const WCHAR* filename,int mode)
{
    const char* mode_fopen = NULL;
    DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
    HANDLE hFile = NULL;

    win32_translate_open_mode(mode,&dwDesiredAccess,&dwCreationDisposition,&dwShareMode,&dwFlagsAndAttributes);

    if ((filename!=NULL) && (dwDesiredAccess != 0))
    {
        hFile = CreateFileW(filename, dwDesiredAccess, dwShareMode, NULL, dwCreationDisposition, dwFlagsAndAttributes, NULL);
    }

    return win32_build_iowin(hFile);
}


uLong ZCALLBACK win32_read_file_func (voidpf opaque, voidpf stream, void* buf,uLong size)
{
    uLong ret=0;
    HANDLE hFile = NULL;
    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream) -> hf;

    if (hFile != NULL)
    {
        if (!ReadFile(hFile, buf, size, &ret, NULL))
        {
            DWORD dwErr = GetLastError();
            if (dwErr == ERROR_HANDLE_EOF)
                dwErr = 0;
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
        }
    }

    return ret;
}


uLong ZCALLBACK win32_write_file_func (voidpf opaque,voidpf stream,const void* buf,uLong size)
{
    uLong ret=0;
    HANDLE hFile = NULL;
    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream) -> hf;

    if (hFile != NULL)
    {
        if (!WriteFile(hFile, buf, size, &ret, NULL))
        {
            DWORD dwErr = GetLastError();
            if (dwErr == ERROR_HANDLE_EOF)
                dwErr = 0;
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
        }
    }

    return ret;
}

static BOOL MySetFilePointerEx(HANDLE hFile, LARGE_INTEGER pos, LARGE_INTEGER *newPos,  DWORD dwMoveMethod)
{
#ifdef IOWIN32_USING_WINRT_API
    return SetFilePointerEx(hFile, pos, newPos, dwMoveMethod);
#else
    LONG lHigh = pos.HighPart;
    DWORD dwNewPos = SetFilePointer(hFile, pos.LowPart, &lHigh, dwMoveMethod);
    BOOL fOk = TRUE;
    if (dwNewPos == 0xFFFFFFFF)
        if (GetLastError() != NO_ERROR)
            fOk = FALSE;
    if ((newPos != NULL) && (fOk))
    {
        newPos->LowPart = dwNewPos;
        newPos->HighPart = lHigh;
    }
    return fOk;
#endif
}

long ZCALLBACK win32_tell_file_func (voidpf opaque,voidpf stream)
{
    long ret=-1;
    HANDLE hFile = NULL;
    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream) -> hf;
    if (hFile != NULL)
    {
        LARGE_INTEGER pos;
        pos.QuadPart = 0;

        if (!MySetFilePointerEx(hFile, pos, &pos, FILE_CURRENT))
        {
            DWORD dwErr = GetLastError();
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
            ret = -1;
        }
        else
            ret=(long)pos.LowPart;
    }
    return ret;
}

ZPOS64_T ZCALLBACK win32_tell64_file_func (voidpf opaque, voidpf stream)
{
    ZPOS64_T ret= (ZPOS64_T)-1;
    HANDLE hFile = NULL;
    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream)->hf;

    if (hFile)
    {
        LARGE_INTEGER pos;
        pos.QuadPart = 0;

        if (!MySetFilePointerEx(hFile, pos, &pos, FILE_CURRENT))
        {
            DWORD dwErr = GetLastError();
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
            ret = (ZPOS64_T)-1;
        }
        else
            ret=pos.QuadPart;
    }
    return ret;
}


long ZCALLBACK win32_seek_file_func (voidpf opaque,voidpf stream,uLong offset,int origin)
{
    DWORD dwMoveMethod=0xFFFFFFFF;
    HANDLE hFile = NULL;

    long ret=-1;
    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream) -> hf;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR :
        dwMoveMethod = FILE_CURRENT;
        break;
    case ZLIB_FILEFUNC_SEEK_END :
        dwMoveMethod = FILE_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET :
        dwMoveMethod = FILE_BEGIN;
        break;
    default: return -1;
    }

    if (hFile != NULL)
    {
        LARGE_INTEGER pos;
        pos.QuadPart = offset;
        if (!MySetFilePointerEx(hFile, pos, NULL, dwMoveMethod))
        {
            DWORD dwErr = GetLastError();
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
            ret = -1;
        }
        else
            ret=0;
    }
    return ret;
}

long ZCALLBACK win32_seek64_file_func (voidpf opaque, voidpf stream,ZPOS64_T offset,int origin)
{
    DWORD dwMoveMethod=0xFFFFFFFF;
    HANDLE hFile = NULL;
    long ret=-1;

    if (stream!=NULL)
        hFile = ((WIN32FILE_IOWIN*)stream)->hf;

    switch (origin)
    {
        case ZLIB_FILEFUNC_SEEK_CUR :
            dwMoveMethod = FILE_CURRENT;
            break;
        case ZLIB_FILEFUNC_SEEK_END :
            dwMoveMethod = FILE_END;
            break;
        case ZLIB_FILEFUNC_SEEK_SET :
            dwMoveMethod = FILE_BEGIN;
            break;
        default: return -1;
    }

    if (hFile)
    {
        LARGE_INTEGER pos;
        pos.QuadPart = offset;
        if (!MySetFilePointerEx(hFile, pos, NULL, dwMoveMethod))
        {
            DWORD dwErr = GetLastError();
            ((WIN32FILE_IOWIN*)stream) -> error=(int)dwErr;
            ret = -1;
        }
        else
            ret=0;
    }
    return ret;
}

int ZCALLBACK win32_close_file_func (voidpf opaque, voidpf stream)
{
    int ret=-1;

    if (stream!=NULL)
    {
        HANDLE hFile;
        hFile = ((WIN32FILE_IOWIN*)stream) -> hf;
        if (hFile != NULL)
        {
            CloseHandle(hFile);
            ret=0;
        }
        free(stream);
    }
    return ret;
}

int ZCALLBACK win32_error_file_func (voidpf opaque,voidpf stream)
{
    int ret=-1;
    if (stream!=NULL)
    {
        ret = ((WIN32FILE_IOWIN*)stream) -> error;
    }
    return ret;
}

void fill_win32_filefunc (zlib_filefunc_def* pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen_file = win32_open_file_func;
    pzlib_filefunc_def->zread_file = win32_read_file_func;
    pzlib_filefunc_def->zwrite_file = win32_write_file_func;
    pzlib_filefunc_def->ztell_file = win32_tell_file_func;
    pzlib_filefunc_def->zseek_file = win32_seek_file_func;
    pzlib_filefunc_def->zclose_file = win32_close_file_func;
    pzlib_filefunc_def->zerror_file = win32_error_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

void fill_win32_filefunc64(zlib_filefunc64_def* pzlib_filefunc_def)
{
    pzlib_filefunc_def->zopen64_file = win32_open64_file_func;
    pzlib_filefunc_def->zread_file = win32_read_file_func;
    pzlib_filefunc_def->zwrite_file = win32_write_file_func;
    pzlib_filefunc_def->ztell64_file = win32_tell64_file_func;
    pzlib_filefunc_def->zseek64_file = win32_seek64_file_func;
    pzlib_filefunc_def->zclose_file = win32_close_file_func;
    pzlib_filefunc_def->zerror_file = win32_error_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

/* iowin32.c end */
int
check_exist_dir(const WCHAR* path)
{
    DWORD fileattr = GetFileAttributesW(path);
    if (fileattr != INVALID_FILE_ATTRIBUTES)
    {
        return (int)((fileattr & FILE_ATTRIBUTE_DIRECTORY) != 0);
    }
    return 0;
}

int check_exist_file(const WCHAR* filename)
{
    FILE* ftestexist;
    int ret = 1;
    ftestexist = FOPEN_FUNC(filename, L"rb");
    if (ftestexist==NULL)
        ret = 0;
    else
        fclose(ftestexist);
    return ret;
}
