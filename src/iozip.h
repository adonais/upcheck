#ifndef _ZLIBIOAPI64_H
#define _ZLIBIOAPI64_H

#if (!defined(_WIN32)) && (!defined(WIN32)) && (!defined(__APPLE__))

  // Linux needs this to support file operation on files larger then 4+GB
  // But might need better if/def to select just the platforms that needs them.

        #ifndef __USE_FILE_OFFSET64
                #define __USE_FILE_OFFSET64
        #endif
        #ifndef __USE_LARGEFILE64
                #define __USE_LARGEFILE64
        #endif
        #ifndef _LARGEFILE64_SOURCE
                #define _LARGEFILE64_SOURCE
        #endif
        #ifndef _FILE_OFFSET_BIT
                #define _FILE_OFFSET_BIT 64
        #endif

#endif

#if defined(_WIN32) && (!(defined(_CRT_SECURE_NO_WARNINGS)))
        #define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdint.h>
#include <zlib.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ioapi.h */
/* Maximum unsigned 32-bit value used as placeholder for zip64 */
#define MAXU32 0xffffffff
typedef uint64_t ZPOS64_T;

#define ZLIB_FILEFUNC_SEEK_CUR (1)
#define ZLIB_FILEFUNC_SEEK_END (2)
#define ZLIB_FILEFUNC_SEEK_SET (0)

#define ZLIB_FILEFUNC_MODE_READ      (1)
#define ZLIB_FILEFUNC_MODE_WRITE     (2)
#define ZLIB_FILEFUNC_MODE_READWRITEFILTER (3)

#define ZLIB_FILEFUNC_MODE_EXISTING (4)
#define ZLIB_FILEFUNC_MODE_CREATE   (8)

#define FOPEN_FUNC(filename, mode) _wfopen(filename, mode)
#define FTELLO_FUNC(stream) _ftelli64(stream)
#define FSEEKO_FUNC(stream, offset, origin) _fseeki64(stream, offset, origin)

#ifndef ALLOC
# define ALLOC(size) (malloc(size))
#endif

#ifndef Z_BUFSIZE
#define Z_BUFSIZE (64*1024) //(16384)
#endif

#ifndef Z_MAXFILENAMEINZIP
#define Z_MAXFILENAMEINZIP (256)
#endif

#ifndef ZCALLBACK
 #if (defined(WIN32) || defined(_WIN32) || defined (WINDOWS) || defined (_WINDOWS)) && defined(CALLBACK) && defined (USEWINDOWS_CALLBACK)
   #define ZCALLBACK CALLBACK
 #else
   #define ZCALLBACK
 #endif
#endif

typedef voidpf   (ZCALLBACK *open_file_func)      (voidpf opaque, const WCHAR* filename, int mode);
typedef uLong    (ZCALLBACK *read_file_func)      (voidpf opaque, voidpf stream, void* buf, uLong size);
typedef uLong    (ZCALLBACK *write_file_func)     (voidpf opaque, voidpf stream, const void* buf, uLong size);
typedef int      (ZCALLBACK *close_file_func)     (voidpf opaque, voidpf stream);
typedef int      (ZCALLBACK *testerror_file_func) (voidpf opaque, voidpf stream);

typedef long     (ZCALLBACK *tell_file_func)      (voidpf opaque, voidpf stream);
typedef long     (ZCALLBACK *seek_file_func)      (voidpf opaque, voidpf stream, uLong offset, int origin);

/* tm_zip contain date/time info */
typedef struct tm_zip_s
{
    int tm_sec;            /* seconds after the minute - [0,59] */
    int tm_min;            /* minutes after the hour - [0,59] */
    int tm_hour;           /* hours since midnight - [0,23] */
    int tm_mday;           /* day of the month - [1,31] */
    int tm_mon;            /* months since January - [0,11] */
    int tm_year;           /* years - [1980..2044] */
} tm_zip;

/* here is the "old" 32 bits structure structure */
typedef struct zlib_filefunc_def_s
{
    open_file_func      zopen_file;
    read_file_func      zread_file;
    write_file_func     zwrite_file;
    tell_file_func      ztell_file;
    seek_file_func      zseek_file;
    close_file_func     zclose_file;
    testerror_file_func zerror_file;
    voidpf              opaque;
} zlib_filefunc_def;

typedef ZPOS64_T (ZCALLBACK *tell64_file_func)    (voidpf opaque, voidpf stream);
typedef long     (ZCALLBACK *seek64_file_func)    (voidpf opaque, voidpf stream, ZPOS64_T offset, int origin);
typedef voidpf   (ZCALLBACK *open64_file_func)    (voidpf opaque, const WCHAR* filename, int mode);

typedef struct zlib_filefunc64_def_s
{
    open64_file_func    zopen64_file;
    read_file_func      zread_file;
    write_file_func     zwrite_file;
    tell64_file_func    ztell64_file;
    seek64_file_func    zseek64_file;
    close_file_func     zclose_file;
    testerror_file_func zerror_file;
    voidpf              opaque;
} zlib_filefunc64_def;

void fill_fopen64_filefunc (zlib_filefunc64_def* pzlib_filefunc_def);
void fill_fopen_filefunc (zlib_filefunc_def* pzlib_filefunc_def);

/* now internal definition, only for zip.c and unzip.h */
typedef struct zlib_filefunc64_32_def_s
{
    zlib_filefunc64_def zfile_func64;
    open_file_func      zopen32_file;
    tell_file_func      ztell32_file;
    seek_file_func      zseek32_file;
} zlib_filefunc64_32_def;


#define ZREAD64(filefunc,filestream,buf,size)     ((*((filefunc).zfile_func64.zread_file))   ((filefunc).zfile_func64.opaque,filestream,buf,size))
#define ZWRITE64(filefunc,filestream,buf,size)    ((*((filefunc).zfile_func64.zwrite_file))  ((filefunc).zfile_func64.opaque,filestream,buf,size))
#define ZCLOSE64(filefunc,filestream)             ((*((filefunc).zfile_func64.zclose_file))  ((filefunc).zfile_func64.opaque,filestream))
#define ZERROR64(filefunc,filestream)             ((*((filefunc).zfile_func64.zerror_file))  ((filefunc).zfile_func64.opaque,filestream))

voidpf call_zopen64 (const zlib_filefunc64_32_def* pfilefunc,const void*filename,int mode);
long    call_zseek64 (const zlib_filefunc64_32_def* pfilefunc,voidpf filestream, ZPOS64_T offset, int origin);
ZPOS64_T call_ztell64 (const zlib_filefunc64_32_def* pfilefunc,voidpf filestream);

void    fill_zlib_filefunc64_32_def_from_filefunc32(zlib_filefunc64_32_def* p_filefunc64_32,const zlib_filefunc_def* p_filefunc32);

#define ZOPEN64(filefunc,filename,mode)         (call_zopen64((&(filefunc)),(filename),(mode)))
#define ZTELL64(filefunc,filestream)            (call_ztell64((&(filefunc)),(filestream)))
#define ZSEEK64(filefunc,filestream,pos,mode)   (call_zseek64((&(filefunc)),(filestream),(pos),(mode)))

/* ioapi.h end */

/* iowin32.h */
void fill_win32_filefunc OF((zlib_filefunc_def* pzlib_filefunc_def));
void fill_win32_filefunc64 OF((zlib_filefunc64_def* pzlib_filefunc_def));
void fill_win32_filefunc64A OF((zlib_filefunc64_def* pzlib_filefunc_def));
void fill_win32_filefunc64W OF((zlib_filefunc64_def* pzlib_filefunc_def));
/* iowin32.h end */

int check_exist_dir(const WCHAR* path);
int check_exist_file(const WCHAR* filename);

#ifdef __cplusplus
}
#endif

#endif /* _unz64_H */
