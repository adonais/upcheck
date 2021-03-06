#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "ini_parser.h"
#include "spinlock.h"

#pragma comment(lib, "advapi32.lib")

volatile long g_locked = 0;

#ifdef DEBUG_LOG
static char logfile_buf[MAX_PATH];

void __cdecl 
logmsg(const char * format, ...)
{
    enter_spinlock();
    va_list args;
    char    buffer[MAX_MESSAGE];
    va_start (args, format);
    if (strlen(logfile_buf) > 0)
    {
        FILE *pFile = NULL;
        int  len = wvnsprintfA(buffer,MAX_MESSAGE,format, args);
        if ( len > 0 && len < MAX_MESSAGE )
        {
            buffer[len] = '\0';
            if ( (pFile = fopen(logfile_buf,"a+")) != NULL )
            {
                fwrite(buffer,strlen(buffer),1,pFile);
                fclose(pFile);
            }
        }
    }
    va_end(args);
    leave_spinlock();
    return;
}

void WINAPI 
init_logs(void)
{
    if ( *logfile_buf == '\0' && GetEnvironmentVariableA("APPDATA",logfile_buf,MAX_PATH) > 0 )
    {
        strncat(logfile_buf,"\\",MAX_PATH);
        strncat(logfile_buf,"upcheck.log",MAX_PATH);
    }
}
#endif

uint64_t WINAPI
ini_read_uint64(const char *sec, const char *key, const char *ini)
{
    char *m_str = NULL;
    uint64_t result = 0;
    if (ini_read_string(sec, key, &m_str, ini))
    {
        result = _strtoui64(m_str, NULL, 10);
        free(m_str);
    }
    return result;
}

void WINAPI 
wchr_replace(LPWSTR path)        /* 替换unix风格的路径符号 */
{
    LPWSTR   lp = NULL;
    intptr_t pos;
    do
    {
        lp =  StrChrW(path,L'/');
        if (lp)
        {
            pos = lp-path;
            path[pos] = L'\\';
        }
    } while (lp!=NULL);
    return;
}

bool WINAPI 
exists_dir(LPCWSTR path) 
{
    DWORD fileattr = GetFileAttributesW(path);
    if (fileattr != INVALID_FILE_ATTRIBUTES)
    {
        return (fileattr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    return false;
}

bool WINAPI 
create_dir(LPCWSTR dir)
{
    LPWSTR p = NULL;
    WCHAR  tmp_name[MAX_PATH];
    wcscpy(tmp_name, dir);
    p = wcschr(tmp_name, L'\\');
    for ( ; p != NULL; *p = L'\\', p = wcschr(p+1, L'\\') )
    {
        *p = L'\0';
        if (exists_dir(tmp_name))
        {
            continue;
        }
        CreateDirectoryW(tmp_name, NULL);
    }
    return (CreateDirectoryW(tmp_name, NULL)||GetLastError() == ERROR_ALREADY_EXISTS);
}

bool WINAPI
path_combine(LPWSTR lpfile, int len)
{
#define SIZE 128
    int n = 1;
    if (NULL == lpfile || *lpfile == L' ')
    {
        return false;
    }
    if (lpfile[1] != L':')
    {
        WCHAR modname[SIZE + 1] = { 0 };
        if (GetModuleFileNameW(NULL, modname, SIZE) > 0)
        {
            WCHAR tmp_path[MAX_PATH] = { 0 };
            if (PathRemoveFileSpecW(modname) && PathCombineW(tmp_path, modname, lpfile))
            {
                n = wnsprintfW(lpfile, len, L"%ls", tmp_path);
            }
        }
    }
    return (n > 0 && n < len);
#undef SIZE
}

int WINAPI
get_cpu_works(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int) (si.dwNumberOfProcessors);
}

void WINAPI
enter_spinlock(void)
{
    SIZE_T spinCount = 0;
    // Wait until the flag is false.
    while (_InterlockedCompareExchange(&g_locked, 1, 0) != 0)
    {
        // Prevent the loop from being too busy.
        if (spinCount < 32)
        {
            Sleep(0);
        }
        else
        {
            Sleep(1);
        }
        spinCount++;
    }
}

void WINAPI
leave_spinlock(void)
{
    // No need to generate a memory barrier here, since InterlockedExchange()
    // generates a full memory barrier itself.
    InterlockedExchange(&g_locked, 0);
}

static char *
memstr(char *full_data, int full_data_len, const char *substr)
{
    if (full_data == NULL || full_data_len <= 0 || substr == NULL)
    {
        return NULL;
    }

    if (*substr == '\0')
    {
        return NULL;
    }

    int sublen = (int)strlen(substr);

    int i;
    char *cur = full_data;
    int last_possible = full_data_len - sublen + 1;
    for (i = 0; i < last_possible; i++)
    {
        if (*cur == *substr)
        {
            // assert(full_data_len - i >= sublen);
            if (memcmp(cur, substr, sublen) == 0)
            {
                // found
                return cur;
            }
        }
        cur++;
    }

    return NULL;
}

bool WINAPI
init_file_strings(LPCWSTR names, char *out_path)
{
    WCHAR filename[MAX_PATH];
    if (!GetModuleFileNameW(NULL, filename, MAX_PATH))
    {
        return false;
    }
    if (!PathRemoveFileSpecW(filename))
    {
        return false;
    }
    if (!PathAppendW(filename,names))
    {
        return false;
    }
    if (!PathFileExistsW(filename))
    {
        return false;
    }
    return (WideCharToMultiByte(CP_UTF8, 0, filename, -1, out_path, MAX_PATH, NULL, NULL)>0);
}

bool WINAPI
find_local_str(char *result, int len)
{
    FILE *fp = NULL;
    char *u = NULL;
    bool found = false;
    const char *ctags = "/global/intl.css";
    char buff[BUFF_MAX+1] = {0};
    char omni[MAX_PATH] = {0};
    if (!init_file_strings(L"omni.ja", omni))
    {
        return false;
    }
    fp = fopen(omni, "rb");
    if (fp == NULL)
    {
        printf("open omni.ja false\n");
        return false;
    }
    while (fread(buff, BUFF_MAX, 1, fp) > 0)
    {
        if ((u = memstr(buff, BUFF_MAX, ctags)) != NULL)
        {
            found = true;
            break;
        }
    }
    if (found)
    {
        strncpy(result, u-5, 5);
    }
    if (fp)
    {
        fclose(fp);
    }
    return found;
}

/* 将hex编码的MD5转换成字符串 */
static void 
md5_to_str(byte* in_md5_hex, char* out_md5_str)
{
    int i = 0;

    for (i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(out_md5_str + i * 2, "%.2x", in_md5_hex[i]);
    }
    out_md5_str[MD5_DIGEST_LENGTH * 2] = '\0';
}

bool WINAPI 
get_file_md5(LPCWSTR path, char* md5_str)
{
    bool res = false;
    BYTE*  pbHash=NULL;
    byte*  rgbFile=NULL;
    HANDLE hFile=NULL;
    HCRYPTPROV hProv=0;
    HCRYPTPROV hHash=0;
    do
    {
    #define MD5_SIZE 1024*1000*10
        DWORD cbRead;
        DWORD dwHashLen=sizeof(DWORD);
        
        hFile=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
        if (hFile==INVALID_HANDLE_VALUE)                                        //如果CreateFile调用失败
        {
            printf("CreateFile error : %lu\n", GetLastError());
            return false;
        }
        
        if(!CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))       //获得CSP中一个密钥容器的句柄
        {
            printf("CryptAcquireContext error : %lu\n", GetLastError());
            break;
        }
        
        if(!CryptCreateHash(hProv,CALG_MD5,0,0,&hHash))     //初始化对数据流的hash，创建并返回一个与CSP的hash对象相关的句柄
        {
            printf("CryptCreateHash error : %lu\n", GetLastError());
            break;
        }
        if((rgbFile=(byte*)SYS_MALLOC(MD5_SIZE)) == NULL)
        {
            printf("allocation failed\n");
            break;

        }
        while (ReadFile(hFile,rgbFile,MD5_SIZE,&cbRead,NULL))
        {
            if (cbRead==0)        //读取文件
            {
                break;
            }
            if(!CryptHashData(hHash,rgbFile,cbRead,0))      //hash文件
            {
                printf("CryptHashData error : %lu\n", GetLastError());
                break;
            }
        }
        if (!CryptGetHashParam(hHash,HP_HASHVAL,NULL,&dwHashLen,0))      //获取内存长度
        {
            printf("CryptGetHashParam error : %lu\n", GetLastError());
        }
        if((pbHash=(byte*)SYS_MALLOC(dwHashLen)) == NULL)
        {
            printf("allocation failed\n");
            break;

        }
        if(CryptGetHashParam(hHash,HP_HASHVAL,pbHash,&dwHashLen,0))  //获得md5值
        {
            md5_to_str(pbHash, md5_str);
            res = true;
        }
    #undef MD5_SIZE
    }while (0);
	if(hHash)          //销毁hash对象
	{
		CryptDestroyHash(hHash);
	}
	if(hProv)
	{
		CryptReleaseContext(hProv,0);
	}
    if (hFile)
    {
        CloseHandle(hFile); 
    }
    if (rgbFile)
    {
        SYS_FREE(rgbFile);
    }
    if (pbHash)
    {
        SYS_FREE(pbHash);
    }
    return res;
}

bool WINAPI
merge_file(LPCWSTR path1,LPCWSTR path2,LPCWSTR name)
{
    size_t rc1,rc2;
    FILE *fp1 = NULL, *fp2 = NULL, *fp3 = NULL;
    bool res = false;
    unsigned char buf[BUFSIZE];
    do
    {
        fp1 = _wfopen(path1, L"rb");
        if (fp1 == NULL)
        {
            break;
        }
        fp2 = _wfopen(path2, L"rb");
        if (fp2 == NULL)
        {
            break;
        }
        fp3 = _wfopen(name, L"wb");
        if (fp3 == NULL)
        {
            break;
        }
        while((rc1 = fread(buf, 1, BUFSIZE, fp1)) != 0)
        {
            fwrite(buf, 1, rc1, fp3);
        } 
        while((rc2 = fread(buf, 1, BUFSIZE, fp2)) != 0)
        {
            fwrite(buf, 1, rc2, fp3);
        }
        res = true;
    }while (0);
    if (fp1)
    {
        fclose(fp1);
    }
    if (fp2)
    {
        fclose(fp2);
    }
    if (fp3)
    {
        fclose(fp3);
    }
    return res;
}

bool WINAPI
get_files_lenth(LPCWSTR path, int64_t *psize)
{
    struct _stati64 statbuf;
    if (_wstati64(path,&statbuf))
    {
        return false;
    }
    *psize = statbuf.st_size;
    return true;
}

bool WINAPI 
exec_ppv(LPCSTR cmd, LPCSTR pcd, int flags)
{
    bool res = false;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    DWORD dw = 0;
    WCHAR *wdir = NULL;
    WCHAR *process = utf8_to_utf16(cmd);
    if (!process)
    {
        return false;
    }
    do
    {
        if (NULL != pcd)
        {
            wdir = utf8_to_utf16(pcd);
            if (!wdir)
            {
                break;
            }
        }
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        if (!flags)
        {
            si.wShowWindow = SW_HIDE;
            dw |= CREATE_NEW_PROCESS_GROUP;
        }
        else
        {
            si.wShowWindow = SW_SHOWNOACTIVATE;
        }
        if(!CreateProcessW(NULL,
                          process,
                          NULL,
                          NULL,
                          false,
                          dw,
                          NULL,
                          wdir,   
                          &si,&pi))
        {
            printf("CreateProcessw error %lu\n", GetLastError());
            break;
        }
        else
        {
            res = true;
        }
        CloseHandle(pi.hProcess);        
    }while(0);
    if (wdir)
    {
        free(wdir);
    }
    if (process)
    {
        free(process);
    }    
    return res;
}

bool WINAPI
get_name_self(LPWSTR lpstrName, DWORD wlen)
{
    int   i = 0;
    WCHAR lpFullPath[MAX_PATH+1]= {0};
    if (GetModuleFileNameW(NULL,lpFullPath,MAX_PATH)>0)
    {
        for(i=(int)wcslen(lpFullPath); i>0; i--)
        {
            if (lpFullPath[i] == L'\\')
                break;
        }
        if (i > 0)
        {
            i = _snwprintf(lpstrName,wlen,L"%ls",lpFullPath+i+1);
        }
    }
    return (i>0 && i<(int)wlen);
}

bool WINAPI
search_process(LPCWSTR names)
{
    bool   ret = false;
    PROCESSENTRY32W pe32 = {0};
    HANDLE hSnapshot = INVALID_HANDLE_VALUE;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    pe32.dwSize=sizeof(pe32);
    if (!Process32FirstW(hSnapshot,&pe32))
    {
        return false;
    }        
    do
    {
        if (!_wcsicmp(pe32.szExeFile, names) && pe32.th32ProcessID != GetCurrentProcessId())
        {
            ret = true;
            break;
        }
    } while (Process32NextW(hSnapshot,&pe32));
    CloseHandle(hSnapshot);
    return ret;
}

char* WINAPI
url_decode (const char *input)
{
	int input_length = (int)strlen(input);
	size_t output_length = (input_length + 1);
	char *working, *output;
	if ((working = output = SYS_MALLOC(output_length)) == NULL)
	{
	    return NULL;
	}
	while(*input)
	{
		if(*input == '%')
		{
			char buffer[3] = { input[1], input[2], 0 };
			*working++ = (char)strtol(buffer, NULL, 16);
			input += 3;
		}
		else
		{
			*working++ = *input++;
		}
	}
	*working = 0;  //null terminate
	return output;
}
