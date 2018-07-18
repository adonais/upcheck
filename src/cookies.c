#include <stdio.h>
#include <stdint.h>
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <shlwapi.h>
#include "spinlock.h"
#include "sqlite3.h"

extern file_info_t file_info;
static char baidu_login[256+1];
static char baidu_set[64+1];

int WINAPI
parse_baidu_cookies(char *cookies, int len)
{
    if (strlen(baidu_login) < 2 || strlen(baidu_set) < 2)
    {
        printf("parse_baidu_cookies return false\n");
        return -1;
    }
    wnsprintfA(cookies, len, "%s; %s", baidu_login, baidu_set);
    return 0;
}

static 
int parse_sqlite_cookies(void *hfile, int count, char **column, char **names)
{
    char only[8] = {0};
    char secure[8] = {0};
    char expir[32] = {0};
    char path[32] = {0};
    char tmp_t[VALUE_LEN+1] = {0};
    char host[VALUE_LEN+1] = {0};
    char name[VALUE_LEN+1] = {0};
    char *value = NULL;
    char line[2048+1] = {0};
	for(int i=0; i<count; i++)
    {
		if(!_stricmp(names[i], "host"))
			strncpy(tmp_t, column[i], VALUE_LEN);
		if(!_stricmp(names[i], "name"))
			strncpy(name, column[i], VALUE_LEN);
		if(!_stricmp(names[i], "value"))
			value = _strdup(column[i]);
		if(!_stricmp(names[i], "path"))
			strncpy(path, column[i], 32);
		if(!_stricmp(names[i], "expiry"))
			strncpy(expir, column[i], 32);
		if(!_stricmp(names[i], "isSecure"))
			strncpy(secure, column[i], 8);
		if(!_stricmp(names[i], "isHttpOnly"))
			strncpy(only, column[i], 8);
	}	
    if (atoi(only))
    {
        wnsprintfA(host, VALUE_LEN, "#HttpOnly_%s", tmp_t);
        wnsprintfA(only, 8, "TRUE");
    }
    else
    {
        wnsprintfA(host, VALUE_LEN, "%s", tmp_t);
        wnsprintfA(only, 8, "FALSE");
    }
    if (!atoi(secure))
    {
        wnsprintfA(secure, 8, "FALSE");
    }
    else
    {
        wnsprintfA(secure, 8, "TRUE");
    }
    {
        LPCSTR host1 = "#HttpOnly_.nuomi.com";
        LPCSTR host2 = "#HttpOnly_.pcs.baidu.com";
        LPCSTR key1= "BDUSS";
        LPCSTR key2= "pcsett";
        if (strcmp(host, host1) == 0 && strcmp(name, key1) == 0)
        {
            wnsprintfA(baidu_login, 256, "%s=%s", key1, value);
        }
        if (strcmp(host, host2) == 0 && strcmp(name, key2) == 0)
        {
            wnsprintfA(baidu_set, 64, "%s=%s", key2, value);
        }
    }
	wnsprintfA(line, 2048, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", host, only, path, secure, expir, name, value);
    if (value)
    {
        free(value);
    }
    DWORD written;
    WriteFile(hfile, line, strlen(line), &written, NULL);
	return 0;
}

static 
int sqlite_txt(LPCWSTR cookie_path, HANDLE hfile)
{
	sqlite3 *db;
    char    *err = NULL;
	char     utf8[MAX_PATH+2];
	int      rc = -1;
    if (!WideCharToMultiByte(CP_UTF8, 0, cookie_path, -1, utf8, sizeof(utf8), NULL, NULL))
    {
        printf("WideCharToMultiByte cookie_path error: %lu\n", GetLastError());
    }
	if ((rc = sqlite3_open(utf8, &db)) != SQLITE_OK) 
    {
        printf("sqlite3_open false\n");
		return -1;
    }
	rc = sqlite3_exec(db, "SELECT host,isHttpOnly,path,isSecure,expiry,name,value FROM moz_cookies;", parse_sqlite_cookies, (void *)hfile, &err);
    if (rc != SQLITE_OK)
    {
        printf("select table error : %s\n",err);
        if (err)
        {
            sqlite3_free(err);
        }
    }
	sqlite3_close(db);
	return rc;
}

int WINAPI
dump_cookies(const wchar_t *sql_path)
{
    DWORD written = 0;
    char  temp_path[MAX_PATH];
    char  cookies[MAX_PATH];
	LPCSTR notes = "# Netscape HTTP Cookie File\n"
		           "# select host,isHttpOnly,path,isSecure,expiry,name,value from moz_cookies\n\n";
	if (sql_path == NULL || !PathFileExistsW(sql_path)) 
    {
        printf("%S no exist\n", sql_path);
		return -1;
    }
    if(!GetTempPathA(sizeof(temp_path),temp_path)) 
    {
        return -1;
    }
    if(!GetTempFileNameA(temp_path, "cke", 0, cookies)) 
    {
        printf("GetTempFileNameA return false\n");
        return -1;
    }
    file_info.cookie_handle = CreateFileA(cookies,
                              GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                              NULL, TRUNCATE_EXISTING,
                              FILE_ATTRIBUTE_TEMPORARY |
                              FILE_FLAG_DELETE_ON_CLOSE,
                              NULL);
    if (INVALID_HANDLE_VALUE == file_info.cookie_handle)
    {
        printf("CreateFileA false\n");
        file_info.cookie_handle = NULL;
        return -1;
    }
    WriteFile(file_info.cookie_handle, notes, strlen(notes), &written, NULL);
	if (sqlite_txt(sql_path, file_info.cookie_handle) != SQLITE_OK)
    {
        CloseHandle(file_info.cookie_handle);
        file_info.cookie_handle = NULL;
    }
    else
    {
        FlushFileBuffers(file_info.cookie_handle);
        wnsprintfA(file_info.cookies, MAX_PATH, "%s", cookies);
    }
	return 0;
}
