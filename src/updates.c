#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <windows.h>
#include "ini_parser.h"
#include "spinlock.h"

extern  file_info_t file_info;
static  bool fn_chrome;
static  bool fx_browser;
static  bool ice_build;
static  bool fn_erase;

LPWSTR WINAPI
wstr_replace(LPWSTR in,size_t in_size,LPCWSTR pattern,LPCWSTR by)
{
    WCHAR *in_ptr = in;
    WCHAR res[MAX_PATH + 1] = { 0 };
    size_t resoffset = 0;
    WCHAR *needle;
    while ((needle = StrStrW(in, pattern)) && resoffset < in_size)
    {
        wcsncpy(res + resoffset, in, needle - in);
        resoffset += needle - in;
        in = needle + (int) wcslen(pattern);
        wcsncpy(res + resoffset, by, wcslen(by));
        resoffset += (int) wcslen(by);
    }
    wcscpy(res + resoffset, in);
    _snwprintf(in_ptr, (int) in_size, L"%s", res);
    return in_ptr;
}

static void 
remove_null_dir(LPCWSTR parent)
{
    HANDLE h_file = NULL;
    WIN32_FIND_DATAW fd = {0};
    WCHAR path_name[MAX_PATH] = {0};
    WCHAR sub[MAX_PATH] = {0};
    if( parent[wcslen(parent) -1] != '\\' )
    {
        _snwprintf(path_name, MAX_PATH, L"%s\\*.*", parent);
    }
    else
    {
        _snwprintf(path_name, MAX_PATH, L"%s*.*", parent);
    }
    h_file = FindFirstFileW(path_name, &fd);
    if(h_file == INVALID_HANDLE_VALUE)
    {
        return;
    }
    do
    {
        if(!(wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")))
        {
            continue;
        }
        else if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            _snwprintf(sub, MAX_PATH, L"%s\\%s",parent, fd.cFileName);
            if (PathIsDirectoryEmptyW(sub))
            {
                RemoveDirectoryW(sub);
            }
            else
            {
                remove_null_dir(sub);
            }
        }
    } while(FindNextFileW(h_file, &fd) != 0);
    FindClose(h_file); 
    h_file = NULL;
}

static void 
erase_dir(LPCWSTR parent)
{
    HANDLE h_file = NULL;
    WIN32_FIND_DATAW fd = {0};
    WCHAR path_name[MAX_PATH] = {0};
    WCHAR sub[MAX_PATH] = {0};
    BOOL  finded = TRUE;
    if( parent[wcslen(parent) -1] != '\\' )
    {
        _snwprintf(path_name, MAX_PATH, L"%s\\*.*", parent);
    }
    else
    {
        _snwprintf(path_name, MAX_PATH, L"%s*.*", parent);
    }
    h_file = FindFirstFileW(path_name, &fd);
    if(h_file == INVALID_HANDLE_VALUE)
    {
        return;
    }
    while(finded) 
    {
        finded = FindNextFileW(h_file, &fd);
        if(wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L".."))
        {
            _snwprintf(sub, MAX_PATH, L"%s\\%s",parent, fd.cFileName);
            if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (_wcsicmp(fd.cFileName, L"plugins") == 0)
                {
                    continue;
                }
                erase_dir(sub);
            }
            else
            {
                DeleteFileW(sub);
            }            
        }
    }
    FindClose(h_file); 
    RemoveDirectoryW(parent); 
    h_file = NULL;
}

static int
exist_root_dir(LPCWSTR wlog, LPWSTR root_path)
{
    FILE *fp = NULL;
    int  res = 1;
    WCHAR *pos = NULL;
    WCHAR root[MAX_PATH+1] = {0};
    WCHAR buf[MAX_PATH+1] = {0};
    if((fp = _wfopen(wlog, L"rb")) == NULL) 
    {
        return -1;
    }
    if (fgetws(buf,MAX_PATH,fp))
    {
        wcsncpy(root, &buf[1], MAX_PATH);
        if ((pos = wcsrchr(root, L'\r')) != NULL)
        {
            *pos = L'\0';
        }
        if ((pos = wcschr(root, L'/')) != NULL)
        {
            root[++pos-root] = L'\0';
        }
        else
        {
            wcsncat(root, L"/", MAX_PATH);
        }
    }
    if (wcslen(root) < 1)
    {
        fclose(fp);
        return -1;
    }
    while (fgetws(buf,MAX_PATH,fp) != NULL)
    {
        if (wcsstr(buf, L"/App/Iceweasel.exe"))
        {
            ice_build = true;
        }
        if (wcsstr(buf, L"/browser/omni.ja"))
        {
            fn_chrome = true;
        }   
        if (wcsstr(buf, L"erased_lists.bat"))
        {
            fn_erase = true;
        }         
        if ((pos = wcsrchr(buf, L'\r')) != NULL)
        {
            *pos = L'\0';
        }
        if (wcsncmp(buf, root, wcslen(root)) != 0)
        {
            res = 0;
        }
    }
    if (res && wcslen(root) > 1)
    {
        root[wcslen(root)-1] = L'\0';
        wcsncpy(root_path, root, MAX_PATH);
    }
    fclose(fp);
    return res;
}

static bool 
move_file(LPCWSTR src_path, LPCWSTR dst_path)
{
    uint32_t attrs = 0;
    if (!(src_path && dst_path))
    {
        return false;
    }
    attrs = GetFileAttributesW(dst_path);
    // 有只读属性
    if(attrs & FILE_ATTRIBUTE_READONLY)
    {
        // 取消只读属性
        attrs &= ~FILE_ATTRIBUTE_READONLY;
        SetFileAttributesW(dst_path, attrs);

    }
    if (!MoveFileExW(src_path, dst_path, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING))
    {
        printf("move %ls failed, error[%lu]\n", src_path, GetLastError());
        return false;
    }
    return true;
}

static bool 
move_form_src(LPCWSTR wlog, LPCWSTR dst, LPCWSTR root, void *pr)
{
    FILE *fp = NULL;
    bool res = true;
    bool is_root = false;
    WCHAR *unofficial = (WCHAR *)pr;
    bool ice_unofficial = unofficial != NULL;
    size_t len = 0;
    size_t line = 2;
    WCHAR *pos = NULL;
    WCHAR buf[MAX_PATH+1] = {0};
    
    if((fp = _wfopen(wlog, L"rb")) == NULL) 
    {
        return false;
    }
    if (root && wcslen(root) > 1)
    {
        line = 1;
        is_root = true;
        len = wcslen(root);
    }
    if (ice_unofficial)
    {
        WCHAR oldname[MAX_PATH+1] = {0};
        WCHAR newname[MAX_PATH+1] = {0};
        _snwprintf(oldname, MAX_PATH, L"%s\\%s", root, L"App");
        _snwprintf(newname, MAX_PATH, L"%s\\%s", root, unofficial);
        if (_wrename(oldname ,newname))
        {
            printf("Error occurred.\n");
            return false;
        }
    }
    while (fgetws(buf,MAX_PATH,fp) != NULL)
    {
        WCHAR dst_path[MAX_PATH+1] = {0};
        if (line++ == 1)
        {
            continue;
        }
        if ((pos = wcsrchr(buf, L'\r')) != NULL)
        {
            *pos = L'\0';
        }
        if (ice_unofficial)
        {
            WCHAR tmp[MAX_PATH+1] = {0};
            _snwprintf(tmp, MAX_PATH, L"%s%s", L"\\", unofficial);
            wstr_replace(buf, MAX_PATH, L"/App", tmp);
        }  
        if (is_root)
        {
            wcsncpy(dst_path, dst, MAX_PATH);
            wcsncat(dst_path, buf+len, MAX_PATH);
        }
        else
        {
            wcsncpy(dst_path, dst, MAX_PATH);
            wcsncat(dst_path, L"\\", MAX_PATH);
            wcsncat(dst_path, buf, MAX_PATH);
        }      
        if (true)
        {
            wchr_replace(dst_path);
        }
        if (PathIsDirectoryW(buf))
        {   
       
            if (!PathIsDirectoryW(dst_path))
            {
                create_dir(dst_path);
            }
        }
        else if (move_file(buf, dst_path))
        {
            remove_null_dir(root);
            if (RemoveDirectoryW(root))
            {
                printf("Update success ^_^\n");
            }
        }
        else
        {
            res = false;
        }
    }
    fclose(fp);
    return res;
}

bool WINAPI 
getw_cwd(LPWSTR lpstrName, DWORD wlen)
{
    int   i = 0;
    WCHAR lpFullPath[MAX_PATH+1] = {0};
    if ( GetModuleFileNameW(NULL,lpFullPath,MAX_PATH)>0 )
    {
        for( i=(int)wcslen(lpFullPath); i>0; i-- )
        {
            if (lpFullPath[i] == L'\\')
            {
                lpFullPath[i] = L'\0';
                break;
            }
        }
        if ( i > 0 )
        {
            i = _snwprintf(lpstrName, wlen, L"%s", lpFullPath);
        }
    }
    return (i>0 && i<(int)wlen);
}

static bool 
is_ice(void)
{
    bool res = false;
    char *names = NULL;
    char ini[MAX_PATH+1] = {0};
    if (!init_file_strings(L"application.ini", ini))
    {
        return false;
    }
    if (!ini_read_string("App", "RemotingName", &names, ini))
    {
        return false;
    }
    res = _stricmp(names, "Iceweasel") == 0;
    free(names);
    return res;
}

static int
do_update(LPCWSTR src0, LPCWSTR dst0)
{
    int res = -1;
    if (!src0 || !dst0)
    {
        return res;
    }
    WCHAR dst[MAX_PATH+1] = {0};
    WCHAR root[MAX_PATH+1] = {0};
    WCHAR wlog[MAX_PATH+1] = {0};
    WCHAR strip[MAX_PATH+1] = {0};
    wcsncpy(dst, dst0, MAX_PATH);
    wcsncpy(wlog, src0, MAX_PATH);
    wcsncat(wlog, L"\\update.log", MAX_PATH);
    if (!PathFileExistsW(wlog))
    {
        return res;
    }
    if (!SetCurrentDirectoryW(src0))
    {
        return res;
    }
    if ((res = exist_root_dir(wlog, root)) < 0)
    {
        printf("exist_root_dir return error\n");
        return res;
    }
    if (fn_chrome)
    {
        WCHAR chrome[MAX_PATH+1] = {0};
        wcsncpy(chrome, file_info.process, MAX_PATH);
        PathRemoveFileSpecW(chrome);
        PathAppendW(chrome,L"browser");
        // 删除browser子目录
        erase_dir(chrome);
    }
    if (res > 0)
    {
        printf("yes, path Is root Director\n");
        wcsncpy(strip, dst0, MAX_PATH);
        PathStripPathW(strip);
        if (is_ice())
        {
            if (ice_build && (_wcsicmp(strip, L"App") == 0))
            {
                // iceweasel official package
                PathRemoveFileSpecW(dst);
                if (move_form_src(wlog, dst, root, NULL))
                {
                    return 0;
                }                    
            }
            else if (ice_build && (_wcsicmp(strip, L"App") != 0))
            {
                PathRemoveFileSpecW(dst);
                if (move_form_src(wlog, dst, root, strip))
                {
                    return 0;
                }                
            }          
        }
        else
        {
            fx_browser = true;
        }
        if (move_form_src(wlog, dst, root, NULL))
        {
            return 0;
        }
    }
    else
    {
        printf("not exist root director\n");
    }
    return res;
}

bool WINAPI 
unknown_builds(void)
{
    return (fx_browser && ice_build);
}

int WINAPI
update_thread(void *p)
{
    // 准备复制更新文件到file_info.process所在目录
    WCHAR dst[MAX_PATH+1] = {0};
    wcsncpy(dst, file_info.process, MAX_PATH);
    PathRemoveFileSpecW(dst);
    if (do_update(file_info.unzip_dir, dst) != 0)
    {
        printf("do_update false!\n");
        return 1;
    } 
    // 自定义erased_lists.bat文件,用于清理多余配置.
    if (fn_erase)
    {
        WCHAR r_list[MAX_PATH+1] = {0};
        wcsncpy(r_list, dst, MAX_PATH);
        if (ice_build)
        {
            PathRemoveFileSpecW(r_list);
            wcsncpy(dst, r_list, MAX_PATH);
        }
        if (PathAppendW(r_list,L"erased_lists.bat") && PathFileExistsW(r_list) && SetCurrentDirectoryW(dst))
        {
            exec_ppv("cmd.exe /c erased_lists.bat", NULL, 0);
            Sleep(1000);
        }
    }
    return (0);
}
