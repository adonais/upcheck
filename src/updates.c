#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <windows.h>
#include "spinlock.h"
#include "progressui.h"

#define PROGRESS_PREPARE_SIZE 10.0f
#define PROGRESS_EXECUTE_SIZE 99.0f
#define PROGRESS_FINISH_SIZE   1.0f
extern  file_info_t file_info;
bool    ice_build = false;

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
    wnsprintfW(in_ptr, (int) in_size, L"%ls", res);
    return in_ptr;
}

static void 
remove_dir(LPCWSTR parent)
{
    HANDLE h_file = NULL;
    WIN32_FIND_DATAW fd = {0};
    WCHAR path_name[MAX_PATH] = {0};
    WCHAR tmp[MAX_PATH] = {0};
    WCHAR sub[MAX_PATH] = {0};
    if( parent[wcslen(parent) -1] != '\\' )
    {
        wnsprintfW(path_name,MAX_PATH, L"%ls\\*.*", parent);
    }
    else
    {
        wnsprintfW(path_name,MAX_PATH, L"%ls*.*", parent);
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
             wnsprintfW(sub,MAX_PATH, L"%s\\%s",parent, fd.cFileName);
             if (PathIsDirectoryEmptyW(sub))
             {
                 RemoveDirectoryW(sub);
             }
             else
            {
                 remove_dir(sub);
            }
        }
    } while(FindNextFileW(h_file, &fd) != 0);
    FindClose(h_file); 
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
    if (!MoveFileExW(src_path, dst_path, MOVEFILE_REPLACE_EXISTING))
    {
        printf("move file false, error[%lu]\n", GetLastError());
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
    float percent = PROGRESS_PREPARE_SIZE;
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
        wnsprintfW(oldname, MAX_PATH, L"%ls\\%ls", root, L"App");
        wnsprintfW(newname, MAX_PATH, L"%ls\\%ls", root, unofficial);
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
            wnsprintfW(tmp, MAX_PATH, L"%ls%ls", L"\\", unofficial);
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
            if (percent < PROGRESS_EXECUTE_SIZE)
            {
                percent += PROGRESS_FINISH_SIZE;
                update_progress(percent);
            }
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
            remove_dir(root);
            if (RemoveDirectoryW(root))
            {
                printf("haha ^_^\n");
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
            i = wnsprintfW(lpstrName,wlen,L"%ls",lpFullPath);
        }
    }
    return (i>0 && i<(int)wlen);
}

static 
bool is_ice(void)
{
    WCHAR ini[MAX_PATH+1] = {0};
    WCHAR names[32] = {0};
    if (init_file_strings(L"application.ini", ini) < 0)
    {
        return false;
    }
    if (!read_appkey(L"App", L"RemotingName", names, sizeof(names), ini))
    {
        return false;
    }
    return (_wcsicmp(names, L"Iceweasel") == 0);
}

static int
do_update(LPCWSTR src0, LPCWSTR dst0)
{
    int res = 1;
    if (!src0 || !dst0)
    {
        return res;
    }
    bool  ice_official = false;
    bool  ice_unofficial = false;
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
    if (res > 0)
    {
        printf("yes, path Is root Director\n");
        wcsncpy(strip, dst0, MAX_PATH);
        PathStripPathW(strip);
        if (is_ice())
        {
            ice_build = false;
            if (_wcsicmp(strip, L"App") == 0)
            {
                ice_official = true;
            }
            else
            {
                ice_unofficial = true;
            }
        }
        else if (ice_build)
        {
            ice_unofficial = true;
        }
        if (ice_official || ice_unofficial)
        {
            PathRemoveFileSpecW(dst);
        }
        if (ice_unofficial)
        {
            if (move_form_src(wlog, dst, root, strip))
            {
                return 0;
            }
        }
        else
        {
            if (move_form_src(wlog, dst, root, NULL))
            {
                return 0;
            }
        }
    }
    else
    {
        printf("not exist root director\n");
        if (move_form_src(wlog, dst, root, NULL))
        {
            return 0;
        }
    }
    return 1;
}

unsigned WINAPI update_thread(void *p)
{
    // 准备复制更新文件到file_info.process所在目录
    WCHAR dst[MAX_PATH+1] = {0};
    wcsncpy(dst, file_info.process, MAX_PATH);
    PathRemoveFileSpecW(dst);
    if (do_update(file_info.unzip_dir, dst))
    {
        printf("do_update false!\n");
    }
    return (1);
}
