#include <stdio.h>
#include <wchar.h>
#include <shlwapi.h>
#include <windows.h>
#include "ini_parser.h"
#include "spinlock.h"

static int g_directory_count = 0;
static wchar_t update_src_path[URL_LEN];
static wchar_t update_fn_erase[URL_LEN];
static wchar_t update_dst_path[2][URL_LEN];

static int
update_deleted(LPCWSTR srcfile)
{
    const WCHAR *crtfile[] = {
        L"msvcp1",
        L"vcruntime1",
        L"ucrtbase.dll",
        L"api-ms-",
        NULL
    };
    const WCHAR *name = get_file_name(srcfile);
    if (name && name[0])
    {
        for (int i = 0; crtfile[i]; ++i)
        {   // 不复制crt文件, 因为upcheck动态链接依赖它们, 复制失败
            if (_wcsnicmp(name, crtfile[i], wcslen(crtfile[i])) == 0)
            {
                return DeleteFileW(srcfile);
            }
        }
    }
    return 0;
}

static int
update_file_callback(LPCWSTR srcfile)
{
    int ret = 0;
    wchar_t *dst = NULL;
    wchar_t topdir[VALUE_LEN] = {0};
    wchar_t name[VALUE_LEN] = {0};
    wchar_t *p = wcsstr(srcfile, update_src_path);
    if (p)
    {
        p += wcslen(update_src_path) + 1;
        if (g_directory_count)
        {
            strpath_copy(topdir, p);
            p += wcslen(topdir) + 1;
        }
        if (_wcsicmp(topdir, L"update.log") == 0)
        {   // 删除日志文件
            DeleteFileW(srcfile);
            return 0;
        }
        if (update_deleted(srcfile))
        {
            return 0;
        }
        strpath_copy(name, p);
        if (name[0] && (dst = (wchar_t *)calloc(URL_LEN, sizeof(wchar_t))) != NULL)
        {   // iceweasel包含App目录, 特殊处理
            if (_wcsicmp(name, L"App") == 0)
            {
                p += wcslen(name) + 1;
            }
            // 不能指向了目录尾部
            if (!p[0])
            {
                p = name;
            }
            if (_wcsicmp(name, L"readme.txt") == 0)
            {
                _snwprintf(dst, URL_LEN - 1, L"%s\\%s", update_dst_path[1], p);
            }
            else if (_wcsicmp(name, L"erased_lists.bat") == 0)
            {
                _snwprintf(dst, URL_LEN - 1, L"%s\\%s", update_dst_path[1], p);
                _snwprintf(update_fn_erase, URL_LEN - 1, L"%s", dst);
            }
            else
            {
                _snwprintf(dst, URL_LEN - 1, L"%s\\%s", update_dst_path[0], p);
            }
            if (!move_file_wrapper(srcfile, dst, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING))
            {
                ret = 1;
            }
        }
    }
    if (dst)
    {
        free(dst);
    }
    return ret;
}

static int
update_directory_callback(LPCWSTR srcfile)
{
    uint32_t attrs = GetFileAttributesW(srcfile);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
    {   // 如果只有一个目录, 源目录是顶层目录
        ++g_directory_count;
    }
    return 0;
}

static int
do_update(LPCWSTR src, LPCWSTR dst)
{
    int ret = 1;
    // 保存源路径, 用于目标路径拼接
    _snwprintf(update_src_path, URL_LEN - 1, L"%s", src);
    // 进程所在目录
    _snwprintf(update_dst_path[0], URL_LEN - 1, L"%s", dst);
    // 进程所在的上一级目录
    _snwprintf(update_dst_path[1], URL_LEN - 1, L"%s", dst);
    PathRemoveFileSpecW(update_dst_path[1]);
    if (do_file_copy(src, update_directory_callback, false) == 0)
    {
        ret = do_file_copy(src, update_file_callback, true);
        g_directory_count = 0;
        update_src_path[0] = 0;
    }
    return ret;
}

int
update_thread(void *p)
{
    // 准备复制更新文件到file_info.process所在目录
    WCHAR dst[URL_LEN] = {0};
    wcsncpy(dst, file_info.process, URL_LEN - 1);
    PathRemoveFileSpecW(dst);
    if (do_update(file_info.unzip_dir, dst) != 0)
    {
        printf("do_update false!\n");
        return 1;
    }
    // 自定义erased_lists.bat文件,用于清理多余配置.
    if (update_fn_erase[0] && PathFileExistsW(update_fn_erase))
    {
        CloseHandle(create_new(L"cmd.exe /c", update_fn_erase, NULL, 0, NULL, 0));
        Sleep(1000);
    }
    return 0;
}
