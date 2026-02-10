#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shlwapi.h>
#include "spinlock.h"
#include "ini_parser.h"
#include "xml.h"
#include "extract7z.h"
#include "load_chrome.h"

static wchar_t cp_src_path[BUFF_LEN];
static wchar_t cp_dst_path[2][BUFF_LEN];

static int
integration_file_callback(LPCWSTR srcfile)
{
    int ret = 0;
    wchar_t *dst = NULL;
    wchar_t name[VALUE_LEN] = {0};
    wchar_t *p = wcsstr(srcfile, cp_src_path);
    if (p)
    {
        p += wcslen(cp_src_path) + 1;
        strpath_copy(name, p);
        if (name[0] && (dst = (wchar_t *)calloc(BUFF_LEN, sizeof(wchar_t))) != NULL)
        {
            p += wcslen(name);
            if (_wcsicmp(name, L"Aria2") == 0)
            {
                _snwprintf(dst, BUFF_LEN - 1, L"%s%s", cp_dst_path[0], p);
            }
            else if (_wcsicmp(name, L"Profiles") == 0)
            {
                _snwprintf(dst, BUFF_LEN - 1, L"%s%s", cp_dst_path[1], p);
            }
            if (_wcsicmp(name, L"update.log") == 0)
            {
                DeleteFileW(srcfile);
            }
            else
            {
                if (!move_file_wrapper(srcfile, dst, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING))
                {
                    ret = 1;
                }
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
integration_update(const wchar_t *bin, const wchar_t *profd, const wchar_t *temp)
{
    _snwprintf(cp_src_path, BUFF_LEN - 1, L"%s", temp);
    _snwprintf(cp_dst_path[0], BUFF_LEN - 1, L"%s", bin);
    _snwprintf(cp_dst_path[1], BUFF_LEN - 1, L"%s\\chrome", profd);
    PathRemoveFileSpecW(cp_dst_path[0]);
    PathAppendW(cp_dst_path[0], L"Aria2");
    return do_file_copy(temp, integration_file_callback, true);
}

static int
integration_download(const wchar_t *bin, xml_buffer *pbuf)
{
    int ret = -1;
    char *ini = NULL;
    char *url = NULL;
    wchar_t *profile = NULL;
    do
    {
        if (!bin || !pbuf)
        {
            break;
        }
        if (!(profile = path_utf16_clone(bin)))
        {
            break;
        }
        if (!PathAppendW(profile, L"portable.ini"))
        {
            break;
        }
        if (!PathFileExistsW(profile))
        {
            break;
        }
        if (!(ini = ini_utf16_utf8(profile, NULL)))
        {
            break;
        }
        if (!ini_read_string("chrome", "dl_url", &url, ini, true))
        {
            url = _strdup("https://master.dl.sourceforge.net/project/libportable/Iceweasel/downloadupchek.7z?viasf=1");
        }
        ret = init_process(url, &write_data_callback, pbuf);
    } while(0);
    ini_safe_free(ini);
    ini_safe_free(url);
    ini_safe_free(profile);
    return ret;
}

static int
integration_write_ini(const wchar_t *bin)
{
    int ret = -1;
    char *ini = NULL;
    wchar_t *profile = NULL;
    ini_cache plist = NULL;
    do
    {
        if (!(profile = path_utf16_clone(bin)))
        {
            break;
        }
        if (!PathAppendW(profile, L"portable.ini"))
        {
            break;
        }
        if (!(ini = ini_utf16_utf8(profile, NULL)))
        {
            break;
        }
        if (ini_section_exists("[aria2]", ini))
        {
            ret = ini_write_string("General", "DownloadTaskOver", "1", ini) ? 0 : -1;
            break;
        }
        if ((plist = iniparser_create_cache(ini, true, true)) == NULL)
        {
            break;
        }
        if (!inicache_new_section("\n[aria2]\npath=../Aria2/aria2c.exe\narg=\nrpc=http://127.0.0.1:6800/jsonrpc\nsecret=\nnohide=\nclose=\n", &plist))
        {
            break;
        }
        if (inicache_write_string("General", "DownloadTaskOver", "1", &plist))
        {
            ret = 0;
        }
    } while(0);
    ini_safe_free(ini);
    ini_safe_free(profile);
    if (plist)
    {
        iniparser_destroy_cache(&plist);
    }
    return 0;
}

int
integration_install(const wchar_t *bin, const wchar_t *profd)
{
    int ret = -1;
    wchar_t *temp = NULL;
    xml_buffer xbuf = {0};
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (chrome_check(bin, profd, false) <= 0)
        {
            break;
        }
        if (!(temp = (wchar_t *)calloc(BUFF_LEN + 1, sizeof(wchar_t))))
        {
            break;
        }
        if ((ret = integration_download(bin, &xbuf)) == 0)
        {
            time_t cc = time(NULL);
            _snwprintf(temp, BUFF_LEN, L"%s\\dl%I64d", profd, cc);
            if (!create_dir(temp))
            {
                ret = 1;
                break;
            }
            if (extract7z(NULL, temp, xbuf.str, xbuf.cur) != 0)
            {
                ret = 1;
                break;
            }
            if ((ret = integration_update(bin, profd, temp)) == 0)
            {
                ret = integration_write_ini(bin);
            }
        }
    } while(0);
    ini_safe_free(temp);
    ini_safe_free(xbuf.str);
    return ret;
}

int
integration_check(const wchar_t *bin, const wchar_t *profd, const bool uncheck)
{
    // 防止返回值在js中抛出异常, 不返回负数
    int ret = 0;
    wchar_t *mjs = NULL;
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (!uncheck && chrome_check(bin, profd, false) <= 0)
        {   // 没有启用userchrome
            break;
        }
        if (!(mjs = path_utf16_clone(profd)))
        {
            break;
        }
        wp_wcsncat(mjs, L"\\chrome\\SubScript\\DownloadUpcheck.uc.js", BUFF_LEN);
        if (!uncheck)
        {
            if (!(ret = PathFileExistsW(mjs)))
            {
                break;
            }
        }
        else
        {
            DeleteFileW(mjs);
        }
    } while(0);
    if (mjs)
    {
        free(mjs);
    }
    return ret;
}
