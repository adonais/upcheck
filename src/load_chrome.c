#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <shlwapi.h>
#include "spinlock.h"
#include "ini_parser.h"
#include "xml.h"
#include "extract7z.h"

static wchar_t file_src_path[URL_LEN];
static wchar_t file_dst_path[2][URL_LEN];

static int
chrome_file_callback(LPCWSTR srcfile)
{
    int ret = 0;
    wchar_t *dst = NULL;
    wchar_t name[VALUE_LEN] = {0};
    wchar_t *p = wcsstr(srcfile, file_src_path);
    if (p)
    {
        p += wcslen(file_src_path) + 1;
        strpath_copy(name, p);
        if (name[0] && (dst = (wchar_t *)calloc(URL_LEN, sizeof(wchar_t))) != NULL)
        {
            p += wcslen(name);
            if (_wcsicmp(name, L"App") == 0)
            {
                _snwprintf(dst, URL_LEN - 1, L"%s%s", file_dst_path[0], p);
            }
            else if (_wcsicmp(name, L"Profiles") == 0)
            {
                _snwprintf(dst, URL_LEN - 1, L"%s%s", file_dst_path[1], p);
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
chrome_update(const wchar_t *bin, const wchar_t *profd, const wchar_t *temp)
{
    _snwprintf(file_src_path, URL_LEN - 1, L"%s", temp);
    _snwprintf(file_dst_path[0], URL_LEN - 1, L"%s", bin);
    _snwprintf(file_dst_path[1], URL_LEN - 1, L"%s\\chrome", profd);
    return do_file_copy(temp, chrome_file_callback, true);
}

static int
chrome_download(const wchar_t *bin, xml_buffer *pbuf)
{
    int ret = -1;
    char *ini = NULL;
    char *url = NULL;
    wchar_t *profile = NULL;
    char md5_str[MD5_DIGEST_LENGTH * 2 + 1] = {0};
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
        if (!ini_read_string("chrome", "url", &url, ini, true))
        {
            url = _strdup("https://sourceforge.net/projects/libportable/files/Iceweasel/userchrome.7z/download");
        }
        ret = init_process(url, &write_data_callback, pbuf);
    } while(0);
    ini_safe_free(ini);
    ini_safe_free(url);
    ini_safe_free(profile);
    return ret;
}

static wchar_t *
chrome_dec_path(const wchar_t *path)
{
    char *dec_u8 = NULL;
    wchar_t *dec_path = NULL;
    char *u8_path = ini_utf16_utf8(path, NULL);
    if (u8_path && (dec_u8 = url_decode(u8_path)) != NULL)
    {
        dec_path = path_utf8_utf16(dec_u8);
    }
    ini_safe_free(dec_u8);
    ini_safe_free(u8_path);
    return dec_path;
}

int
chrome_install(const wchar_t *bin, const wchar_t *profd)
{
    int ret = -1;
    wchar_t *temp = NULL;
    wchar_t *dec_bin = NULL;
    wchar_t *dec_profd = NULL;
    xml_buffer xbuf = {0};
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (!(temp = (wchar_t *)calloc(URL_LEN + 1, sizeof(wchar_t))))
        {
            break;
        }
        if (!(dec_bin = chrome_dec_path(bin)))
        {
            break;
        }
        if (!(dec_profd = chrome_dec_path(profd)))
        {
            break;
        }
        if ((ret = chrome_download(dec_bin, &xbuf)) == 0)
        {
            time_t cc = time(NULL);
            _snwprintf(temp, URL_LEN, L"%s\\%I64d", dec_profd, cc);
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
            ret = chrome_update(dec_bin, dec_profd, temp);
        }
    } while(0);
    ini_safe_free(temp);
    ini_safe_free(dec_bin);
    ini_safe_free(dec_profd);
    ini_safe_free(xbuf.str);
    return ret;
}

int
chrome_check(const wchar_t *bin, const wchar_t *profd, const bool uncheck)
{
    int ret = -1;
    bool cfg = false;
    bool acfg = false;
    bool prefs = false;
    bool aprefs = false;
    bool chrome = false;
    wchar_t *path = NULL;
    wchar_t *mjs = NULL;
    wchar_t *clone = NULL;
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (!(path = chrome_dec_path(bin)))
        {
            break;
        }
        if (!(mjs = chrome_dec_path(profd)))
        {
            break;
        }
        if (!(clone = _wcsdup(path)))
        {
            break;
        }
        wcsncat(path, L"\\defaults\\pref\\autoconfig.js", URL_LEN);
        if (!uncheck)
        {
            if (!PathFileExistsW(path))
            {
                PathRemoveFileSpecW(path);
                PathAppendW(path, L"config-prefs.js");
                if (PathFileExistsW(path))
                {
                    prefs = true;
                }
            }
            else
            {
                aprefs = true;
            }
            ret =  (aprefs || prefs ? 1 : 0);
            _snwprintf(path, URL_LEN, L"%s\\Iceweasel.cfg", clone);
            if (!PathFileExistsW(path))
            {
                PathRemoveFileSpecW(path);
                PathAppendW(path, L"config.js");
                if (PathFileExistsW(path))
                {
                    acfg = true;
                }
            }
            else
            {
                cfg = true;
            }
            ret =  (acfg || cfg ? ret : 0);
        }
        wcsncat(mjs, L"\\chrome\\userChrome.js", URL_LEN);
        if (!uncheck)
        {
            if (!PathFileExistsW(mjs))
            {
                ret = 0;
            }
            else
            {
                chrome = true;
            }
        }
        if (ret == 0)
        {
            if (!(acfg || cfg || aprefs || prefs || chrome))
            {   // 测试目录是否可写入
                FILE *fd = NULL;
                wcsncat(path, L".tmp", URL_LEN);
                if (!(fd = _wfopen(path, L"w+b")))
                {
                    ret = -1;
                    break;
                }
                fclose(fd);
                if (!DeleteFileW(path))
                {
                    ret = -1;
                    break;
                }
            }
            if (aprefs)
            {
                _snwprintf(path, URL_LEN, L"%s\\defaults\\pref\\autoconfig.js", clone);
                if (!DeleteFileW(path))
                {
                    ret = -1;
                    break;
                }
            }
            if (prefs)
            {
                _snwprintf(path, URL_LEN, L"%s\\defaults\\pref\\config-prefs.js", clone);
                if (!DeleteFileW(path))
                {
                    ret = -1;
                    break;
                }
            }
            if (chrome)
            {
                _snwprintf(path, URL_LEN, L"%s.old", mjs);
                if (!MoveFileExW(mjs, path, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING))
                {
                    ret = -1;
                    break;
                }
            }
        }
        else if (uncheck)
        {
            ret = 0;
            _snwprintf(path, URL_LEN, L"%s\\defaults\\pref\\autoconfig.js", clone);
            if (PathFileExistsW(path))
            {
                ret = DeleteFileW(path) ? 0 : -1;
            }
            _snwprintf(path, URL_LEN, L"%s\\defaults\\pref\\config-prefs.js", clone);
            if (PathFileExistsW(path))
            {
                ret = DeleteFileW(path) ? 0 : -1;
            }
            if (PathFileExistsW(mjs))
            {
                _snwprintf(path, URL_LEN, L"%s.old", mjs);
                ret = MoveFileExW(mjs, path, MOVEFILE_COPY_ALLOWED|MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
            }
        }
    } while(0);
    if (path)
    {
        free(path);
    }
    if (mjs)
    {
        free(mjs);
    }
    if (clone)
    {
        free(clone);
    }
    return ret;
}
