#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "spinlock.h"
#include "ini_parser.h"
#include "xml.h"
#include "extractxz.h"
#include "load_chrome.h"

#define REDIRECT_URL "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/userchrome.tar.xz/download"
#define MG_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/mousegestures.tar.xz/download"
#define MT_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/multilinetabs.tar.xz/download"
#define AP_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/addonspage.tar.xz/download"
#define DL_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/downloadupcheck.tar.xz/download"
#define T1_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/auto_activate_tab.tar.xz/download"
#define T2_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/right_click_close_tab.tar.xz/download"
#define T3_URL       "https://sourceforge.net/projects/libportable/files/Iceweasel/scripts/linux/right_wheel_switch_tab.tar.xz/download"

bool
chrome_faster(const char *ini, char **purl)
{
    char *fast = NULL;
    if (!(purl && *purl))
    {
        return false;
    }
    if (ini_read_string("update", "faster", &fast, ini, true))
    {
        char re[URL_LEN] = {0};
        if (fast[strlen(fast) - 1] == '/')
        {
            fast[strlen(fast) - 1] = 0;
        }
        snprintf(re, URL_LEN, "%s/%s", fast, *purl);
        free(fast);
        free(*purl);
        return ((*purl = strdup(re)) != NULL);
    }
    return true;
}

static int
chrome_download(const char *profd, xml_buffer *pbuf, mozscr srcid)
{
    int ret = -1;
    char *url = NULL;
    char *profile = NULL;
    do
    {
        if (!profd || !pbuf)
        {
            break;
        }
        if (!(profile = path_utf8_clone(profd)))
        {
            break;
        }
        if (wp_strncat(profile, "/portable.ini", BUFF_LEN) != 0)
        {
            break;
        }
        if (!exists_file(profile))
        {
            break;
        }
        switch (srcid)
        {
            case MOZ_CHROME:
                if (!ini_read_string("chrome", "uc_url", &url, profile, true))
                {
                    url = strdup(REDIRECT_URL);
                }
                break;
            case MOZ_MOUSEGESTURES:
                if (!ini_read_string("chrome", "mg_url", &url, profile, true))
                {
                    url = strdup(MG_URL);
                }
                break;
            case MOZ_MULTILINES:
                if (!ini_read_string("chrome", "mt_url", &url, profile, true))
                {
                    url = strdup(MT_URL);
                }
                break;
            case MOZ_UCADDONS:
                if (!ini_read_string("chrome", "ap_url", &url, profile, true))
                {
                    url = strdup(AP_URL);
                }
                break;
            case MOZ_DOWNLOADUPCHECK:
                if (!ini_read_string("chrome", "dl_url", &url, profile, true))
                {
                    url = strdup(DL_URL);
                }
                break;
            case MOZ_ONTABACTIVATE:
                if (!ini_read_string("chrome", "t1_url", &url, profile, true))
                {
                    url = strdup(T1_URL);
                }
                break;
            case MOZ_ONTABRIGHTCLICK:
                if (!ini_read_string("chrome", "t2_url", &url, profile, true))
                {
                    url = strdup(T2_URL);
                }
                break;
            case MOZ_ONTABRIGHTSWITCH:
                if (!ini_read_string("chrome", "t3_url", &url, profile, true))
                {
                    url = strdup(T3_URL);
                }
                break;
            default:
                break;
        }
        if (!url)
        {
            break;
        }
        if (!strncmp(url, "https://sourceforge.net", strlen("https://sourceforge.net")))
        {
            if (!chrome_faster(profile, &url))
            {
                break;
            }
        }
        ret = init_process(url, &write_data_callback, pbuf);
    } while(0);
    ini_safe_free(url);
    ini_safe_free(profile);
    return ret;
}

int chrome_install(const char *bin, const char *profd, mozscr srcid)
{
    int ret = -1;
    char *profile = NULL;
    xml_buffer xbuf = {0};
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (srcid != MOZ_CHROME && chrome_check(bin, profd, false) <= 0)
        {
            break;
        }
        if ((ret = chrome_download(profd, &xbuf, srcid)) == 0)
        {
            ret = 1;
            if (extract_tar_xz(NULL, xbuf.str, xbuf.cur, profd) != 0)
            {
                break;
            }
            if (srcid == MOZ_DOWNLOADUPCHECK)
            {
                if (!(profile = path_utf8_clone(profd)))
                {
                    break;
                }
                if (wp_strncat(profile, "/portable.ini", BUFF_LEN) != 0)
                {
                    break;
                }
                if (!ini_write_string("General", "DownloadTaskOver", "1", profile))
                {
                    break;
                }
            }
            ret = 0;
        }
    } while(0);
    ini_safe_free(xbuf.str);
    ini_safe_free(profile);
    return ret;
}

int chrome_uncheck(const char *bin, const char *profd, mozscr srcid)
{
    int ret = -1;
    char *ucjs = NULL;
    char *mjs = path_utf8_clone(profd);
    if (mjs && (ucjs = strdup(mjs)))
    {
        switch (srcid)
        {
            case MOZ_CHROME:
                wp_strncat(mjs, "/chrome/userChrome.us.js", BUFF_LEN);
                break;
            case MOZ_MOUSEGESTURES:
                wp_strncat(mjs, "/chrome/uc/MouseGestures.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/MouseGestures.uc.js", ucjs);
                }
                break;
            case MOZ_MULTILINES:
                wp_strncat(mjs, "/chrome/uc/MultiRowTabLiteforFx.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/MultiRowTabLiteforFx.uc.js", ucjs);
                }
                break;
            case MOZ_UCADDONS:
                wp_strncat(mjs, "/chrome/uc/AddonsPage.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/AddonsPage.uc.js", ucjs);
                }
                break;
            case MOZ_DOWNLOADUPCHECK:
                wp_strncat(mjs, "/chrome/uc/DownloadUpcheck.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/DownloadUpcheck.uc.js", ucjs);
                }
                break;
            case MOZ_ONTABACTIVATE:
                wp_strncat(mjs, "/chrome/uc/HoverActivateTab.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/HoverActivateTab.uc.js", ucjs);
                }
                break;
            case MOZ_ONTABRIGHTCLICK:
                wp_strncat(mjs, "/chrome/uc/RclickCloseTab.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/RclickCloseTab.uc.js", ucjs);
                }
                break;
            case MOZ_ONTABRIGHTSWITCH:
                wp_strncat(mjs, "/chrome/uc/RclickSwitchTab.uc.js", BUFF_LEN);
                if (!exists_file(mjs))
                {
                    snprintf(mjs, BUFF_LEN, "%s/chrome/SubScript/RclickSwitchTab.uc.js", ucjs);
                }
                break;
            default:
                break;
        }
        free(ucjs);
        if (exists_file(mjs))
        {
            ret = delete_file(mjs);
        }
    }
    if (mjs)
    {
        free(mjs);
    }
    return ret;
}

int chrome_check(const char *bin, const char *profd, const bool uncheck)
{
    int ret = -1;
    bool cfg = false;
    bool acfg = false;
    bool prefs = false;
    bool aprefs = false;
    bool chrome = false;
    char *path = NULL;
    char *mjs = NULL;
    char *clone = NULL;
    do
    {
        if (!bin[0] || !profd[0])
        {
            break;
        }
        if (!(path = path_utf8_clone(bin)))
        {
            break;
        }
        if (!(mjs = path_utf8_clone(profd)))
        {
            break;
        }
        if (!(clone = strdup(path)))
        {
            break;
        }
        wp_strncat(path, "/defaults/pref/autoconfig.js", BUFF_LEN);
        if (!uncheck)
        {
            if (!exists_file(path))
            {
                strip_file_spec(path);
                wp_strncat(path, "/config-prefs.js", BUFF_LEN);
                if (exists_file(path))
                {
                    prefs = true;
                }
            }
            else
            {
                aprefs = true;
            }
            ret =  (aprefs || prefs ? 1 : 0);
            snprintf(path, BUFF_LEN, "%s/Iceweasel.cfg", clone);
            if (!exists_file(path))
            {
                strip_file_spec(path);
                wp_strncat(path, "/config.js", BUFF_LEN);
                if (exists_file(path))
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
        wp_strncat(mjs, "/chrome/userChrome.js", BUFF_LEN);
        if (!uncheck)
        {
            if (!exists_file(mjs))
            {
                if (ret > 0 && acfg && exists_file(path))
                {
                    FILE *fp = fopen(path, "rb");
                    ret = 0;
                    if (fp)
                    {
                        char buff[1024] = {0};
                        size_t buf_len = 0;
                        if ((buf_len = fread(buff, 1, 1024, fp)) > 0)
                        {
                            if (check_memstr(buff, (int)buf_len, "/boot.sys.mjs") != NULL)
                            {
                                ret = 1;
                                break;
                            }
                        }
                        fclose(fp);
                    }
                }
                else
                {
                    ret = 0;
                }
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
                wp_strncat(path, ".tmp", BUFF_LEN);
                if (!(fd = fopen(path, "wb")))
                {
                    ret = -1;
                    break;
                }
                fclose(fd);
                delete_file(path);
            }
            if (chrome)
            {
                if (delete_file(mjs) != 0)
                {
                    ret = -1;
                    break;
                }
            }
        }
        else if (uncheck)
        {
            ret = 0;
            if (exists_file(mjs))
            {
                ret = delete_file(mjs);
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
