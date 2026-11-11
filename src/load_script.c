#include "spinlock.h"
#include "ini_parser.h"
#include "xml.h"

#define luajit_c
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static int
upcheck_getenv(lua_State *L)
{
    wchar_t *buffer = NULL;
    const char *varname = luaL_checkstring(L, -1);
    char *u8_buf = varname ? getenv(varname) : NULL;
    if (!u8_buf)
    {
        lua_pushnil(L);
    }
    else
    {
        lua_pushstring(L, u8_buf);
    }
    return 1;
}

static int
upcheck_putenv(lua_State *L)
{
    size_t var_len;
    const char *var_name = luaL_checklstring(L, 1, &var_len);
    const char *var_value = luaL_checkstring(L, 2);
    if (var_name && var_value)
    {
        if (setenv(var_name, var_value, 1) != 0)
        {
            lua_pushnil(L);
            lua_pushfstring(L, "Failed to set environment variable: %d", errno);
            return 2;
        }
        lua_pushboolean(L, 1);
        return 1;
    }
    return 2;
}

static int
upcheck_malloc(lua_State *L)
{
    void *var;
    size_t size = (size_t)lua_tonumber(L, -1);
    if (!size)
    {
        ++size;
    }
    if ((var = malloc(size)) == NULL)
    {
        lua_pushnil(L);
        lua_pushfstring(L, "Failed to malloc");
        return 2;
    }
    lua_pushlightuserdata(L, var);
    return 1;
}

static int
upcheck_free(lua_State *L)
{
    char *var = (char *)lua_topointer(L, -1);
    if (var)
    {
        free(var);
    }
    return 0;
}

static int
upcheck_filetime(lua_State *L)
{
    struct stat buf = {0};
    const char *utf8 = (const char *)lua_tostring(L, -1);
    if (stat(utf8, &buf) != -1)
    {
        char buffer[MD5_LEN+1] = {0};
        sprintf(buffer,"%ld", buf.st_mtime);
        lua_pushfstring(L, buffer);
        return 1;
    }
    return 2;
}

static int
upcheck_curtime(lua_State *L)
{
    time_t ltime = time(NULL);
    if (ltime != -1)
    {
        char buffer[MD5_LEN+1] = {0};
        sprintf(buffer,"%ld", ltime);
        lua_pushfstring(L, buffer);
        return 1;
    }
    return 2;
}

static int
upcheck_difftime(lua_State *L)
{
    const char *value1 = luaL_checkstring(L, 1);
    const char *value2 = luaL_checkstring(L, 2);
    if (value1 && value2)
    {
        int64_t v1 = _atoi64(value1);
        int64_t v2 = _atoi64(value2);
        double diff = difftime(v1, v2);
        lua_pushnumber(L, diff);
        return 1;
    }
    return 2;
}

static int
upcheck_fmttime(lua_State *L)
{
    const char *value1 = luaL_checkstring(L, 1);
    const double value2 = luaL_checknumber(L, 2);
    if (value1 && value2)
    {
        int64_t v1 = _atoi64(value1);
        int64_t diff = (int64_t)value2;
        int hours = (int)(diff / 3600);
        int minutes = (diff % 3600) / 60;
        int seconds = diff % 60;
        char str[VALUE_LEN] = {0};
        snprintf(str, VALUE_LEN, value1, hours, minutes, seconds);
        lua_pushfstring(L, str);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_global_init(lua_State *L)
{
    long value = luaL_checklong(L, -1);
    int ret = curl_global_init(value);
    if (!ret)
    {
        lua_pushinteger(L, ret);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_global_cleanup(lua_State *L)
{
    curl_global_cleanup();
    return 0;
}

static int
upcheck_curl_easy_init(lua_State *L)
{
    CURL* curl = curl_easy_init();
    if (curl)
    {
        lua_pushlightuserdata(L, curl);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_easy_cleanup(lua_State *L)
{
    CURL *var = (CURL *)lua_topointer(L, -1);
    if (var)
    {
        curl_easy_cleanup(var);
        return 0;
    }
    return 2;
}

static int
upcheck_curl_easy_setopt(lua_State *L)
{
    CURL *curl = (CURL *)lua_topointer(L, 1);
    long opt = luaL_checklong(L, 2);
    const char *type = luaL_typename(L, 3);
    if (type)
    {
        int ret = 2;
        if (strcmp(type, "string") == 0)
        {
            const char *value = (const char *)lua_tostring(L, 3);
            ret = curl_easy_setopt(curl, opt, value);
        }
        else if (strcmp(type, "function") == 0)
        {
            printf("The callback function must be converted\n");
            return ret;
        }
        else if (strcmp(type, "cdata") == 0)
        {
            intptr_t value = (intptr_t)lua_topointer(L, 3);
            ret = curl_easy_setopt(curl, opt, value);
        }
        else if (strcmp(type, "number") == 0)
        {   // 回调函数必须转换为number类型
            if (
                CURLOPT_WRITEFUNCTION == opt || 
                CURLOPT_READFUNCTION == opt ||
                CURLOPT_PROGRESSFUNCTION == opt ||
                CURLOPT_HEADERFUNCTION == opt ||
                CURLOPT_IOCTLFUNCTION == opt
               )
            {
                intptr_t value = (intptr_t)lua_tonumber(L, 3);
                ret = curl_easy_setopt(curl, opt, value);
            }
            else
            {
                long value = luaL_checklong(L, 3);
                ret = curl_easy_setopt(curl, opt, value);
            }
        }
        lua_pushinteger(L, ret);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_easy_perform(lua_State *L)
{
    CURL *curl = (CURL *)lua_topointer(L, -1);
    if (curl)
    {
        int ret = curl_easy_perform(curl);
        lua_pushinteger(L, ret);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_slist_append(lua_State *L)
{
    struct curl_slist* v1 = (struct curl_slist *)lua_topointer(L, 1);
    const char *v2 = (const char *)lua_topointer(L, 2);
    if (v1 && v2)
    {
        struct curl_slist *ret = curl_slist_append(v1, v2);
        lua_pushlightuserdata(L, ret);
        return 1;
    }
    return 2;
}

static int
upcheck_curl_slist_free_all(lua_State *L)
{
    struct curl_slist* v1 = (struct curl_slist *)lua_topointer(L, -1);
    if (v1)
    {
        curl_slist_free_all(v1);
        return 0;
    }
    return 2;
}

static int
upcheck_curl_easy_getinfo(lua_State *L)
{
    CURLcode code = -1;
    CURL *curl = (CURL *)lua_topointer(L, 1);
    long ninfo = luaL_checklong(L, 2);
    if (ninfo>CURLINFO_SLIST)
    {   /* string list */
        struct curl_slist *slist=0;
        if (CURLE_OK == (code = curl_easy_getinfo(curl, ninfo, &slist)))
        {
            if (slist)
            {
                int i;
                lua_newtable(L);
                for (i = 1; slist; i++, slist = slist->next)
                {
                    lua_pushnumber(L, i);
                    lua_pushstring(L, slist->data);
                    lua_settable(L, -3);
                }
                curl_slist_free_all(slist);
            }
            else
            {
                lua_pushnil(L);
            }
            return 1;
        }
        else
        {
            /* curl_easy_getinfo returns error */
        }
    }
    else if (ninfo > CURLINFO_DOUBLE)
    {
        /* double */
        double value;
        if (CURLE_OK == (code=curl_easy_getinfo(curl, ninfo, &value)))
        {
            lua_pushnumber(L, value);
            return 1;
        }
        else
        {
            /* curl_easy_getinfo returns error */
        }
    }
    else if (ninfo > CURLINFO_LONG)
    {
        /* long */
        long value;
        if (CURLE_OK == (code=curl_easy_getinfo(curl, ninfo, &value)))
        {
            lua_pushinteger(L, (lua_Integer)value);
            return 1;
        }
        else
        {
            /* curl_easy_getinfo returns error */
        }
    }
    else if (ninfo > CURLINFO_STRING)
    {
        /* string */
        char* value;
        if (CURLE_OK == (code=curl_easy_getinfo(curl, ninfo, &value)))
        {
            lua_pushstring(L, value);
            return 1;
        }
        else
        {
            /* curl_easy_getinfo returns error */
        }
    }
    /* on error, return nil, error message, error code */
    lua_pushnil(L);
    if (code > CURLE_OK)
    {
        lua_pushstring(L, curl_easy_strerror(code));
        lua_pushnumber(L, code);
        return 3;
    }
    else
    {
        lua_pushfstring(L, "Invalid CURLINFO number: %d", ninfo);
    }
    return 2;
}

static int
upcheck_curl_easy_strerror(lua_State *L)
{
    long err = luaL_checklong(L, -1);
    const char *ret = curl_easy_strerror(err);
    lua_pushlightuserdata(L, (void *)ret);
    return 1;
}

static int
upcheck_ini_cdata_parser(lua_State *L)
{
    xml_buffer *pbuf = (xml_buffer *)lua_topointer(L, -1);
    if (pbuf)
    {
        int res = xml_query_ice(pbuf, false);
        lua_pushinteger(L, res);
        return 1;
    }
    return 2;
}

static int
luax_open(const char *filename, char **parg, const int len)
{
    int ret = -1;
    lua_State *L = luaL_newstate();
    while (L && filename)
    {
        luaL_openlibs(L);
        // 注册函数到全局表中
        lua_register(L, "getenv_lua", upcheck_getenv);
        lua_register(L, "putenv_lua", upcheck_putenv);
        lua_register(L, "malloc_lua", upcheck_malloc);
        lua_register(L, "free_lua", upcheck_free);
        lua_register(L, "curtime_lua", upcheck_curtime);
        lua_register(L, "filetime_lua", upcheck_filetime);
        lua_register(L, "difftime_lua", upcheck_difftime);
        lua_register(L, "fmttime_lua", upcheck_fmttime);
        // libcurl
        lua_register(L, "luacurl_global_init", upcheck_curl_global_init);
        lua_register(L, "luacurl_global_cleanup", upcheck_curl_global_cleanup);
        lua_register(L, "luacurl_easy_init", upcheck_curl_easy_init);
        lua_register(L, "luacurl_easy_cleanup", upcheck_curl_easy_cleanup);
        lua_register(L, "luacurl_easy_setopt", upcheck_curl_easy_setopt);
        lua_register(L, "luacurl_easy_perform", upcheck_curl_easy_perform);
        lua_register(L, "luacurl_slist_append", upcheck_curl_slist_append);
        lua_register(L, "luacurl_slist_free_all", upcheck_curl_slist_free_all);
        lua_register(L, "luacurl_easy_getinfo", upcheck_curl_easy_getinfo);
        lua_register(L, "luacurl_easy_strerror", upcheck_curl_easy_strerror);
        // ini parser
        lua_register(L, "luaini_cdata_parser", upcheck_ini_cdata_parser);

        if (luaL_dofile(L, filename) != LUA_OK)
        {
            printf("Failed to load script: %s\n", lua_tostring(L, -1));
            break;
        }
        // 调用脚本的run函数
        lua_getglobal(L, "run");
        if (!lua_isfunction(L, -1))
        {
            printf("'run' is not a function\n");
            break;
        }
        if (len > 0)
        {
            int i = 0;
            for (; i < len; ++i)
            {
                char *dt = url_decode(parg[i]);
                if (dt)
                {
                    lua_pushstring(L, dt);
                    free(dt);
                }
                else
                {
                    printf("lua_pushstring failed\n");
                    break;
                }
            }
            if (i != len)
            {
                printf("%d + 1 != %d\n", i, len);
                break;
            }
        }
        if (lua_pcall(L, len, 1, 0) != LUA_OK)
        {
            printf("Error calling 'run': %s\n", lua_tostring(L, -1));
            break;
        }
        // 获取返回值
        ret = (int)lua_tonumber(L, -1);
        // 从栈中移除结果
        lua_pop(L, 1);
        break;
    }
    if (L)
    {
        lua_close(L);
    }
    return ret;
}

int
lua_script_loader(char **parg, const int len)
{
    int status = 1;
    char *filename = NULL;
    char *dec_name = NULL;
    char *dec_chrome = NULL;
    char *path = NULL;
    char *chrome = NULL;
    do
    {
        const char *uchrome = NULL;
        const char *name = NULL;
        if (!parg || !*parg)
        {
            break;
        }
        if (len < 2 || len > NAMES_LEN)
        {
            break;
        }
        if ((uchrome = parg[0]) == NULL)
        {
            break;
        }
        if ((name = parg[1]) == NULL)
        {
            break;
        }
        if (strlen(name) < 2)
        {
            break;
        }
        if (!(path = (char *)calloc(BUFF_LEN, 1)))
        {
            break;
        }
        if (!get_process_path(path, BUFF_LEN) || *path == 0)
        {
            break;
        }
        if (!(dec_chrome = url_decode(uchrome)))
        {
            break;
        }
        if (!(dec_name = url_decode(name)))
        {
            break;
        }
        if (!(chrome = strdup(dec_chrome)))
        {
            break;
        }
        // if (!enviroment_variables_set("LD_LIBRARY_PATH", path, VARIABLES_APPEND))
        // {
        //     break;
        // }
        if (enviroment_variables_set("UPCHECK_MOZ_BIN", path, VARIABLES_RESET))
        {
            wp_strncat(path, ":", BUFF_LEN);
            wp_strncat(path, chrome, BUFF_LEN);
            wp_strncat(path, ":", BUFF_LEN);
            wp_strncat(path, chrome, BUFF_LEN);
            wp_strncat(path, "/lua", BUFF_LEN);
        }
        if (!enviroment_variables_set("PATH", path, VARIABLES_APPEND))
        {
            break;
        }
        if (!enviroment_variables_set("UPCHECK_MOZ_CHROME", chrome, VARIABLES_RESET))
        {
            break;
        }
        if (!strip_file_spec(chrome))
        {
            break;
        }
        if (!enviroment_variables_set("UPCHECK_MOZ_PROFD", chrome, VARIABLES_RESET))
        {
            break;
        }
        if (!(filename = (char *)calloc(BUFF_LEN, 1)))
        {
            break;
        }
        if (name[0] != '/')
        {
            snprintf(filename, BUFF_LEN, "%s/lua/%s", dec_chrome, dec_name);
        }
        else
        {
            snprintf(filename, BUFF_LEN, "%s", dec_name);
        }
        status = luax_open(filename, &parg[2], len - 2);
        printf("lua status = [%d]\n", status);
    } while (0);
    if (dec_name)
    {
        free(dec_name);
    }
    if (dec_chrome)
    {
        free(dec_chrome);
    }
    if (chrome)
    {
        free(chrome);
    }
    if (path)
    {
        free(path);
    }
    if (filename)
    {
        free(filename);
    }
    return status;
}
