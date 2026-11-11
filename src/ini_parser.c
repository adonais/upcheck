#include <string.h>
#ifdef _MSC_VER
#include <io.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#ifdef _WIN32
#include <wchar.h>
#include <windows.h>
#endif
#include "ini_parser.h"

#define LEN_CONTENT 260
#define MAX_COUNT 1024

#define GET_UTF8(val, GET_BYTE, ERROR)           \
    val = (GET_BYTE);                            \
    {                                            \
        uint32_t top = (val & 128) >> 1;         \
        if ((val & 0xc0) == 0x80 || val >= 0xFE) \
        {                                        \
            ERROR                                \
        }                                        \
        while (val & top)                        \
        {                                        \
            uint32_t tmp = (GET_BYTE) -128;      \
            if (tmp >> 6)                        \
            {                                    \
                ERROR                            \
            }                                    \
            val = (val << 6) + tmp;              \
            top <<= 5;                           \
        }                                        \
        val &= (top << 1) - 1;                   \
    }

typedef bool (* remove_fn)(node *en, const char *v);
extern bool exists_file(const char *path);
extern int create_file(const char *path, mode_t mode);
extern int wp_strncat(char *dst, const char *src, size_t number);

static int
truncate_file(FILE *fp, long n)
{
#ifdef _MSC_VER
    return _chsize(_fileno(fp), n);
#else
    return ftruncate(fileno(fp), n);
#endif
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#endif

static ini_list *
list_init(ini_list **pli)
{
    *pli = (ini_list *)calloc(sizeof(ini_list), 1);
    if (*pli)
    {
        if (((*pli)->pd = (node *)calloc(sizeof(node), 1)) == NULL)
        {
            free(*pli);
            *pli = NULL;
        }
    }
    return *pli;
}

static void
list_destroy(ini_list **pli)
{
    if (!(pli && *pli))
    {
        return;
    }
    for (node **cur = &(*pli)->pd; *cur;)
    {
        node *entry = *cur;
        *cur = entry->next;
        free(entry);
    }
    free(*pli);
    *pli = NULL;
}

static position
list_ender(node **pphead)
{
    position p = *pphead;
    while (p && p->next != NULL)
        p = p->next;
    return p;
}

/* 链表头部插入 */
static int
rever_insert(node **pphead, const char *v)
{
    size_t len = strlen(v);
    if (len > LEN_CONTENT - 1)
    {
        return 0;
    }
    node *t = (node *)calloc(sizeof(node) + LEN_CONTENT, 1);
    if (NULL == t)
    {
        return 0;
    }
    memcpy(t->content, v, len + 1);
    t->next = *pphead;
    *pphead = t;
    return 1;
}

static position
list_find(node **pphead, const char *v)
{
    size_t len = strlen(v);
    position p = (*pphead)->next;
    if (len > LEN_CONTENT - 1)
    {
        return NULL;
    }
    while (p != NULL)
    {
        if (strncmp(p->content, v, len) == 0 && (*(p->content+len) == '\r' ||
            *(p->content+len) == '\n' || *(p->content+len) == '\0'))
        {
            break;
        }
        else
        {
            p = p->next;
        }

    }
    return p;
}

/* 链表逆向查找所在区段 */
static void
list_rfind(node **pphead, position end, position *find)
{
    position p = *pphead;
    if (p->next != NULL && p->next != end)
    {
        list_rfind(&(p->next), end, find);
    }
    if (*(p->content) == '[' && strrchr(p->content, ']'))
    {
        if (!*find)
        {
            *find = p;
        }
    }
}

/* 插入节点, pos 为空时，在尾部插入 */
static bool
list_insert(node **pphead, position pos, const char *v)
{
    bool ret = false;
    while (pphead && v)
    {
        position p = NULL;
        node *tmp = NULL;
        size_t len = strlen(v);
        if (len > LEN_CONTENT - 1)
        {
            ret = false;
            break;
        }
        if (!pos)
        {
            p = list_ender(pphead);
        }
        else
        {
            p = pos;
        }
        if (NULL == (tmp = (node *) calloc(sizeof(node) + LEN_CONTENT, 1)))
        {
            ret = false;
            break;
        }
        memcpy(tmp->content, v, len + 1);
        tmp->next = p->next;
        p->next = tmp;
        ret = true;
        break;
    }
    return ret;
}

#ifdef APP_DEBUG
/* 输出链表所有元素 */
static void
list_print(node **pphead)
{
    for (node *cur = *pphead; cur;)
    {
        printf("%s", cur->content);
        cur = cur->next;
    }
    printf("\n");
}
#endif

/* 使用回调函数,删除节点值为v的所有节点 */
static void
list_delete_if(node **pphead, remove_fn rm_node, const char *v)
{
    for (node **cur = pphead; *cur;)
    {
        node *en = *cur;
        if (rm_node(en, v))
        {
            *cur = en->next;
            free(en);
        }
        else
        {
            cur = &en->next;
        }
    }
}

static void
list_delete_node(node **pphead, position pos)
{
    for (node **cur = pphead; *cur;)
    {
        node *en = *cur;
        if (en == pos)
        {
            *cur = en->next;
            free(en);
        }
        else
        {
            cur = &en->next;
        }
    }
}

static str_line
get_block_eol(const char *str, const int len)
{
    char *p = NULL;
    if (!str || len <= 0)
    {
        return CHR_UNKOWN;
    }
    if ((p = strchr(str, '\n')))
    {
        if (p > str && *(p - 1) == '\r')
        {
            return CHR_WIN;
        }
        else
        {
            return CHR_UNIX;
        }
    }
    return CHR_UNKOWN;
}

static bool
read_lines(char *text, const int len, char **ptr)
{
    char *p = NULL;
    if (!(**ptr))
    {
        return false;
    }
    if ((p = strchr((*ptr), '\n')))
    {
        if (p > (*ptr) && (*(p - 1) == '\r'))
        {
            *(p - 1) = 0;
        }
        else
        {
            *p = 0;
        }
        snprintf(text, len, "%s", *ptr);
        ++p;
        (*ptr) = p;
    }
    else
    {
        **ptr = 0;
    }
    return true;
}

static bool
open_to_mem(ini_list **li, const char *path, const bool write_access)
{
    FILE *fp = NULL;
    int m_line = 0;
    size_t n = 0;
    char buf[MAX_COUNT+1] = { 0 };
    if (write_access)
    {
        fp = fopen(path, "r+");
    }
    else
    {
        fp = fopen(path, "r");
    }
    if (!fp)
    {
        printf("open_to_mem(), fopen failed\n");
        return false;
    }
    (*li)->codes = E_UTF8;
    if (1)
    {
        while (fgets(buf, MAX_COUNT, fp))
        {
            if (!write_access && (*buf == ';' || *buf == '#' || *buf == '\r' || *buf == '\n'))
            {
                continue;
            }
            n = strlen(buf);
            if (buf[n - 2] == '\r')
            {
                if (!m_line)
                {
                    (*li)->breaks = CHR_WIN;
                }
                if (!write_access)
                {
                    buf[n - 2] = '\0';
                }
            }
            else if (buf[n - 1] == '\n')
            {
                if (!m_line)
                {
                    (*li)->breaks = CHR_UNIX;
                }
                if (!write_access)
                {
                    buf[n - 1] = '\0';
                }
            }
            if (!list_insert(&(*li)->pd, NULL, buf))
            {
                printf("list_add failed\n");
            }
            ++m_line;
        }
    }
    if (!write_access)
    {
        fclose(fp);
        fp = NULL;
    }
    else
    {
        (*li)->pf = fp;
    }
    return true;
}

static position
list_parser(node **pphead, const char *ps, const char *pk, char **value)
{
    bool s_find = false;
    bool v_find = false;
    int m_section = 0;
    node *it = NULL;
    for (it = *pphead; it; it = it->next)
    {
        char section[LEN_SECTION + 1] = { 0 };
        if (it->content[0] == ';' || it->content[0] == '#')
        {
            continue;
        }
        if (it->content[0] == '[' && strrchr(it->content, ']'))
        {
            if (s_find)
            {
                ++m_section;
            }
            if (m_section > 1)
            {
                break;
            }
            if (sscanf(it->content, "[%[^]]", section) != 1)
            {
                break;
            }
            if (strcmp(ps, section) == 0)
            {
                if (!pk)
                {
                    v_find = true;
                    break;
                }
                ++m_section;
                s_find = true;
                continue;
            }
        }
        else if (s_find)
        {
            char key[MAX_COUNT] = { 0 };
            if (MAX_COUNT > strlen(it->content) && sscanf(it->content, "%[^=$ ]", key) == 1 && strcmp(pk, key) == 0)
            {
                if (!value)
                {
                    v_find = true;
                    break;
                }
                if ((*value = (char *) calloc(MAX_COUNT, 1)) == NULL)
                {
                    break;
                }
                if (sscanf(it->content, "%*[^=] = %[^\'|;|#|\r|\n]", *value) == 1 ||
                    sscanf(it->content, "%*[^=] = \'%[^\'|;|#|\r|\n]", *value) == 1)
                {
                    v_find = true;
                }
                else
                {
                    free(*value); *value = NULL;
                }
                break;
            }
        }
    }
    if (!v_find)
    {
        return NULL;
    }
    return it;
}

static void
list_section(node **pphead, char (*lpdata)[LEN_SECTION], const int line)
{
    int i = 0;
    node *it = NULL;
    for (it = *pphead; it && i < line; it = it->next)
    {
        char *p = NULL;
        if (it->content[0] == '[' && (p = strrchr(it->content, ']')))
        {
            sscanf(&it->content[1], "%[^]]", lpdata[i++]);
        }
    }
}

static bool
ini_foreach_entry(node **pphead, const char *sec, char (*lpdata)[LEN_STRINGS], int line, bool get_key)
{
    bool res = false;
    position pos = NULL;
    if (!(pphead && *pphead))
    {
        return false;
    }
    if ((pos = list_parser(pphead, sec, NULL, NULL)) != NULL)
    {
        int i = 0;
        for (node *cur = pos; cur && i < line;)
        {
            cur = cur->next;
            if (!cur || *cur->content == '[')
            {
                break;
            }
            else if (*cur->content == ';' || *cur->content == '#' ||
                    *cur->content == '\r' || *cur->content == '\n')
            {
                continue;
            }
            if (!get_key)
            {
                if (sscanf(cur->content, "%*[^=] = %[^\'|;|#|\r|\n]", lpdata[i]) == 1 ||
                    sscanf(cur->content, "%*[^=] = \'%[^\'|;|#|\r|\n]", lpdata[i]) == 1)
                {
                    printf("got it.\n");
                }
            }
            else
            {
                sscanf(cur->content, "%[^\r\n]", lpdata[i]);
            }
            if (*lpdata[i] == '\0')
            {
                continue;
            }
            ++i;
        }
        if (i < line)
        {
            memset(lpdata[i], 0, sizeof(lpdata[i]));
        }
        res = true;
    }
    return res;
}

static void
save_to_file(ini_list **li)
{
    fseek((*li)->pf, 0x0L, SEEK_SET);
    truncate_file((*li)->pf, 0);
    for (node *cur = (*li)->pd; cur;)
    {
        fwrite(cur->content, 1, strlen(cur->content), (*li)->pf);
        cur = cur->next;
    }
}

/* 销毁解析器 */
void
iniparser_destroy_cache(ini_cache *pli)
{
    if (!(pli && *pli))
    {
        return;
    }
    if ((*pli)->write)
    {
        save_to_file(pli);
    }
    if ((*pli)->pf)
    {
        fclose((*pli)->pf);
        (*pli)->pf = NULL;
    }
    list_destroy(pli);
}

/** * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *
 * ini 必须是utf8文件名
 */
static bool
iniparser_from_file(const char *ini, ini_list **ini_table, const bool write_access)
{
    bool res = false;
    do
    {
        if (!exists_file(ini))
        {
            if (!write_access)
            {
                break;
            }
            if (create_file(ini, 0755))
            {
                break;
            }
        }
        if (list_init(ini_table) == NULL)
        {
            break;
        }
        if (!open_to_mem(ini_table, ini, write_access))
        {
            printf("open_to_mem error!\n");
            list_destroy(ini_table);
            break;
        }
        res = true;
    }while (0);
    return res;
}

static bool
iniparser_from_memory(const char *buf, const int size, ini_list **ini_table)
{
    bool ret = false;
    char *ptxt = strdup(buf);
    str_line eol = CHR_UNKOWN;
    if (ptxt && (eol = get_block_eol(ptxt, (const int)strlen(ptxt))) && list_init(ini_table))
    {
        char *tmp = ptxt;
        char text[MAX_COUNT+1] = {0};
        (*ini_table)->codes = E_UTF8;
        (*ini_table)->breaks = eol;
        while ((*tmp) && read_lines(text, MAX_COUNT, &tmp))
        {
            if (*text == ';' || *text == '#')
            {
                continue;
            }
            if (!list_insert(&(*ini_table)->pd, NULL, text))
            {
                printf("list_add failed\n");
                break;
            }
        }
        ret = true;
    }
    ini_safe_free(ptxt);
    return ret;
}

ini_cache
iniparser_create_cache(const char *ini, const int access_or_size, const bool isfile)
{
    ini_cache ini_handle = NULL;
    if (isfile)
    {
        if (iniparser_from_file(ini, &ini_handle, (const bool)access_or_size))
        {
            ini_handle->write = (const bool)access_or_size;
        }
    }
    else if (iniparser_from_memory(ini, access_or_size, &ini_handle))
    {
        ini_handle->write = false;
    }
    return ini_handle;
}

static bool
erase_node(node *en, const char *v)
{
    static bool turn = false;
    if (strncmp(en->content, v, strlen(v)) == 0)
    {
        turn = true;
    }
    else if (*en->content == '[' && strrchr(en->content, ']'))
    {
        turn = false;
    }
    return turn;
}

bool
inicache_delete_section(const char *sec, ini_cache *ini)
{
    bool res = false;
    position pos = NULL;
    if (!(ini && *ini))
    {
        return false;
    }
    if ((pos = list_parser(&(*ini)->pd, sec, NULL, NULL)) != NULL)
    {
        char sec_name[LEN_SECTION] = {0};
        snprintf(sec_name, LEN_SECTION, "[%s]", sec);
        list_delete_if(&(*ini)->pd, erase_node, sec_name);
        res = true;
    }
    return res;
}

bool
ini_delete_section(const char *sec, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, true, true);
    if (!plist)
    {
        return false;
    }
    res = inicache_delete_section(sec, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

static void
replace_insert(node **pnode, const char *in, const char *sub, const char *by)
{
    char *res = NULL, *needle = NULL;
    const char *in_ptr = in;
    size_t in_size = strlen(in) + 16;
    if ((res = (char *)malloc(in_size)) == NULL || sub == NULL || by == NULL)
    {
        return;
    }
    while ((needle = strstr(in_ptr, sub)) != NULL)
    {
        memset(res, 0, in_size);
        if (needle - in_ptr > 0)
        {
            strncpy(res, in_ptr, needle - in_ptr);
        }
        wp_strncat(res, by, in_size - 1);
        list_insert(pnode, NULL, res);
        in_ptr = needle + (int) strlen(sub);
    }
    if (*in_ptr != '\0')
    {
        list_insert(pnode, NULL, in_ptr);
    }
    free(res);
}

bool
inicache_new_section(const char *value, ini_cache *ini)
{
    int  len = 0;
    char *end, *ptr = NULL;
    char sec[LEN_SECTION+1] = {0};

    if (!(ini && *ini))
    {
        return false;
    }
    if ((ptr = strchr(value, '[')) == NULL)
    {
        return false;
    }
    if ((end = strchr(ptr, ']')) == NULL)
    {
        return false;
    }
    if ((len = (int)(end-ptr+2)) > LEN_SECTION)
    {
        return false;
    }
    else
    {
        snprintf(sec, len, "%s", ptr);
    }
    if (*sec != '\0' && list_find(&(*ini)->pd, sec))
    {
        printf("%s exists, no need to add.\n", sec);
        return false;
    }
    return list_insert(&(*ini)->pd, NULL, value);
}

bool
ini_new_section(const char *value, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, true, true);
    if (!plist)
    {
        return false;
    }
    res = inicache_new_section(value, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
inicache_section_exists(const char *value, ini_cache *ini)
{
    if (value && ini)
    {
        return (list_find(&(*ini)->pd, value) != NULL);
    }
    return false;
}

bool
ini_section_exists(const char *value, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false, true);
    if (!plist)
    {
        return false;
    }
    res = inicache_section_exists(value, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

void
inicache_foreach_section(char (*lpdata)[LEN_SECTION], const int line, ini_cache *ini)
{
    list_section(&(*ini)->pd, lpdata, line);
}

void
ini_foreach_section(char (*lpdata)[LEN_SECTION], const int line, const char *path, const bool isfile)
{
    ini_cache plist = iniparser_create_cache(path, true, isfile);
    if (plist)
    {
        inicache_foreach_section(lpdata, line, &plist);
        iniparser_destroy_cache(&plist);
    }
}

bool
inicache_write_string(const char *sec, const char *key, const char *value, ini_cache *ini)
{
    bool res = true;
    position pos = NULL;
    if (!(ini && *ini && sec))
    {
        return false;
    }
    if ((pos = list_parser(&(*ini)->pd, sec, key, NULL)) != NULL)
    {
        if (value)
        {
            const char *separator = strchr(pos->content, '=');
            if (separator && *(separator - 1) == ' ')
            {
                snprintf(pos->content, LEN_CONTENT, "%s = %s", key, value);
            }
            else if (separator)
            {
                snprintf(pos->content, LEN_CONTENT, "%s=%s", key, value);
            }
            if ((*ini)->breaks == CHR_WIN)
            {
                wp_strncat(pos->content, "\r\n", LEN_CONTENT);
            }
            else
            {
                wp_strncat(pos->content, "\n", LEN_CONTENT);
            }
        }
        else
        {
            list_delete_node(&(*ini)->pd, pos);
        }
    }
    else if (key && value && (pos = list_parser(&(*ini)->pd, sec, NULL, NULL)) != NULL)
    {
        size_t len = strlen(key) + strlen(value) + 6;
        char *new_value = (char *) calloc(len + 1, 1);
        if (new_value)
        {
            if ((*ini)->breaks == CHR_WIN)
            {
                snprintf(new_value, len, "%s=%s\r\n", key, value);
            }
            else
            {
                snprintf(new_value, len, "%s=%s\n", key, value);
            }
            if (list_insert(&(*ini)->pd, pos, new_value))
            {
                res = true;
            }
            free(new_value);
        }
    }
    else
    {
        res = false;
    }
    return res;
}

bool
ini_write_string(const char *sec, const char *key, const char *new_value, const char *path)
{
    bool res = false;
    ini_cache plist = NULL;
    if ((plist = iniparser_create_cache(path, true, true)) != NULL)
    {
        res = inicache_write_string(sec, key, new_value, &plist);
        iniparser_destroy_cache(&plist);
    }
    return res;
}

bool
inicache_read_string(const char *sec, const char *key, char **buf, ini_cache *ini)
{
    bool res = false;
    position pos = NULL;
    if (!(ini && *ini))
    {
        return false;
    }
    if ((pos = list_parser(&(*ini)->pd, sec, key, buf)) != NULL)
    {
        res = true;
    }
    return res;
}

bool
ini_read_string(const char *sec, const char *key, char **buf, const char *path, const bool isfile)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false, isfile);
    if (!plist)
    {
        return false;
    }
    res = inicache_read_string(sec, key, buf, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

uint64_t
ini_read_uint64(const char *sec, const char *key, const char *path, const bool isfile)
{
    char *m_str = NULL;
    uint64_t result = 0;
    if (ini_read_string(sec, key, &m_str, path, isfile))
    {
        result = strtoull(m_str, NULL, 10);
        free(m_str);
    }
    return result;
}

uint64_t
inicache_read_uint64(const char *sec, const char *key, ini_cache *ini)
{
    uint64_t res = 0;
    char *value = NULL;
    if (inicache_read_string(sec, key, &value, ini))
    {
        res = strtoull(value, NULL, 10);
    }
    if (value)
    {
        free(value);
    }
    return res;
}
int
ini_read_int(const char *sec, const char *key, const char *path, const bool isfile)
{
    int res = 0;
    char *value = NULL;
    if (ini_read_string(sec, key, &value, path, isfile))
    {
        res = atoi(value);
    }
    if (value)
    {
        free(value);
    }
    return res;
}

int
inicache_read_int(const char *sec, const char *key, ini_cache *ini)
{
    int res = 0;
    char *value = NULL;
    if (inicache_read_string(sec, key, &value, ini))
    {
        res = atoi(value);
    }
    if (value)
    {
        free(value);
    }
    return res;
}

bool
inicache_foreach_key(const char *sec,
                     char (*lpdata)[LEN_STRINGS],
                     const int line,
                     ini_cache *ini)
{
    if (!(ini && *ini))
    {
        return false;
    }
    return ini_foreach_entry(&(*ini)->pd, sec, lpdata, line , true);
}

/************************************************************
 * 遍历区段,把获得key和它的值写入lpdata二维数组             *
 * ini 区段入口                                             *
 * 二维数组首地址,保存多个段值                              *
 * 二维数组行数                                             *
 * ini文件路径                                              *
 ************************************************************/
bool
ini_foreach_key(const char *sec,
                char (*lpdata)[LEN_STRINGS],
                const int line,
                const char *path,
                const bool isfile)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false, isfile);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_key(sec, lpdata, line, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
inicache_foreach_string(const char *sec,
                        char (*lpdata)[LEN_STRINGS],
                        const int line,
                        ini_cache *ini)
{
    if (!(ini && *ini))
    {
        return false;
    }
    return ini_foreach_entry(&(*ini)->pd, sec, lpdata, line , false);
}

/************************************************************
 * 遍历区段,把获得key的值写入lpdata二维数组                 *
 * ini 区段入口                                             *
 * 二维数组首地址,保存多个段值                              *
 * 二维数组行数                                             *
 * ini文件路径                                              *
 ************************************************************/
bool
ini_foreach_string(const char *sec,
                   char (*lpdata)[LEN_STRINGS],
                   const int line,
                   const char *path,
                   const bool isfile)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false, isfile);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_string(sec, lpdata, line, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
inicache_search_string(const char *key, char **buf, ini_cache *ini)
{
    bool res = false;
    position pos = NULL;
    if (!(ini && *ini))
    {
        return false;
    }
    if ((pos = list_find(&(*ini)->pd, key)) != NULL)
    {
        position sec = NULL;
        list_rfind(&(*ini)->pd, pos, &sec);
        if (sec && (*buf = calloc(strlen(sec->content) + 1, 1)) != NULL &&
            sscanf(sec->content, "[%[^]]", *buf) == 1)
        {
            res = true;
        }
    }
    return res;
}

bool
ini_search_string(const char *key, char **buf, const char *path, const bool isfile)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false, isfile);
    if (!plist)
    {
        return false;
    }
    res = inicache_search_string(key, buf, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

/* 交换节点 */
static node* node_swap(node* ptr1, node* ptr2)
{
    node* tmp = ptr2->next;
    ptr2->next = ptr1;
    ptr1->next = tmp;
    return ptr2;
}

/* 冒泡排序算法实现链表局部排序 */
static void bubble_sort(node** head, int count)
{
    node** h;
    int i, j, swapped;

    for (i = 0; i <= count; i++) {

        h = head;
        swapped = 0;

        for (j = 0; j < count - i - 1; j++) {

            node* p1 = *h;
            node* p2 = p1->next;

            if (strcmp(p1->content, p2->content) > 0) {

                /* update the link after swapping */
                *h = node_swap(p1, p2);
                swapped = 1;
            }

            h = &(*h)->next;
        }

        /* break if the loop ended without any swap */
        if (swapped == 0)
            break;
    }
}

/* ini区段排序 */
bool
inicache_sort_section(const char *sec, ini_cache *ini)
{
    int n = 0;
    position pos = NULL;
    if (!(pos = list_parser(&(*ini)->pd, sec, NULL, NULL)))
    {
        return false;
    }
    for (node *cur = pos->next; cur; cur = cur->next, n++)
    {
        if (*cur->content == '[')
        {
            break;
        }
        else if (*cur->content == '\r' || *cur->content == '\n')
        {
            if (cur->next != NULL && *cur->next->content != '[')
            {
                list_delete_node(&(*ini)->pd, cur);
            }
            --n;
            continue;
        }
    }
    bubble_sort(&pos->next, n);
    return true;
}

bool
ini_sort_section(const char *sec, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, true, true);
    if (!plist)
    {
        return false;
    }
    res = inicache_sort_section(sec, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
