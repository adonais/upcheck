#include <string.h>
#ifdef _MSC_VER
#include <io.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif
#include <wchar.h>
#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#endif
#include "ini_parser.h"

#define LEN_CONTENT 260
#define MAX_COUNT 1024
#define LEN_STRINGS 128
#define LEN_SECTION 64

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
            unsigned int tmp = (GET_BYTE) -128;  \
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
    *pli = (ini_list *) calloc(1, sizeof(ini_list));
    if (*pli)
    {
        if (((*pli)->pd = (node *) calloc(1, sizeof(node))) == NULL)
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
    node *t = (node *) calloc(1, sizeof(node) + LEN_CONTENT);
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
        if (NULL == (tmp = (node *) calloc(1, sizeof(node) + LEN_CONTENT)))
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

char*
ini_make_u8(const wchar_t *utf16, char *utf8, int len)
{
    *utf8 = 0;
    int m = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, len, NULL, NULL);
    if (m > 0 && m <= len)
    {
        utf8[m-1] = 0;
    }
    else if (len > 0)
    {
        utf8[len-1] = 0;
    }
    return utf8;
}

/***********************************************************************************
 * 如果函数执行成功, (*out_len) 返回转换后的字符个数, 包含结束符0
 * 所以, buf =  (*out_len - 1) * sizeof(TCHAR)
 ***********************************************************************************/
char*
ini_utf16_utf8(const wchar_t *utf16, size_t *out_len)
{
    int   m, size = 0;
    char *utf8 = NULL;

    size = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, NULL, 0, NULL, NULL);
    utf8 = size > 0 ? (char*) malloc(size+1) : 0;
    if (NULL == utf8 )
    {
        return NULL;
    }
    m = WideCharToMultiByte(CP_UTF8, 0, utf16, -1, utf8, size, NULL, NULL);
    if (m > 0 && m <= size)
    {
        if (out_len)
        {
            *out_len = (size_t)m;
        }
        utf8[m-1] = 0;
    }
    else
    {
        free(utf8);
        utf8 = NULL;
    }
    return utf8;
}

char*
ini_utf16_mbcs(int codepage, const wchar_t *utf16, size_t *out_len)
{
    int   size = 0;
    char *a8 = NULL;
    if (codepage < 0)
    {
        codepage= AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    }
    size = WideCharToMultiByte(codepage, 0, utf16, -1, NULL, 0, NULL, NULL);
    a8 = size > 0 ? (char*) malloc(size+ 1) : 0;
    if (NULL == a8)
    {
        return NULL;
    }
    size = WideCharToMultiByte(codepage, 0, utf16, -1, a8, size, NULL, NULL);
    if (size > 0)
    {
        if (out_len)
        {
            *out_len = (size_t)size;
        }
    }
    else
    {
        free(a8);
        a8 = NULL;
    }
    return a8;
}

wchar_t*
ini_mbcs_utf16(int codepage, const char *ansi, size_t *out_len)
{
    int size;
    wchar_t *u16 = NULL;
    if (codepage < 0)
    {
        codepage= AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    }
    size = MultiByteToWideChar(codepage, 0, ansi, -1, NULL, 0);
    u16 = size > 0 ? (wchar_t*) malloc(sizeof(wchar_t) * (size + 1)) : 0;
    if (!u16)
    {
        return NULL;
    }
    size = MultiByteToWideChar(codepage, 0, ansi, -1, u16, size);
    if (size > 0)
    {
        if (out_len)
        {
            *out_len = (size_t)size;
        }
    }
    else
    {
        free(u16);
        return NULL;
    }
    return u16;
}

char*
ini_mbcs_utf8(int codepage, const char *ansi, size_t *out_len)
{
#ifdef _WIN32
    char *utf8 = NULL;
    wchar_t *u16 = ini_mbcs_utf16(codepage, ansi, NULL);
    if (u16)
    {
        utf8 = ini_utf16_utf8(u16, out_len);
        free(u16);
    }
    return utf8;
#else
  return strdup(ansi);
#endif
}

wchar_t*
ini_utf8_utf16(const char *utf8, size_t *out_len)
{
    int size;
    wchar_t *u16 = NULL;
    size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    u16 = size > 0 ? (wchar_t*) malloc(sizeof(wchar_t) * (size + 1)) : 0;
    if (!u16)
    {
        return NULL;
    }
    size = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, u16, size);
    if (size > 0)
    {
        if (out_len)
        {
            *out_len = (size_t)size;
        }
    }
    else
    {
        free(u16);
        return NULL;
    }
    return u16;
}

char*
ini_utf8_mbcs(int codepage, const char *utf8, size_t *out_len)
{
#ifdef _WIN32
    char *a8 = NULL;
    wchar_t *u16 = ini_utf8_utf16(utf8, NULL);
    if (u16)
    {
        a8 = ini_utf16_mbcs(codepage, u16, out_len);
        free(u16);
    }
    return a8;
#else
  return strdup(utf8);
#endif
}

static int
utf8_to_utf16be(uint8_t *outb, int *outlen, const uint8_t *in, int *inlen)
{
    uint16_t *out = (uint16_t *) outb;
    const uint8_t *processed = in;
    const uint8_t *const instart = in;
    uint16_t *outstart = out;
    uint16_t *outend;
    const uint8_t *inend;
    uint32_t c, d;
    int trailing;
    uint8_t *tmp;
    uint16_t tmp1, tmp2;

    /* UTF-16BE has no BOM */
    if ((outb == NULL) || (outlen == NULL) || (inlen == NULL)) return (-1);
    if (in == NULL)
    {
        *outlen = 0;
        *inlen = 0;
        return (0);
    }
    inend = in + *inlen;
    outend = out + (*outlen / 2);
    while (in < inend)
    {
        d = *in++;
        if (d < 0x80)
        {
            c = d;
            trailing = 0;
        }
        else if (d < 0xC0)
        {
            /* trailing byte in leading position */
            *outlen = (int)(out - outstart);
            *inlen = (int)(processed - instart);
            return (-2);
        }
        else if (d < 0xE0)
        {
            c = d & 0x1F;
            trailing = 1;
        }
        else if (d < 0xF0)
        {
            c = d & 0x0F;
            trailing = 2;
        }
        else if (d < 0xF8)
        {
            c = d & 0x07;
            trailing = 3;
        }
        else
        {
            /* no chance for this in UTF-16 */
            *outlen = (int)(out - outstart);
            *inlen = (int)(processed - instart);
            return (-2);
        }

        if (inend - in < trailing)
        {
            break;
        }

        for (; trailing; trailing--)
        {
            if ((in >= inend) || (((d = *in++) & 0xC0) != 0x80)) break;
            c <<= 6;
            c |= d & 0x3F;
        }

        /* assertion: c is a single UTF-4 value */
        if (c < 0x10000)
        {
            if (out >= outend) break;
            if (true)
            {
                tmp = (uint8_t *) out;
                *tmp = c >> 8;
                *(tmp + 1) = c;
                out++;
            }
        }
        else if (c < 0x110000)
        {
            if (out + 1 >= outend) break;
            c -= 0x10000;
            if (true)
            {
                tmp1 = 0xD800 | (c >> 10);
                tmp = (uint8_t *) out;
                *tmp = tmp1 >> 8;
                *(tmp + 1) = (uint8_t) tmp1;
                out++;

                tmp2 = 0xDC00 | (c & 0x03FF);
                tmp = (uint8_t *) out;
                *tmp = tmp2 >> 8;
                *(tmp + 1) = (uint8_t) tmp2;
                out++;
            }
        }
        else
        {
            break;
        }
        processed = in;
    }
    *outlen = (int)(out - outstart) * 2;
    *inlen = (int)(processed - instart);
    return (*outlen);
}

static bool
utf8_check(const uint8_t *str)
{
    const uint8_t *byte;
    uint32_t codepoint, min;
    while (*str)
    {
        byte = str;
        GET_UTF8(codepoint, *(byte++), return false;);
        min = byte - str == 1 ? 0 : byte - str == 2 ? 0x80 : 1 << (5 * (byte - str) - 4);
        if (codepoint < min || codepoint >= 0x110000 ||
            codepoint == 0xFFFE /* BOM */ ||
            (codepoint >= 0xD800 && codepoint <= 0xDFFF) /* surrogates */
           )
            return false;
        str = byte;
    }
    return true;
}

static str_encoding
get_file_type(FILE *fp)
{
    uint32_t m = 0x0;
    str_encoding m_type = E_OTHER;
    fseek(fp, 0L, SEEK_SET);
    if (fread((char *) &m, 1, 1, fp) != 1)
    {
        return m_type;
    }
    m <<= 8;
    if (fread((char *) &m, 1, 1, fp) != 1)
    {
        return m_type;
    }
    switch (m) // 判断文本前两个字节
    {
        case 0xfffe: // fffe
            m_type = E_UNICODE;
            break;
        case 0xfeff: // feff
            m_type = E_UNICODE_BIG;
            break;
        case 0xefbb: // efbbbf
            m <<= 8;
            if (fread((char *) &m, 1, 1, fp) != 1)
            {
                break;
            }
            if (m == 0xefbbbf) // 判断文本前三个字节
            {
                m_type = E_UTF8_BOM;
            }
            break;
        default:
            m_type = E_UTF8;
            fseek(fp, 0L, SEEK_SET);
    }
    return m_type;
}

static inline void
be_to_le(uint16_t *in)
{
    uint16_t tmp = *in >> 8 | *in << 8;
    *in = tmp;
}

static wchar_t *
fgetws_ex(wchar_t *string, int n, FILE *stream, str_encoding m_type)
{
    if (!string || !stream || feof(stream) || n <= 0)
    {
        return NULL;
    }
    int i = 0;
    while (i < n - 1 && !feof(stream))
    {
        if (fread(&string[i], sizeof(wchar_t), 1, stream) != 1) break;
        if (m_type == E_UNICODE_BIG)
        {
            be_to_le(&string[i]);
        }
        // Check the character readed, break if it's '\n'
        if (string[i] == L'\n')
        {
            i++;
            break;
        }
        i++;
    }
    string[i] = 0x0;
    return string;
}
static bool
open_to_mem(ini_list **li, const wchar_t *path, const bool write_access)
{
    FILE *fp = NULL;
    str_encoding m_type = E_OTHER;
    int m_line = 0;
    size_t n = 0;
    char buf[MAX_COUNT+1] = {0};
    if (write_access)
    {
        fp = _wfopen(path, L"rb+");
    }
    else
    {
        fp = _wfopen(path, L"rb");
    }
    if (!fp)
    {
        printf("open_to_mem(), _wfopen failed\n");
        return false;
    }
    if ((m_type = get_file_type(fp)) == E_OTHER)
    {
        FILE *fp_end = fp;
        int filesize = fseek(fp_end, 0, SEEK_END);
        if (filesize)
        {
            printf("unkown file encode!\n");
            fclose(fp);
            return false;
        }
    }
    (*li)->codes = m_type;
    if (m_type == E_UNICODE || m_type == E_UNICODE_BIG)
    {
        wchar_t wbuf[MAX_COUNT] = { 0 };
        while (fgetws_ex(wbuf, MAX_COUNT, fp, m_type))
        {
            n = wcslen(wbuf);
            if (!write_access && (*wbuf == L';' || *wbuf == L'#' || *wbuf == L'\r' || *wbuf == L'\n'))
            {
                continue;
            }
            if (wbuf[n - 2] == L'\r')
            {
                if (!m_line)
                {
                    (*li)->breaks = CHR_WIN;
                }
                if (!write_access)
                {
                    wbuf[n - 2] = L'\0';
                }
            }
            else if (wbuf[n - 1] == L'\n')
            {
                if (!m_line)
                {
                    (*li)->breaks = CHR_UNIX;
                }
                if (!write_access)
                {
                    wbuf[n - 1] = L'\0';
                }
            }
            if (ini_make_u8(wbuf, buf, MAX_COUNT)[0])
            {
                list_insert(&(*li)->pd, NULL, buf);
            }
            ++m_line;
        }
    }
    else
    {
        while (fgets(buf, MAX_COUNT, fp))
        {
            char *data = NULL;
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
            if ((m_type != E_UTF8_BOM) && !utf8_check((const uint8_t *)buf) &&
               ((data = ini_mbcs_utf8(-1, buf, NULL)) != NULL))
            {
                strncpy(buf, data, MAX_COUNT);
                free(data);
                (*li)->codes = E_ANSI;
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
        char section[LEN_SECTION + 1] = {0};
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
            char key[LEN_SECTION + 1] = {0};
            if (sscanf(it->content, "%[^=$ ]", key) == 1 && strcmp(pk, key) == 0)
            {
                if (!value)
                {
                    v_find = true;
                    break;
                }
                if ((*value = (char *) calloc(1, MAX_COUNT)) == NULL)
                {
                    break;
                }
                if (sscanf(it->content, "%*[^=] = %[^\'|;|#]", *value) == 1 ||
                    sscanf(it->content, "%*[^=] = \'%[^\'|;|#]", *value) == 1)
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

static bool
ini_foreach_entry(node **pphead, const char *sec, char (*lpdata)[129], int line, bool get_key)
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
            if (*cur->content == '[')
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
                if (sscanf(cur->content, "%*[^=] = %[^\'|;|#]", lpdata[i]) == 1 ||
                    sscanf(cur->content, "%*[^=] = \'%[^\'|;|#]", lpdata[i]) == 1)
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
    switch ((*li)->codes)
    {
        case E_UNICODE:
        case E_UNICODE_BIG:
            truncate_file((*li)->pf, 2);
            fseek((*li)->pf, 0x2L, SEEK_SET);
            break;
        case E_UTF8_BOM:
            truncate_file((*li)->pf, 3);
            fseek((*li)->pf, 0x3L, SEEK_SET);
            break;
        default:
            fseek((*li)->pf, 0x0L, SEEK_SET);
            truncate_file((*li)->pf, 0);
            break;
    }
    for (node *cur = (*li)->pd; cur;)
    {
        if ((*li)->codes == E_UNICODE)
        {
            wchar_t u16[MAX_COUNT + 2] = {0};
            int size = MultiByteToWideChar(CP_UTF8, 0, cur->content, -1, u16, MAX_COUNT);
            if (size > 0)
            {
                fwrite(u16, sizeof(wchar_t), wcslen(u16), (*li)->pf);
            }
        }
        else if ((*li)->codes == E_UNICODE_BIG)
        {
            int inlen = (int)strlen(cur->content);
            int outlen = MAX_COUNT;
            char u16[MAX_COUNT + 2] = {0};
            int size = utf8_to_utf16be((uint8_t *)u16, &outlen, (const uint8_t *)cur->content, &inlen);
            if (size > 0 && outlen > 2)
            {
                fwrite(u16, 1, outlen, (*li)->pf);
            }
        }
        else if ((*li)->codes == E_ANSI)
        {
            char *a8 = ini_utf8_mbcs(-1, cur->content, NULL);
            if (a8)
            {
                fwrite(a8, 1, strlen(a8), (*li)->pf);
                free(a8);
            }
        }
        else
        {
            fwrite(cur->content, 1, strlen(cur->content), (*li)->pf);
        }
        cur = cur->next;
    }
}

static bool
iniparser_exist_dir(const wchar_t *path)
{
    uint32_t fileattr = GetFileAttributesW(path);
    if (fileattr != INVALID_FILE_ATTRIBUTES)
    {
        return (fileattr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    return false;
}

static bool
iniparser_create_file(const wchar_t *dir)
{
    wchar_t *p = NULL;
    wchar_t tmp_name[MAX_PATH] = {0};
    wcsncpy(tmp_name, dir, MAX_PATH - 1);
    p = wcschr(tmp_name, L'\\');
    for (; p != NULL; *p = L'\\', p = wcschr(p + 1, L'\\'))
    {
        *p = L'\0';
        if (iniparser_exist_dir(tmp_name))
        {
            continue;
        }
        if (!CreateDirectoryW(tmp_name, NULL))
        {
            return false;
        }
    }
    return (_waccess(tmp_name, 0) != -1 ? true: (fclose(_wfopen(tmp_name, L"wb+")), true));
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
ini_parser_create(const char *ini, ini_list **ini_table, bool write_access)
{
    bool res = false;
    wchar_t *u16_path = NULL;
    do
    {
        if ((u16_path = ini_utf8_utf16(ini, NULL)) == NULL)
        {
            break;
        }
        if (_waccess(u16_path, 0) == -1)
        {
            if (!write_access)
            {
                break;
            }
            if (!iniparser_create_file(u16_path))
            {
                break;
            }
        }
        if (list_init(ini_table) == NULL)
        {
            break;
        }
        if (!open_to_mem(ini_table, u16_path, write_access))
        {
            list_destroy(ini_table);
            break;
        }
        res = true;
    }while (0);
    if (u16_path)
    {
        free(u16_path);
    }
    return res;
}

ini_cache
iniparser_create_cache(const char *ini, bool write_access)
{
    ini_cache ini_handle = NULL;
    if (ini_parser_create(ini, &ini_handle, write_access))
    {
        ini_handle->write = write_access;
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
        char sec_name[LEN_SECTION + 1] = {0};
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
    ini_cache plist = iniparser_create_cache(path, true);
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
    char *res = NULL;
    char *needle;
    const char *split = sub;
    const char *in_ptr = in;
    size_t in_size = strlen(in) + 16;
    if ((res = (char *)malloc(in_size)) == NULL)
    {
        return;
    }
    needle = strstr(in_ptr, sub);
    if (!needle)
    {
        needle = strstr(in_ptr, by);
        split = by;
    }
    while (needle)
    {
        memset(res, 0, in_size);
        if (needle - in_ptr == 0)
        {
            strncpy(res, in_ptr, strlen(by));
        }
        else
        {
            strncpy(res, in_ptr, needle - in_ptr);
            strncat(res, by, in_size - 1);
        }
        list_insert(pnode, NULL, res);
        in_ptr = needle + (int) strlen(split);
        needle = strstr(in_ptr, split);
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
    if ((*ini)->breaks == CHR_WIN)
    {
        replace_insert(&(*ini)->pd, value, "\n", "\r\n");
    }
    else
    {
        replace_insert(&(*ini)->pd, value, "\r\n", "\n");
    }
    return true;
}

bool
ini_new_section(const char *value, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, true);
    if (!plist)
    {
        return false;
    }
    res = inicache_new_section(value, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
inicache_write_string(const char *sec, const char *key, const char *value, ini_cache *ini)
{
    bool res = true;
    position pos = NULL;
    if (!(ini && *ini))
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
                strncat(pos->content, "\r\n", LEN_CONTENT);
            }
            else
            {
                strncat(pos->content, "\n", LEN_CONTENT);
            }
        }
        else
        {
            list_delete_node(&(*ini)->pd, pos);
        }
    }
    else if ((pos = list_parser(&(*ini)->pd, sec, NULL, NULL)) != NULL)
    {
        size_t len = strlen(key) + strlen(value) + 6;
        char *new_value = (char *) calloc(1, len + 1);
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
    if ((plist = iniparser_create_cache(path, true)) != NULL)
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
ini_read_string(const char *sec, const char *key, char **buf, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_read_string(sec, key, buf, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

int
ini_read_int(const char *sec, const char *key, const char *path)
{
    int res = 0;
    char *value = NULL;
    if (ini_read_string(sec, key, &value, path))
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
inicache_foreach_wkey(const char *sec,
                      wchar_t (*lpdata)[129],
                      const int line,
                      ini_cache *ini)
{
    int  i = 0;
    bool res = false;
    char (*data)[129] = NULL;
    if (!(ini && *ini))
    {
        return false;
    }
    data = (char (*)[129])calloc(1, line * sizeof(data[0]));
    if (!data)
    {
        return false;
    }
    res = ini_foreach_entry(&(*ini)->pd, sec, data, line , true);
    if (!res)
    {
        free(data);
        return false;
    }
    for (; i < line && *data[i] != '\0'; ++i)
    {
        res = MultiByteToWideChar(CP_UTF8, 0, data[i], -1, lpdata[i], LEN_STRINGS)>0;
    }
    if (i < line)
    {
        lpdata[i][0] = 0;
    }
    free(data);
    return res;
}

bool
inicache_foreach_key(const char *sec,
                     char (*lpdata)[129],
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
                char (*lpdata)[129],
                const int line,
                const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_key(sec, lpdata, line, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
ini_foreach_wkey(const char *sec,
                wchar_t (*lpdata)[129],
                const int line,
                const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_wkey(sec, lpdata, line, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
inicache_foreach_wstring(const char *sec,
                         wchar_t (*lpdata)[129],
                         const int line,
                         ini_cache *ini)
{
    int  i = 0;
    bool res = false;
    char (*data)[129] = NULL;
    if (!(ini && *ini))
    {
        return false;
    }
    data = (char (*)[129])calloc(1, line * sizeof(data[0]));
    if (!data)
    {
        return false;
    }
    res = ini_foreach_entry(&(*ini)->pd, sec, data, line , false);
    if (!res)
    {
        free(data);
        return false;
    }
    for (; i < line && *data[i] != '\0'; ++i)
    {
        res = MultiByteToWideChar(CP_UTF8, 0, data[i], -1, lpdata[i], LEN_STRINGS)>0;
    }
    if (i < line)
    {
        lpdata[i][0] = 0;
    }
    free(data);
    return res;
}

bool
inicache_foreach_string(const char *sec,
                        char (*lpdata)[129],
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
                   char (*lpdata)[129],
                   const int line,
                   const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_string(sec, lpdata, line, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

bool
ini_foreach_wstring(const char *sec,
                    wchar_t (*lpdata)[129],
                    const int line,
                    const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_foreach_wstring(sec, lpdata, line, &plist);
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
        if (sec && (*buf = calloc(1, strlen(sec->content) + 1)) != NULL &&
            sscanf(sec->content, "[%[^]]", *buf) == 1)
        {
            res = true;
        }
    }
    return res;
}

bool
ini_search_string(const char *key, char **buf, const char *path)
{
    bool res = false;
    ini_cache plist = iniparser_create_cache(path, false);
    if (!plist)
    {
        return false;
    }
    res = inicache_search_string(key, buf, &plist);
    iniparser_destroy_cache(&plist);
    return res;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
