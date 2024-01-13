#ifndef _INI_PARSER_H
#define _INI_PARSER_H

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_BUFFER_SIZE (16 * 1024)

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    CHR_UNKOWN = 0,
    CHR_WIN,
    CHR_UNIX
} str_line;

typedef enum
{
    E_OTHER = 0,
    E_ANSI,
    E_UNICODE,
    E_UNICODE_BIG,
    E_UTF8,
    E_UTF8_BOM,
} str_encoding;

typedef struct _node
{
    struct _node *next;
    char content[1];
} node, *position;

typedef struct _list
{
    str_encoding codes;
    str_line breaks;
    bool write;
    FILE *pf;
    node *pd;
} ini_list, *ini_cache;

#define ini_safe_free(p) ((p) ? ((free((void *)(p))), ((p) = NULL)) : (void *)(p))

extern bool ini_foreach_key(const char *sec, char (*lpdata)[129], const int line, const char *path, const bool isfile);
extern bool ini_foreach_wkey(const char *sec, wchar_t (*lpdata)[129], const int line, const char *path, const bool isfile);
extern bool inicache_foreach_key(const char *sec, char (*lpdata)[129], const int line, ini_cache *ini);
extern bool inicache_foreach_wkey(const char *sec, wchar_t (*lpdata)[129], const int line, ini_cache *ini);
extern bool ini_foreach_string(const char *sec, char (*lpdata)[129], const int line, const char *path, const bool isfile);
extern bool ini_foreach_wstring(const char *sec, wchar_t (*lpdata)[129], const int line, const char *path, const bool isfile);
extern bool inicache_foreach_string(const char *sec, char (*lpdata)[129], const int line, ini_cache *ini);
extern bool inicache_foreach_wstring(const char *sec, wchar_t (*lpdata)[129], const int line, ini_cache *ini);
extern bool ini_read_string(const char *sec, const char *key, char **buf, const char *path, const bool isfile);
extern bool inicache_read_string(const char *sec, const char *key, char **buf, ini_cache *ini);
extern bool ini_write_string(const char *sec, const char *key, const char *new_value, const char *path);
extern bool inicache_write_string(const char *sec, const char *key, const char *new_value, ini_cache *ini);
extern bool ini_new_section(const char *value, const char *path);
extern bool inicache_new_section(const char *value, ini_cache *ini);
extern bool ini_delete_section(const char *sec, const char *path);
extern bool inicache_delete_section(const char *sec, ini_cache *ini);
extern bool ini_search_string(const char *key, char **buf, const char *path, const bool isfile);
extern bool inicache_search_string(const char *key, char **buf, ini_cache *ini);
extern uint64_t inicache_read_uint64(const char *sec, const char *key, ini_cache *ini);
extern uint64_t ini_read_uint64(const char *sec, const char *key, const char *path, const bool isfile);
extern int  inicache_read_int(const char *sec, const char *key, ini_cache *ini);
extern int  ini_read_int(const char *sec, const char *key, const char *path, const bool isfile);
extern char* ini_utf16_utf8(const wchar_t *utf16, size_t *out_len);
extern char* ini_utf16_mbcs(int codepage, const wchar_t *utf16, size_t *out_len);
extern wchar_t* ini_mbcs_utf16(int codepage, const char *ansi, size_t *out_len);
extern char* ini_mbcs_utf8(int codepage, const char *ansi, size_t *out_len);
extern wchar_t* ini_utf8_utf16(const char *utf8, size_t *out_len);
extern char* ini_utf8_mbcs(int codepage, const char *utf8, size_t *out_len);
extern char* ini_make_u8(const wchar_t *utf16, char *utf8, int len);
extern ini_cache iniparser_create_cache(const char *ini, const int access_or_size, const bool isfile);
extern void iniparser_destroy_cache(ini_cache *li);
#ifdef __cplusplus
}
#endif

#endif   /* _INI_PARSER_H */
