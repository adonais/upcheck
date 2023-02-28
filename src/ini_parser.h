#ifndef _INI_PARSER_H
#define _INI_PARSER_H

#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    CHR_UNKOWN,
    CHR_WIN,
    CHR_UNIX
} str_line;

typedef enum
{
    E_OTHER,
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

extern bool ini_foreach_key(const char *sec, char (*lpdata)[129], const int line, const char *path);
extern bool ini_foreach_wkey(const char *sec, wchar_t (*lpdata)[129], const int line, const char *path);
extern bool inicache_foreach_key(const char *sec, char (*lpdata)[129], const int line, ini_cache *ini);
extern bool inicache_foreach_wkey(const char *sec, wchar_t (*lpdata)[129], const int line, ini_cache *ini);
extern bool ini_foreach_string(const char *sec, char (*lpdata)[129], const int line, const char *path);
extern bool ini_foreach_wstring(const char *sec, wchar_t (*lpdata)[129], const int line, const char *path);
extern bool inicache_foreach_string(const char *sec, char (*lpdata)[129], const int line, ini_cache *ini);
extern bool inicache_foreach_wstring(const char *sec, wchar_t (*lpdata)[129], const int line, ini_cache *ini);
extern bool ini_read_string(const char *sec, const char *key, char **buf, const char *path);
extern bool inicache_read_string(const char *sec, const char *key, char **buf, ini_cache *ini);
extern bool ini_write_string(const char *sec, const char *key, const char *new_value, const char *path);
extern bool inicache_write_string(const char *sec, const char *key, const char *new_value, ini_cache *ini);
extern bool ini_new_section(const char *value, const char *path);
extern bool inicache_new_section(const char *value, ini_cache *ini);
extern bool ini_delete_section(const char *sec, const char *path);
extern bool inicache_delete_section(const char *sec, ini_cache *ini);
extern bool ini_search_string(const char *key, char **buf, const char *path);
extern bool inicache_search_string(const char *key, char **buf, ini_cache *ini);
extern ini_cache iniparser_create_cache(const char *ini, bool write_access);
extern void iniparser_destroy_cache(ini_cache *li);
extern int  inicache_read_int(const char *sec, const char *key, ini_cache *ini);
extern int  ini_read_int(const char *sec, const char *key, const char *path);
extern char*utf16_to_utf8(const wchar_t *utf16);
extern char* utf16_to_mbcs(const wchar_t *utf16);
extern wchar_t* mbcs_to_utf16(const char *ansi);
extern char* mbcs_to_utf8(const char *ansi);
extern wchar_t* utf8_to_utf16(const char *utf8);
extern char* utf8_to_mbcs(const char *utf8);

#ifdef __cplusplus
}
#endif

#endif   /* _INI_PARSER_H */
