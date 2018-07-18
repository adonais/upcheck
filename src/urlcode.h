#ifndef __URL_CODE__
#define __URL_CODE__

#ifdef __cplusplus
extern "C" {
#endif

extern const char* __stdcall url_encode_t(char* str);
extern const char* __stdcall url_decode_t(char* str);
extern int   __stdcall utf8_to_utf16(const char *filename_utf8, wchar_t *out_utf16, size_t len);

#ifdef __cplusplus
}
#endif

#endif
