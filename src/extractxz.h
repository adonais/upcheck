#ifndef _EXTRACT_XZ__
#define _EXTRACT_XZ__

#ifdef __cplusplus
extern "C" {
#endif

extern int extract_tar_xz(const char *filename, const void *buffer, size_t size, const char *dest_dir);

#ifdef __cplusplus
}
#endif

#endif
