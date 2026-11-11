#ifndef LIBARCHIVE_STATIC
#define LIBARCHIVE_STATIC
#endif

#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>  // windows 下使用 _mkdir
#include <windows.h>
#else
#define _mkdir(_f) mkdir(_f, 0755)
#define _S_IFDIR S_IFDIR
#endif

#include "spinlock.h"

// 检查路径是否是目录
static int is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return (st.st_mode & _S_IFDIR) != 0;
    }
    return 0;
}

#ifdef _WIN32
// UTF-8 转 GBK（Windows 常用编码）
static int utf8_to_gbk(const char *utf8, char *gbk, size_t gbk_len) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    if (wlen <= 0) return -1;
    wchar_t *wbuf = (wchar_t *)calloc(wlen + 1, sizeof(wchar_t));
    if (!wbuf) return -1;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wbuf, wlen);
    //MessageBoxW(NULL, wbuf, L"info:", MB_OK);
    int glen = WideCharToMultiByte(CP_ACP, 0, wbuf, -1, gbk, (int)gbk_len, NULL, NULL);
    free(wbuf);
    return glen > 0 ? 0 : -1;
}
#endif

// 主解压函数
int extract_tar_xz(const char *filename, const void *buffer, size_t size, const char *dest_dir) {
    struct archive *a = NULL;
    struct archive *ext = NULL;
    struct archive_entry *entry = NULL;
    int r;

    if (!(filename || buffer)) {
        return 1;
    }

    // 1. 创建读取对象，支持xz压缩和tar格式
    a = archive_read_new();
    archive_read_support_filter_xz(a);
    archive_read_support_format_tar(a);

    // 2. 创建写入对象，设置解压选项
    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, 
        ARCHIVE_EXTRACT_TIME | 
        ARCHIVE_EXTRACT_PERM | 
        ARCHIVE_EXTRACT_ACL | 
        ARCHIVE_EXTRACT_FFLAGS);

    // 3. 打开压缩包
    if (filename) {
        if ((r = archive_read_open_filename(a, filename, 10240))) {
            fprintf(stderr, "Failed to open %s: %s\n", filename, archive_error_string(a));
            archive_read_free(a);
            return 1;
        }
    } else if ((r = archive_read_open_memory(a, buffer, size)) != ARCHIVE_OK){
        fprintf(stderr, "Error opening memory archive: %s\n", archive_error_string(a));
        archive_read_free(a);
        return 1;
    }

    // 4. 遍历压缩包中的每一个条目
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        // **核心修正：手动解析路径**
        // 使用 archive_entry_pathname_utf8 获取原始的 UTF-8 路径字符串
        const char *utf8_path = archive_entry_pathname(entry);
        if (!utf8_path) {
            fprintf(stderr, "Failed to get entry path (UTF-8) for an entry.\n");
            continue;
        }
    #ifdef _WIN32
        // 将 UTF-8 路径转换为 GBK 编码（Windows 系统下）
        char gbk_path[1024];
        if (utf8_to_gbk(utf8_path, gbk_path, 1024) != 0) {
            fprintf(stderr, "Encoding conversion failed for %s\n", utf8_path);
            continue;
        }
    #endif
        // 构建完整的输出路径（dest_dir + 转换后的路径）
        char fullpath[PATH_MAX];
    #ifdef _WIN32
        snprintf(fullpath, PATH_MAX - 1, "%s/%s", dest_dir, gbk_path);
    #else
        snprintf(fullpath, PATH_MAX - 1, "%s/%s", dest_dir, utf8_path);
    #endif

        // printf("utf8_path[%s], fullpath[%s]\n", utf8_path, fullpath);
        // 将转换后的完整路径写回 entry
        archive_entry_set_pathname(entry, fullpath);

        // **确保目录存在**
        // 检查 entry 类型，如果是目录则创建
        if (archive_entry_filetype(entry) == AE_IFDIR) {
            // 创建目录（递归）
            if (create_dir(fullpath, 0755) != 0) {
                fprintf(stderr, "Failed to create directory %s\n", fullpath);
                continue;
            }
            // 目录不需要写入数据，直接跳过后续步骤
            archive_write_finish_entry(ext);
            continue;
        }

        // **确保父目录存在（针对文件）**&zwj;
        // 这一步非常重要，防止写入文件时父目录不存在导致错误
        char parent_dir[PATH_MAX];
        strcpy(parent_dir, fullpath);
        char *last_slash = strrchr(parent_dir, '\\');
        if (last_slash) {
            *last_slash = '\0'; // 截取父目录路径
            if (!is_dir(parent_dir)) {
                // 创建父目录
                if (create_dir(parent_dir, 0755) != 0) {
                    fprintf(stderr, "Failed to create parent directory for %s\n", fullpath);
                    continue;
                }
            }
        }

        // **写入文件数据**
        r = archive_write_header(ext, entry);
        if (r != ARCHIVE_OK) {
            fprintf(stderr, "Failed to write header for %s: %s\n", fullpath, archive_error_string(ext));
        } else {
            const void *buff;
            size_t size;
            la_int64_t offset;

            // 循环读取数据块并写入
            while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK) {
                if (archive_write_data_block(ext, buff, size, offset) != ARCHIVE_OK) {
                    fprintf(stderr, "Failed to write data for %s: %s\n", fullpath, archive_error_string(ext));
                    break;
                }
            }
        }
        // 完成当前条目的写入
        archive_write_finish_entry(ext);
    }

    // 5. 关闭资源
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    return 0;
}
