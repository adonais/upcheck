#include "spinlock.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/wait.h>

#define MD5_BUFFER_SIZE 4096

static volatile int g_locked = 0;

#ifdef LOG_DEBUG
static char logfile_buf[MAX_PATH];

void __cdecl 
logmsg(const char * format, ...)
{
    va_list args;
    char    buffer[MAX_MESSAGE] = {0};
    va_start (args, format);
    if (strlen(logfile_buf) > 0)
    {
        FILE *pFile = NULL;
        int  len = vsnprintf(buffer, MAX_MESSAGE, format, args);
        if (len > 0 && len < MAX_MESSAGE)
        {
            buffer[len] = '\0';
            if ((pFile = fopen(logfile_buf, "a+")) != NULL)
            {
                fwrite(buffer, strlen(buffer), 1, pFile);
                fclose(pFile);
            }
        }
    }
    va_end(args);
}

void
init_logs(void)
{
    char *p = NULL;
    if (*logfile_buf == '\0' && (p = getenv("HOME")) != NULL)
    {
        snprintf(logfile_buf, MAX_PATH, "%s/upcheck.log", p);
    }
}
#endif

static inline size_t
get_file_lenth(const char *path)
{
    struct stat statbuf;
    return (stat(path, &statbuf) == -1 ? (size_t)0 : (size_t)statbuf.st_size);
}

static char** command_to_argv(char *lpcmdline, int* numargs)
{
    int argc;
    char** argv;
    char* s;
    char* d;
    char* cmdline;
    int qcount, bcount;

    if (!numargs || *lpcmdline == 0)
    {
        return NULL;
    }

    /* --- First count the arguments */
    argc = 1;
    s    = lpcmdline;
    /* The first argument, the executable path, follows special rules */
    if (*s == '"')
    {
        /* The executable path ends at the next quote, no matter what */
        s++;
        while (*s)
            if (*s++ == '"') break;
    }
    else
    {
        /* The executable path ends at the next space, no matter what */
        while (*s && *s != ' ' && *s != '\t') s++;
    }
    /* skip to the first argument, if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s)
        argc++;

    /* Analyze the remaining arguments */
    qcount = bcount = 0;
    while (*s)
    {
        if ((*s == ' ' || *s == '\t') && qcount == 0)
        {
            /* skip to the next argument and count it if any */
            while (*s == ' ' || *s == '\t') s++;
            if (*s) argc++;
            bcount = 0;
        }
        else if (*s == '\\')
        {
            /* '\', count them */
            bcount++;
            s++;
        }
        else if (*s == '"')
        {
            /* '"' */
            if ((bcount & 1) == 0) qcount++; /* unescaped '"' */
            s++;
            bcount = 0;
            /* consecutive quotes, see comment in copying code below */
            while (*s == '"') {
                qcount++;
                s++;
            }
            qcount = qcount % 3;
            if (qcount == 2) qcount = 0;
        }
        else
        {
            /* a regular character */
            bcount = 0;
            s++;
        }
    }
    /* Allocate in a single lump, the string array, and the strings that go
     * with it. This way the caller can make a single LocalFree() call to free
     * both, as per MSDN.
     */
    argv = (char **)calloc((argc + 1) * sizeof(char*) + (strlen(lpcmdline) + 1) * sizeof(char), 1);
    if (!argv)
    {
        return NULL;
    }
    cmdline = (char*)(argv + argc + 1);
    strcpy(cmdline, lpcmdline);

    /* --- Then split and copy the arguments */
    argv[0] = d = cmdline;
    argc        = 1;
    /* The first argument, the executable path, follows special rules */
    if (*d == '"')
    {
        /* The executable path ends at the next quote, no matter what */
        s = d + 1;
        while (*s)
        {
            if (*s == '"')
            {
                s++;
                break;
            }
            *d++ = *s++;
        }
    }
    else
    {
        /* The executable path ends at the next space, no matter what */
        while (*d && *d != ' ' && *d != '\t')
            d++;
        s = d;
        if (*s)
            s++;
    }
    /* close the executable path */
    *d++ = 0;
    /* skip to the first argument and initialize it if any */
    while (*s == ' ' || *s == '\t')
        s++;
    if (!*s)
    {
        /* There are no parameters so we are all done */
        argv[argc] = NULL;
        *numargs   = argc;
        return argv;
    }

    /* Split and copy the remaining arguments */
    argv[argc++] = d;
    qcount = bcount = 0;
    while (*s)
    {
        if ((*s == ' ' || *s == '\t') && qcount == 0)
        {
            /* close the argument */
            *d++   = 0;
            bcount = 0;

            /* skip to the next one and initialize it if any */
            do {
                s++;
            } while (*s == ' ' || *s == '\t');
            if (*s)
                argv[argc++] = d;
        }
        else if (*s == '\\')
        {
            *d++ = *s++;
            bcount++;
        }
        else if (*s == '"')
        {
            if ((bcount & 1) == 0) {
                /* Preceded by an even number of '\', this is half that
                 * number of '\', plus a quote which we erase.
                 */
                d -= bcount / 2;
                qcount++;
            }
            else
            {
                /* Preceded by an odd number of '\', this is half that
                 * number of '\' followed by a '"'
                 */
                d    = d - bcount / 2 - 1;
                *d++ = '"';
            }
            s++;
            bcount = 0;
            /* Now count the number of consecutive quotes. Note that qcount
             * already takes into account the opening quote if any, as well as
             * the quote that lead us here.
             */
            while (*s == '"')
            {
                if (++qcount == 3)
                {
                    *d++   = '"';
                    qcount = 0;
                }
                s++;
            }
            if (qcount == 2)
                qcount = 0;
        }
        else
        {
            /* a regular character */
            *d++   = *s++;
            bcount = 0;
        }
    }
    *d         = '\0';
    argv[argc] = NULL;
    *numargs   = argc;
    return argv;
}

void sleep_ms(int milliseconds)
{
    usleep(milliseconds * 1000);
}

void enter_spinlock(void)
{
    size_t spinCount = 0;
    // Wait until the flag is false.
    while (__sync_val_compare_and_swap(&g_locked, 0, 1))
    {
        // Prevent the loop from being too busy.
        if (spinCount < 32)
        {
            sleep_ms(0);
        }
        else
        {
            sleep_ms(1);
        }
        spinCount++;
    }
}

void leave_spinlock(void)
{
    g_locked = 0;
}

char *strcasestr(const char *haystack, const char *needle)
{
   char *pptr  = (char *) needle;   /* Pattern to search for    */
   char *start = (char *) haystack; /* Start with a bowl of hay */
   char *sptr;                      /* Substring pointer        */
   int   slen  = strlen (haystack); /* Total size of haystack   */
   int   plen  = strlen (needle);   /* Length of our needle     */

   /* while string length not shorter than pattern length */
   for (; slen >= plen; start++, slen--)
   {
      /* find start of pattern in string */
      while (toupper (*start) != toupper (*needle))
      {
         start++;
         slen--;
         /* if pattern longer than string */
         if (slen < plen)
         {
            return NULL;
         }
      }

      sptr = start;
      pptr = (char *) needle;
      while (toupper (*sptr) == toupper (*pptr))
      {
         sptr++;
         pptr++;
         /* if end of pattern then pattern was found */
         if ('\0' == *pptr)
         {
            return start;
         }
      }
   }
   return NULL;
}

char *
check_memstr(char *full_data, int full_data_len, const char *substr)
{
    if (full_data == NULL || full_data_len <= 0 || substr == NULL || *substr == '\0')
    {
        return NULL;
    }
    const int sublen = (const int)strlen(substr);
    char *cur = full_data;
    int last_possible = full_data_len - sublen + 1;
    for (int i = 0; i < last_possible; i++)
    {
        if (*cur == *substr)
        {
            // assert(full_data_len - i >= sublen);
            if (memcmp(cur, substr, sublen) == 0)
            {
                // found
                return cur;
            }
        }
        cur++;
    }
    return NULL;
}

int wp_strncat(char *dst, const char *src, size_t number)
{
    if (dst == NULL)
    {
        return EINVAL;
    }
    else if (src == NULL)
    {
        dst[0] = '\0';
        return EINVAL;
    }
    else if (number <= strlen(dst) + strlen(src))
    {
        dst[0] = '\0';
        return ERANGE;
    }
    strcat(dst, src);
    return 0;
}

bool exists_dir(const char *path)
{
    struct stat buffer;
    if (stat(path, &buffer) != 0) {
        // 获取状态失败，通常表示路径不存在
        return false;
    }
    // 检查是否为目录
    return S_ISDIR(buffer.st_mode);
}

bool exists_file(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)));
}

/**
 * @brief 递归创建多级目录（类似 mkdir -p）
 * @param path 需要创建的完整目录路径
 * @param mode 目录权限（通常为 0755）
 * @return int 成功返回 0，失败返回 -1 并设置 errno
 */
int create_dir(const char *path, mode_t mode)
{
    struct stat st;
    char *path_copy = strdup(path); // 复制路径，因为 dirname 会修改传入的字符串
    char *parent_dir;

    if (path_copy == NULL) {
        return -1; // 内存分配失败
    }

    // 1. 检查路径是否已经存在
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            free(path_copy);
            return 0; // 目录已存在，直接返回成功
        } else {
            free(path_copy);
            errno = ENOTDIR; // 路径存在但不是目录
            return -1;
        }
    }

    // 2. 获取父目录路径
    parent_dir = dirname(path_copy);
    if (parent_dir == NULL) {
        free(path_copy);
        return -1;
    }

    // 3. 递归创建父目录（如果父目录不是当前目录 "." 或根目录 "/"）
    if (strcmp(parent_dir, ".") != 0 && strcmp(parent_dir, "/") != 0) {
        if (create_dir(parent_dir, mode) != 0) {
            free(path_copy);
            return -1;
        }
    }

    free(path_copy);

    // 4. 父目录已存在，创建当前目录
    if (mkdir(path, mode) == 0) {
        return 0; // 创建成功
    }

    // 5. 处理创建失败的情况（可能其他进程已经创建了）
    if (errno == EEXIST) {
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            return 0; // 确实是个目录，算成功
        }
        errno = ENOTDIR; // 存在同名文件
    }
    return -1;
}

int create_file(const char *path, mode_t mode)
{
    int n = 0;
    char *p = strrchr(path, '/');
    if (p)
    {
        char buf[BUFF_LEN] = {0};
        n = snprintf(buf, p - path + 1, "%s", path);
        if (n > 0 && n < BUFF_LEN)
        {
            n = create_dir(path, mode);
        }
        else
        {
            n = -1;
        }
    }
    if (!n)
    {
        int fd = open(path, O_CREAT | O_WRONLY, mode);
        if (fd == -1)
        {
            n = -1;
        }
        else
        {
            close(fd);
        }
    }
    return n;
}

size_t
get_first_line(char **lineptr, const char *path)
{
    size_t len = 0;
    FILE * stream = fopen(path, "r");
    if (stream)
    {
        int trash = 0;
        char *buf = NULL;
        while (!feof(stream))
        {
            trash = fgetc(stream);
            if (trash == '\n')
            {
                break;
            }
            ++len;
        }
        fseek(stream, 0, SEEK_SET);
        if (len > 0 && (buf = (char *)malloc(len + 1)) != NULL)
        {
            if ((len = fread(buf, 1, len, stream)) > 0)
            {
                buf[len] = 0;
                *lineptr = buf;
            }
        }
        fclose(stream);
    }
    if (!len)
    {
        *lineptr = strdup("");
    }
    return len;
}

/**
 * @brief 计算文件的MD5值
 * @param filename 要计算MD5的文件路径
 * @param md5_str 存储MD5字符串的缓冲区(至少33字节)
 * @return 成功返回true，失败返回false
 */
bool get_file_md5(const char *filename, char *md5_str)
{
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "The file cannot be opened: %s\n", filename);
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        fprintf(stderr, "无法创建EVP_MD_CTX EVP_MD_CTX\n");
        return false;
    }

    const EVP_MD *md = EVP_md5();
    if (!md) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Unable to obtain the MD5 digest algorithm\n");
        return false;
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Unable to initialize summary calculation\n");
        return false;
    }

    unsigned char buffer[MD5_BUFFER_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, MD5_BUFFER_SIZE, file)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes_read) != 1) {
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            fprintf(stderr, "Summary update failed\n");
            return false;
        }
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "The final calculation of the abstract failed\n");
        return false;
    }

    // 将二进制MD5值转换为十六进制字符串
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(&md5_str[i*2], "%02x", md_value[i]);
    }
    md5_str[md_len*2] = '\0';

    EVP_MD_CTX_free(mdctx);
    fclose(file);

    return true;
}

int delete_file(const char *path)
{
    if (unlink(path) == -1) {
    #if APP_DEBUG
        fprintf(stderr, "Failed to delete the file\n");
    #endif
        return -1;
    }
    return 0;
}

void delete_cookie_file(void)
{
    if (file_info.cookiefile[0] && exists_file(path_undo_quotes(file_info.cookiefile)))
    {
        delete_file(file_info.cookiefile);
    }
}

void close_cookie_handle(bool mdel)
{
    if (file_info.pcook)
    {
        free(file_info.pcook);
        file_info.pcook = NULL;
    }
    if (mdel && exists_file(path_undo_quotes(file_info.cookie_tmp)))
    {
        delete_file(file_info.cookie_tmp);
    }
}

bool duplicate_process_run(void)
{
    DIR *dp;
    struct dirent *entry;
    bool duplicate = false;
    char self_pid[PID_LEN ] = {0};
    char exe_path[PATH_MAX] = {0};
    char self_path[PATH_MAX] = {0};
    char proc_path[PROC_PATH_LEN] = {0};
    dp = opendir("/proc");
    if (dp)
    {
        int i = 0;
        ssize_t len = 0;
        snprintf(self_pid, PID_LEN, "%d", getpid());
        sprintf(proc_path, "/proc/%s/exe", self_pid);
        len = readlink(proc_path, self_path, sizeof(self_path));
        if (len != -1)
        {
            self_path[len] = '\0';
        }
        while ((entry = readdir (dp)) != NULL)
        {
            if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0) || (strcmp(entry->d_name, self_pid) == 0) || (atoll(entry->d_name) <= 0))
            {
                continue;
            }
            snprintf(proc_path, PROC_PATH_LEN, "/proc/%s/exe", entry->d_name);
            len = readlink(proc_path, exe_path, sizeof(exe_path));
            if (len == -1)
            {
                continue;
            }
            exe_path[len] = '\0';
            if (strcmp(exe_path, self_path) == 0)
            {
                duplicate = true;
            }
        }
        closedir(dp);
    }
    return duplicate;
}

bool
enviroment_variables_set(const char *szname, const char *sz_newval, sys_flag dw_flag)
{
    int dw_err = -1;
    if (dw_flag == VARIABLES_APPEND)  /* 附加到指定环境变量末尾 */
    {
        char *sz_val = NULL;
        /* 获取指定环境变量的值 */
        char *dw_result = getenv(szname);
        if (dw_result == NULL) /* 不存在环境变量 */
        {
            dw_err = setenv(szname, sz_newval, 0);
        }
        else if ((sz_val = (char *)calloc(strlen(dw_result) + strlen(sz_newval) + 8, 1)) != NULL)
        {
            size_t new_valsize = strlen(dw_result) + strlen(sz_newval) + 8;
            dw_err = snprintf(sz_val, new_valsize, "%s:%s", dw_result, sz_newval);
            if (dw_err > 0 && dw_err < new_valsize)
            {
                dw_err = setenv(szname, sz_val, 1);
            }
            else
            {
                dw_err = -1;
            }
            free(sz_val);
        }
    }
    else if (dw_flag == VARIABLES_RESET)
    {   /* 设置新的环境变量 */
        dw_err = setenv(szname, sz_newval, 1);
    }
    else if (dw_flag == VARIABLES_NULL)
    {   /* 指定环境变量清零 */
        dw_err = unsetenv(szname);
    }
    return dw_err == 0;
}

char *
get_process_path(char *path, size_t len)
{
    int n = readlink("/proc/self/exe", path, len);
    if (n > 0 && n < len)
    {
        path[n] = '\0';
        if (strrchr(path, '/'))
        {
            strrchr(path, '/')[0] =  '\0';
        }
    }
    else
    {
        path[0] = '.';
        if (len > 1)
        {
            path[1] = '\0';
        }
    }
    return path;
}

char*
url_decode(const char *input)
{
    char *working, *output;
    size_t output_length = (int)strlen(input) + NAMES_LEN;
    if ((working = output = calloc(1, output_length)) == NULL)
    {
        return NULL;
    }
    while(*input)
    {
        if(*input == '%')
        {
            char buffer[3] = {input[1], input[2], 0};
            *working = (char)strtol(buffer, NULL, 16);
            working++;
            input += 3;
        }
        else
        {
            *working++ = *input++;
        }
    }
    return output;
}

char *
init_file_strings(const char *names, size_t *psize)
{
    bool ret = false;
    char *path = NULL;
    do
    {
        if ((path = (char *)calloc(BUFF_LEN, 1)) == NULL)
        {
            break;
        }
        get_process_path(path, BUFF_LEN);
        wp_strncat(path, "/", BUFF_LEN);
        wp_strncat(path, names, BUFF_LEN);
        if (!exists_file(path))
        {
            break;
        }
        if (psize)
        {
            *psize = get_file_lenth(path);
        }
        ret = true;
    } while (0);
    if (!ret)
    {
        free(path);
        path = NULL;
    }
    return path;
}

bool
strip_file_spec(char *path)
{
    char *p = strrchr(path, '/');
    if (p)
    {
        p[0] =  '\0';
    }
    return p != NULL;
}

bool
init_portable_path(void)
{
    char *p = getenv("UPCHECK_MOZ_CHROME");
    if (p)
    {
        int n = snprintf(file_info.ini, MAX_PATH, "%s", p);
        if (n > 0 && n < MAX_PATH && strip_file_spec(file_info.ini))
        {
            wp_strncat(file_info.ini, "/portable.ini", MAX_PATH);
            return exists_file(file_info.ini);
        }
    }
    return false;
}

char *path_clone(char **path)
{
    if (path && path[0])
    {
        char *res = NULL;
        char *dup = *path;
        if ((res = (char *)calloc(BUFF_LEN, 1)) != NULL)
        {
            snprintf(res, BUFF_LEN, "%s", *path);
        }
        *path = res;
        free(dup);
        return *path;
    }
    return NULL;
}

char *path_utf8_clone(const char *path)
{
    char *res = NULL;
    if (path && (res = (char *)calloc(BUFF_LEN, 1)) != NULL)
    {
        snprintf(res, BUFF_LEN, "%s", path);
    }
    return res;
}

bool
which_path_exist(const char *name, char *pout, size_t out_len)
{
    int  len = 0;
    int  blen = 0;
    bool diff = false;
    bool quote = false;
    bool add_suf = true;
    char *tok = NULL;
    char *psave = NULL;
    char *env_path = NULL;
    char sz_work[BUFF_LEN] = {0};
    char eu_module_path[BUFF_LEN] = {0};
    const char *delimiter = ":";
    const char *path = (const char *)getenv("PATH");
    const char *uchrome = (const char *)getenv("UPCHECK_MOZ_CHROME");
    if (!pout || !path || !getcwd(sz_work, BUFF_LEN))
    {
        return false;
    }
    if (!get_process_path(eu_module_path, BUFF_LEN))
    {
        return false;
    }
    if (!sz_work[0] || !eu_module_path[0])
    {
        return false;
    }
    if (*pout == '/')
    {
        return exists_file(pout);
    }
    if (uchrome)
    {
        if (*uchrome == '"')
        {
            quote = true;
        }
        len = snprintf(pout, out_len, "%s", quote ? &uchrome[1] : uchrome);
        if (len > 0 && len < out_len)
        {
            if (quote)
            {
                pout[strlen(pout) - 1] = 0;
            }
            wp_strncat(pout, "/libaria2/bin/", out_len);
            wp_strncat(pout, name, out_len);
            if (exists_file(pout))
            {
                return true;
            }
        }
    }
    if (true)
    {
        len = (int)(strlen(path)) + (3 * BUFF_LEN);
        diff = strcmp(sz_work, eu_module_path) != 0;
    }
    if ((env_path = (char *)calloc(len + 1, 1)) == NULL)
    {
        *pout = 0;
        return false;
    }
    if (diff)
    {
        snprintf(env_path, len, "%s:%s:%s", eu_module_path, sz_work, path);
    }
    else
    {
        snprintf(env_path, len, "%s:%s", eu_module_path, path);
    }
    tok = strtok_r(env_path, delimiter, &psave);
    while (tok != NULL)
    {
        int i = 0;
        struct stat st;
        len = (int)strlen(tok);
        if (len > 0 && tok[len - 1] == '"')
        {
            tok[len - 1] = 0;
            quote = true;
        }
        else
        {
            quote = false;
        }
        snprintf(pout, out_len, "%s/%s", quote ? &tok[1] : tok, name);
        if (stat(pout, &st) != -1)
        {
            free(env_path);
            printf("%s return true, pout = [%s]\n", __FUNCTION__, pout);
            return true;
        }
        tok = strtok_r(NULL, delimiter, &psave);
    }
    free(env_path);
    *pout = 0;
    printf("which_path_exist return false\n");
    return false;
}

char *
path_add_quotes(const char *path)
{
    char *buf = NULL;
    if (path)
    {
        int len = (int)strlen(path) + 6;
        if (*path == '"')
        {
            buf = strdup(path);
        }
        else if ((buf = (char *)calloc(1, len)) != NULL)
        {
            snprintf(buf, len, "\"%s\"", path);
        }
    }
    return buf;
}

char *
path_undo_quotes(char *path)
{
    size_t len = strlen(path);
    if (len >= 2 && (path[0] == '"' || path[0] == '\''))
    {
        memmove(path, path + 1, len - 2);
        path[len - 2] = '\0';
    }
    return path;
}

int
exec_ppv(const char *command, const char *command_list, int flags)
{
    int argn = 0;
    pid_t child_pid = !flags ? fork() : -1;
    char **argv= !flags ? command_to_argv((char *)command_list, &argn) : NULL;
    if (child_pid == -1)
    {
        if (!flags)
        {
            // Error creating the process
            perror("fork");
            return 1;
        }
        return system(command_list);
    }
    if (child_pid == 0)
    {
        // Code executed in the child process
        // Call execvp in the child process to execute "ls" with the specified arguments
        int status_code = execvp(command, (char *const *)argv);
        // This line is reached if execvp encounters an error
        perror("execvp");
        // Print statement after execvp
        printf("If this is printed, this child process encountered an error.\n");
        // Error handling in the child process
        return 1;
    }
    else
    {
        // Old Parent process. The C program will come here
        // Code executed in the parent process
        // Wait for the completion of the child process
        // waitpid(child_pid, NULL, 0);
        printf("The child process has completed its execution.\n");
    }
    if (argv)
    {
        free(argv);
    }
    return 0;
}
