#include <stdio.h>
#include <fcntl.h>
#include <io.h>
#include <shlwapi.h>
#include <windows.h>
#include "spinlock.h"
#include "sqlite3.h"
#include "ini_parser.h"

#define LDOWRD 8
#define LINE_SIZE 2048
#define CHECK_RC(rc, szinfo, err, db)      \
    if (rc != SQLITE_OK)                   \
    {                                      \
        printf("%s error!\n", szinfo);     \
        printf("%s\n", err);               \
        sqlite3_free(err);                 \
        return 0;                          \
    }

static int
back_downloaded(void *psize, int count, char **column, char **names)
{
    *((int64_t  *)psize) = _atoi64(column[0]);
    return 0;
}

static int
etag_callback(void *ptag, int count, char **column, char **names)
{
    strcpy(*(char **)ptag, column[0]);
    return SQLITE_ABORT;
}

bool
get_down_size(int64_t *psize)
{
    int  rc = 0;
    char *msg = NULL;
    const char *m_sql = "select max(szTotal) AS szTotal from download_info;";
    if (NULL == file_info.sql)
    {
        return false;
    }
    rc = sqlite3_exec(file_info.sql, m_sql, back_downloaded, psize, &msg);
    CHECK_RC(rc, "get szTotal error", msg, file_info.sql);
    return true;
}

int
get_ranges(sql_node *node)
{
    int  rc = 0;
    int  num = 0;
    uint32_t szThread;
    int64_t  szBegin;
    int64_t  szEnd;
    int64_t  szDown;
    int      szStatus;
    int  col = 0;
    sqlite3_stmt *pstmt;
    char *msg = NULL;
    const char *tail;
    const char *m_sql = "select szBegin,szEnd,szDown,szThread,szStatus from download_info;";
    if (NULL == file_info.sql)
    {
        return 0;
    }
    rc = sqlite3_prepare_v2(file_info.sql,m_sql,(int)strlen(m_sql),&pstmt,&tail);
    if (rc != SQLITE_OK)
    {
        printf("sqlite3_exec error in get_ranges(): %s\n", msg);
        sqlite3_close(file_info.sql);
        return 0;
    }
    while(sqlite3_step(pstmt) == SQLITE_ROW)
    {
        col = 0;
        szBegin = sqlite3_column_int64(pstmt,col++);
        szEnd = sqlite3_column_int64(pstmt,col++);
        szDown = sqlite3_column_int64(pstmt,col++);
        szThread = (uint32_t)sqlite3_column_int64(pstmt,col++);
        szStatus = sqlite3_column_int(pstmt,col++);

        if (!szStatus)
        {
            node[num].startidx = szBegin;
            node[num].endidx = szEnd;
            node[num].szdown = szDown;
            node[num].thread = szThread;
            num++;
        }
    }
    sqlite3_finalize(pstmt);
    return num;
}

bool
update_status(uint32_t thread, int status)
{
    int  rc = 0;
    char *msg = NULL;
    char m_sql[VALUE_LEN] = {0};
    if (NULL == file_info.sql)
    {
        return false;
    }
    _snprintf(m_sql, VALUE_LEN - 1, "update download_info set szStatus=%d where szThread=%u;" ,status, thread);
    rc = sqlite3_exec(file_info.sql, m_sql, 0, 0, &msg);
    CHECK_RC(rc, "update_status error", msg, file_info.sql);
    return true;
}

bool
update_ranges(uint32_t thread, int64_t begin, int64_t size)
{
    int  rc = 0;
    char *msg = NULL;
    char m_sql[VALUE_LEN] = {0};
    if (NULL == file_info.sql)
    {
        return false;
    }
    rc = sqlite3_exec(file_info.sql, "PRAGMA journal_mode=OFF;", 0, 0, &msg);
    CHECK_RC(rc, "journal_mode=OFF error", msg, file_info.sql);
    _snprintf(m_sql, VALUE_LEN - 1, "update download_info set szDown=%I64d,szTotal=%I64d where szThread=%u;" ,begin, size, thread);
    rc = sqlite3_exec(file_info.sql, m_sql, 0, 0, &msg);
    CHECK_RC(rc, "update ranges error", msg, file_info.sql);
    return true;
}

bool
thread_insert(const char *url, const char *etag, int64_t begin, int64_t end, int64_t down, int64_t total, uint32_t thread, uint32_t pid, int status)
{
    int  rc = 0;
    char *msg = NULL;
    char m_sql[COOKE_LEN] = {0};
    if (NULL == file_info.sql)
    {
        return false;
    }
    _snprintf(m_sql, COOKE_LEN - 1, "insert into download_info(szUrl,szEtag,szBegin,szEnd,szDown,szTotal,szThread,szPid,szStatus) values('%s','%s',%I64d,%I64d,%I64d,%I64d,%u,%u,%d);"
              ,url, etag, begin, end, down, total, thread, pid, status);
    rc = sqlite3_exec(file_info.sql, m_sql, 0, 0, &msg);
    CHECK_RC(rc, "thread_insert error", msg, file_info.sql);
    return true;
}

void
clean_sql_logs(void)
{
    if (file_info.sql != NULL)
    {
        sqlite3_close(file_info.sql);
    }
}

bool
init_sql_logs(const wchar_t *logs)
{
    int   rc = 0;
    char  *msg = NULL;
    const char *sql = "create table download_info(szId INTEGER PRIMARY KEY, szUrl char(2048), szEtag char(64), szBegin BIGINT, szEnd BIGINT, szDown BIGINT,"
                      "szTotal BIGINT, szThread INT UNSIGNED, szPid INT UNSIGNED, szStatus int);";
    char  utf8[MAX_PATH + 2];
    sqlite3 *db = NULL;
    if (!WideCharToMultiByte(CP_UTF8, 0, logs, -1, utf8, sizeof(utf8), NULL, NULL))
    {
        printf("WideCharToMultiByte %S error: %lu\n", logs, GetLastError());
        return false;
    }
    rc = sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE, NULL);
    if (rc == SQLITE_CANTOPEN)
    {
        char m_sql[MAX_PATH] = {0};
        rc = sqlite3_open_v2(utf8, &db, SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
        if (rc != SQLITE_OK)
        {
            printf("sqlite3_open_v2[%s] error: %d\n", utf8, rc);
            return false;
        }
        rc = sqlite3_exec(db, sql, 0, 0, &msg);
        if (rc != SQLITE_OK)
        {
            printf("create table error: %s\n", msg);
            sqlite3_free(msg);
            sqlite3_close(db);
            return false;
        }
    }
    else if (rc != SQLITE_OK)
    {
        printf("sqlite3_open_v2 error: %d\n", rc);
        return false;
    }
    file_info.sql = db;
    return true;
}

bool
get_etag_different(const wchar_t *name)
{
    int  rc = 0;
    bool ret = true;
    char *etag = NULL;
    const char *m_sql = "select szEtag from download_info;";
    if ((NULL != name) && init_sql_logs(name) && ((etag = (char *)calloc(NAMES_LEN, 1)) != NULL))
    {
        rc = sqlite3_exec(file_info.sql, m_sql, etag_callback, &etag, NULL);
        if (*etag && _stricmp(etag, file_info.etag) == 0)
        {
            ret = false;
        }
        free(etag);
    }
    clean_sql_logs();
    return ret;
}
