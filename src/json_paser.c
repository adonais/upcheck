#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "cjson.h"
#include "spinlock.h"
#include "json_paser.h"

#ifndef MAX_BUFF
#define MAX_BUFF 1024
#endif

#define UBO_EXTEN   "uBlock0@raymondhill.net"
#define UBO_URL     "https://github.com/yxl0756/ublock-origin/releases/latest/download/latest.xpi"
#define UPDATE_URL  "https://github.com/yxl0756/ublock-origin/releases/latest/download/update.json"
#define UBO_URL2    "https://gh-proxy.org/sourceforge/project/libportable/Iceweasel/ublock-origin/latest.xpi"
#define UPDATE_URL2 "https://gh-proxy.org/sourceforge/project/libportable/Iceweasel/ublock-origin/update-gh.json"

#ifdef __GNUC__
#define GCC_VERSION ((__GNUC__ * 10000) + (__GNUC_MINOR__ * 1000) + (__GNUC_PATCHLEVEL__ * 100))
#pragma GCC diagnostic push
#if GCC_VERSION >= 80100
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
#if GCC_VERSION >= 80200
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
#endif

#define SAFE_GET_STRING(_obj, _key, _dst) do { \
    cJSON *_tmp = cJSON_GetObjectItem(_obj, _key); \
    _dst = (_tmp && cJSON_IsString(_tmp)) ? _tmp->valuestring : NULL; \
} while(0)

static bool
cjson_write_file(const char *path, const char *str)
{
    FILE *f = NULL;
    char dist[MAX_BUFF + 1] = {0};
    strncpy(dist, path, MAX_BUFF);
    strip_file_spec(dist);
    if (!exists_dir(dist))
    {
        create_dir(dist, 0755);
    }
    f =  fopen(path, "wb");
    if (!f)
    {
        return false;
    }
    fwrite(str, 1, strlen(str), f);
    fclose(f);
    return true;
}

static cJSON * cjson_read_file(const char *filename)
{
    long len;
    char *data;
    cJSON *json = NULL;
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);
    do
    {
        size_t count = 0;
        data = (char *) malloc(len + 1);
        if (!data)
        {
            break;
        }
        count = fread(data, 1, len, f);
        data[count] = '\0';
        json = cJSON_Parse(data);
        if (!json)
        {
        #ifdef APP_DEBUG
            printf("cJSON_Parse Error: [%s]\n", cJSON_GetErrorPtr());
        #endif
            break;
        }
    } while (0);
    fclose(f);
    if (data)
    {
        free(data);
    }
    return json;
}

static void
write_policies_obj(const cJSON *root, const char *json_file)
{
    char *out = cJSON_Print(root);
    if (out)
    {
        cjson_write_file(json_file, out);
        free(out);
    }
}

static void 
add_element_string(cJSON *setting, const char *pstr, const bool fast)
{
    cJSON *element = NULL;
    if (strcmp(pstr, "update_url") == 0 && (element = cJSON_CreateString(fast ? UPDATE_URL2 : UPDATE_URL)) != NULL)
    {
        cJSON_AddItemToObject(setting, "update_url", element);
    }
}

static void 
add_ubo_string(cJSON *setting, bool *rms, const bool fast)
{
    if (setting)
    {
        cJSON *object = NULL;
        if ((object = cJSON_GetObjectItem(setting, "update_url")) != NULL)
        {
            if (!(cJSON_IsString(object) && strcmp(object->valuestring, fast ? UPDATE_URL2 : UPDATE_URL) == 0))
            {
                cJSON_DeleteItemFromObject(setting, "update_url");
                add_element_string(setting, "update_url", fast);
                if (rms)
                {
                    *rms = true;
                }
            }
        }
        else
        {
            add_element_string(setting, "update_url", fast);
        }
    }
}

static bool
has_update_obj(cJSON *update_obj, const bool fast)
{
    const char *update = NULL;
    SAFE_GET_STRING(update_obj, "update_url", update);
    return (update && strcasecmp(update, fast ? UPDATE_URL2 : UPDATE_URL) == 0);
}

static bool
add_ubo_obj(cJSON *extension, const bool ubo, bool *rms, const bool fast)
{
    bool modified = false;
    cJSON *setting = cJSON_GetObjectItem(extension, UBO_EXTEN);
    bool has_ubo = setting && cJSON_GetArraySize(setting) >= 1 && has_update_obj(setting, fast);
    if (has_ubo)
    {
        if (!ubo)
        {
            cJSON_DeleteItemFromObject(extension, UBO_EXTEN);
            if (rms)
            {
                *rms = true;
            }
            modified = true;
        }
    }
    else if (ubo)
    {
        if (setting)
        {
            add_ubo_string(setting, &modified, fast);
        }
        else if ((setting = cJSON_CreateObject()) != NULL && cJSON_AddItemToObject(extension, UBO_EXTEN, setting))
        {
            add_ubo_string(setting, NULL, fast);
            modified = true;
        }
    }
    else if (setting)
    {
        cJSON_DeleteItemFromObject(extension, UBO_EXTEN);
        if (rms)
        {
            *rms = true;
        }
        modified = true;
    }
    return modified;
}

static void 
add_install_string(cJSON *installer, int array_size, const bool fast)
{
    if (cJSON_IsArray(installer))
    {
        int i = 0;
        bool old_url = false;
        cJSON *url = NULL;
        if (array_size > 0)
        {
            for (; i < array_size; ++i)
            {
                url = cJSON_GetArrayItem(installer, i);
                if (url && cJSON_IsString(url) && strcasecmp(url->valuestring, fast ? UBO_URL : UBO_URL2) == 0)
                {
                    old_url = true;
                    break;
                }
            }
        }
        if ((url = cJSON_CreateString(fast ? UBO_URL2 : UBO_URL)) != NULL)
        {
            if (!old_url)
            {
                cJSON_AddItemToArray(installer, url);
            }
            else
            {
                cJSON_ReplaceItemInArray(installer, i, url);
            }
        }
    }
}

static bool
add_installer_obj(cJSON *extension, const bool ubo, bool *rms, const bool fast)
{
    int i = 0;
    bool has_ubo = false;
    cJSON *url = NULL;
    cJSON *installer = cJSON_GetObjectItem(extension, "Install");
    int array_size = installer ? cJSON_GetArraySize(installer) : 0;
    for (; i < array_size; ++i)
    {
        url = cJSON_GetArrayItem(installer, i);
        if (url && cJSON_IsString(url) && strcasecmp(url->valuestring, fast ? UBO_URL2 : UBO_URL) == 0)
        {
            has_ubo = true;
            break;
        }
    }
    if (has_ubo)
    {
        if (!ubo)
        {
            if (array_size == 1)
            {
                cJSON_DeleteItemFromObject(extension, "Install");
                if (rms)
                {
                    *rms = true;
                }
            }
            else
            {
                cJSON_DeleteItemFromArray(installer, i);
            }
            return true;
        }
    }
    else if (ubo)
    {
        if (installer)
        {
            add_install_string(installer, array_size, fast);
        }
        else if (cJSON_AddArrayToObject(extension, "Install"))
        {
            add_install_string(cJSON_GetObjectItem(extension, "Install"), 0, fast);
        }
        return true;
    }
    return false;
}

static bool
add_extension_obj(cJSON *base, const bool ubo, const char *desc, const bool fast)
{
    bool modified = false;
    cJSON *extension = NULL;
    if (strcmp(desc, "Extensions") == 0)
    {
        if ((extension = cJSON_CreateObject()) != NULL && cJSON_AddItemToObject(base, "Extensions", extension))
        {
            modified = add_installer_obj(extension, ubo, NULL, fast);
        }
    }
    else if (strcmp(desc, "ExtensionSettings") == 0)
    {
        if ((extension = cJSON_CreateObject()) != NULL && cJSON_AddItemToObject(base, "ExtensionSettings", extension))
        {
            modified = add_ubo_obj(extension, ubo, NULL, fast);
        }
    }
    return modified;
}

static bool
add_policies_obj(cJSON *root, const bool ubo, const bool fast)
{
    bool ex_modified = false;
    bool st_modified = false;
    cJSON *policies = cJSON_CreateObject();
    if (policies && cJSON_AddItemToObject(root, "policies", policies))
    {
        ex_modified = add_extension_obj(policies, ubo, "Extensions", fast);
        st_modified = add_extension_obj(policies, ubo, "ExtensionSettings", fast);
    }
    return (ex_modified && st_modified);
}

int fn_ubo(const char *profd, uint32_t flags)
{
    cJSON *base, *root = NULL;
    bool policie_exist = false;
    char json_file[MAX_BUFF] = {0};
    int ubo = (int)(flags & 0x1);
    int fast = (int)(flags & 0x2);
    snprintf(json_file, MAX_BUFF, "%s/distribution/policies/policies.json", profd);
    policie_exist = exists_file(json_file);
    if (!policie_exist)
    {
        if (ubo)
        {
            char str[MAX_BUFF] = {0};
            const char *fmt = "{\n  \"policies\": {\n    \"Extensions\": {\n      \"Install\": [\n        \"""%s""\"\n      ]\n    },\n    \"ExtensionSettings\": {\n      \""UBO_EXTEN"\": {\n        \"update_url\": \"""%s""\"\n      }\n    }\n  }\n}";
            snprintf(str, MAX_BUFF, fmt, fast ? UBO_URL2 : UBO_URL, fast ? UPDATE_URL2 : UPDATE_URL);
            return cjson_write_file(json_file, str);
        }
        return 0;
    }
    while (policie_exist)
    {
        bool modified = false;
        root = cjson_read_file(json_file);
        if (!root)
        {
            policie_exist = false;
            break;
        }
        base = cJSON_GetObjectItem(root, "policies");
        if (base)
        {
            bool self = false;
            cJSON *setting = NULL; 
            cJSON *extension = cJSON_GetObjectItem(base, "Extensions");
            if (extension)
            {
                modified = add_installer_obj(extension, ubo > 0, &self, fast);
                if (self)
                {
                    extension = cJSON_GetObjectItem(base, "Extensions");
                    if (extension->child == NULL)
                    {
                        cJSON_DeleteItemFromObject(base, "Extensions");
                    }
                    modified = true;
                }
            }
            else if (ubo)
            {
                modified = add_extension_obj(base, ubo > 0, "Extensions", fast);
            }
            if ((setting = cJSON_GetObjectItem(base, "ExtensionSettings")) != NULL)
            {
                self = false;
                modified = add_ubo_obj(setting, ubo > 0, &self, fast);
                if (self)
                {
                    setting = cJSON_GetObjectItem(base, "ExtensionSettings");
                    if (setting->child == NULL)
                    {
                        cJSON_DeleteItemFromObject(base, "ExtensionSettings");
                    }
                    modified = true;
                }
            }
            else if (ubo)
            {
                modified = add_extension_obj(base, ubo > 0, "ExtensionSettings", fast);
            }
        }
        else if (ubo)
        {
            modified = add_policies_obj(root, ubo > 0, fast);
        }
        if (modified)
        {
            if (!ubo && (base = cJSON_GetObjectItem(root, "policies")) != NULL && base->child == NULL)
            {
            #ifdef APP_DEBUG
                printf("we delete policies.json\n");
            #endif
                policie_exist = false;
            }
            if (policie_exist)
            {
                write_policies_obj(root, json_file);
            }
        }
        break;
    }
    if (root)
    {
        cJSON_Delete(root);
    }
    if (!policie_exist)
    {
        delete_file(json_file);
    }
    return 0;
}

#ifdef __GNUC__
#pragma GCC diagnostic pop /* -Wstringop-truncation -Wstringop-overflow */
#endif
