#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// str必须有足够的空间,函数会回写str,并返回str
// 遵循RFC 2396,把空格编码成%20,而不是+
const char*
url_encode_t(char* str)
{
    int i;
    int j = 0;
    char ch;
    char *result = NULL;
    int m_size=0;
    if (str == NULL)
    {
        return NULL;
    }
    m_size=(int)strlen(str);
    if ((result = (char *)malloc(3*m_size)) == NULL)
    {
        return NULL;
    }
    for (i=0; i<m_size; ++i)
    {
        ch = str[i];
        if (((ch>='A') && (ch<='Z')) ||
            ((ch>='a') && (ch<='z')) ||
            ((ch>='0') && (ch<='9')))
        {
            result[j++] = ch;
        }
        else if (ch == '.' || ch == '-' || ch == '_' || ch == '*')
        {
            result[j++] = ch;
        }
        else
        {
            sprintf(result+j, "%%%02X", (unsigned char)ch);
            j += 3;
        }
    }
    result[j] = '\0';
    strcpy(str,result);
    free(result);
    return str;
}

// 注意,函数会回写str,并返回str
const char*
url_decode_t(char* str)
{
    int m_size=0;
    char *result = NULL;
    char *output = NULL;
    char *input = str;
    if (str == NULL)
    {
        return NULL;
    }
    if ((m_size=(int)strlen(str)) < 3)
    {
        return str;
    }
    if ((output = result = (char *)malloc(m_size+1)) == NULL)
    {
        return NULL;
    }
    while(*input)
    {
        if(*input == '%')
        {
            char buffer[3] = { input[1], input[2], 0 };
            *result++ = (char)strtol(buffer, NULL, 16);
            input += 3;
        }
        else
        {
            *result++ = *input++;
        }
    }
    *result = 0;
    strcpy(str,output);
    free(output);
    return str;
}
