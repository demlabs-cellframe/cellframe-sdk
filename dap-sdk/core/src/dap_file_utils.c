/*
 * Authors:
 * Aleksandr Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

 DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#ifdef DAP_BUILD_WITH_ZIP
#include <zip.h>
#endif
#if (OS_TARGET == OS_MACOS)
    #include <stdio.h>
#else
    #include <malloc.h>
#endif
#include <string.h>
#include <sys/stat.h>
#include <stdarg.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#endif

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"

#define LOG_TAG "file_utils"

/**
 * Check the directory path for unsupported symbols
 *
 * @string
 * @return true, if the directory path contains only ASCII symbols
 */
bool dap_valid_ascii_symbols(const char *a_string)
{
    if(!a_string)
        return true;
    for(size_t i = 0; i < strlen(a_string); i++) {
        if((uint8_t) a_string[i] > 0x7f)
            return false;
    }
    return true;
}

/**
 * Check the file for exists
 *
 * @a_file_path filename pathname
 * @return true, if file exists
 */
bool dap_file_test(const char * a_file_path)
{
    if(!a_file_path)
        return false;
#ifdef _WIN32
    int attr = GetFileAttributesA(a_file_path);
    if(attr != -1 && (attr & FILE_ATTRIBUTE_NORMAL))
        return true;
#else
    struct stat st;
    if (!stat(a_file_path, &st)) {
        if (S_ISREG(st.st_mode))
        return true;
    }
#endif
    return false;
}

/**
 * Check the file for exists
 *
 * @a_file_path filename pathname
 * @return true, if file exists
 */
bool dap_file_simple_test(const char * a_file_path)
{
    if(!a_file_path)
        return false;
#ifdef _WIN32
    int attr = GetFileAttributesA(a_file_path);
    if(attr != -1)
        return true;
#else
    struct stat st;
    if (!stat(a_file_path, &st)) {
        if (S_ISREG(st.st_mode))
        return true;
    }
#endif
    return false;
}

/**
 * Check the directory for exists
 *
 * @dir_path directory pathname
 * @return true, if the file is a directory
 */
bool dap_dir_test(const char * a_dir_path)
{
    if(!a_dir_path)
        return false;
#ifdef _WIN32
    int attr = GetFileAttributesA(a_dir_path);
    if(attr != -1 && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return true;
#else
    struct stat st;
    if(!stat(a_dir_path, &st)) {
        if(S_ISDIR(st.st_mode))
            return true;
    }
#endif
    return false;
}


/**
 * @brief dap_mkdir_with_parents Create a new directory with intermediate sub-directories
 * 
 * @param a_dir_path new directory pathname
 * @return int 0, if the directory was created or already exist, else -1
 */

int dap_mkdir_with_parents(const char *a_dir_path)
{
    // validation of a pointer
    if(a_dir_path == NULL || a_dir_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }
    char path[strlen(a_dir_path) + 1];
    memset(path, '\0', strlen(a_dir_path) + 1);
    memcpy(path, a_dir_path, strlen(a_dir_path));
    char *p;
    // skip the root component if it is present, i.e. the "/" in Unix or "C:\" in Windows
#ifdef _WIN32
    if(((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z'))
            && (path[1] == ':') && DAP_IS_DIR_SEPARATOR(path[2])) {
        p = path + 3;
    }
#else
        if (DAP_IS_DIR_SEPARATOR(path[0])) {
            p = path + 1;
        }
#endif
        else
        p = path;

    do {
        while(*p && !DAP_IS_DIR_SEPARATOR(*p))
            p++;

        if(!*p)
            p = NULL;
        else
            *p = '\0';

        if(!dap_dir_test(path)) {
#ifdef _WIN32
            int result = mkdir(path);
#else
            int result = mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO);
                         chmod(path, S_IRWXU | S_IRWXG | S_IRWXO);
#endif
            if(result == -1) {
                errno = ENOTDIR;
                return -1;
            }
        }
        if(p) {
            *p++ = DAP_DIR_SEPARATOR;
            while(*p && DAP_IS_DIR_SEPARATOR(*p))
                p++;
        }
    } while(p);
    return 0;
}

/**
 * dap_path_get_basename:
 * @a_file_name: the name of the file
 *
 * Gets the last component of the filename.
 *
 * If @a_file_name ends with a directory separator it gets the component
 * before the last slash. If @a_file_name consists only of directory
 * separators (and on Windows, possibly a drive letter), a single
 * separator is returned. If @a_file_name is empty, it gets ".".
 *
 * Returns: a newly allocated string containing the last
 *    component of the filename
 */
char* dap_path_get_basename(const char *a_file_name)
{
    ssize_t l_base;
    ssize_t l_last_nonslash;
    const char *l_retval;

    dap_return_val_if_fail(a_file_name != NULL, NULL);

    if(a_file_name[0] == '\0')
        return dap_strdup(".");

    l_last_nonslash = strlen(a_file_name) - 1;

    while(l_last_nonslash >= 0 && DAP_IS_DIR_SEPARATOR(a_file_name[l_last_nonslash]))
        l_last_nonslash--;

    if(l_last_nonslash == -1)
        // string only containing slashes
        return dap_strdup(DAP_DIR_SEPARATOR_S);

#ifdef _WIN32
    if (l_last_nonslash == 1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    // string only containing slashes and a drive
    return dap_strdup (DAP_DIR_SEPARATOR_S);
#endif
    l_base = l_last_nonslash;

    while(l_base >= 0 && !DAP_IS_DIR_SEPARATOR(a_file_name[l_base]))
        l_base--;

#ifdef _WIN32
    if (l_base == -1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    l_base = 1;
#endif

    //size_t l_len = l_last_nonslash - l_base;
    l_retval = a_file_name + l_base + 1;

    return dap_strdup(l_retval);
}

/**
 * dap_path_is_absolute:
 * @a_file_name: a file name
 *
 * Returns true if the given @a_file_name is an absolute file name.
 * Note that this is a somewhat vague concept on Windows.
 *
 * On POSIX systems, an absolute file name is well-defined. It always
 * starts from the single root directory. For example "/usr/local".
 *
 * On Windows, the concepts of current drive and drive-specific
 * current directory introduce vagueness. This function interprets as
 * an absolute file name one that either begins with a directory
 * separator such as "\Users\tml" or begins with the root on a drive,
 * for example "C:\Windows". The first case also includes UNC paths
 * such as "\\myserver\docs\foo". In all cases, either slashes or
 * backslashes are accepted.
 *
 * Returns: true if @a_file_name is absolute
 */
bool dap_path_is_absolute(const char *a_file_name)
{
    dap_return_val_if_fail(a_file_name != NULL, false);

    if(DAP_IS_DIR_SEPARATOR(a_file_name[0]))
        return true;

#ifdef _WIN32
    // Recognize drive letter on native Windows
    if (dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':' && DAP_IS_DIR_SEPARATOR (a_file_name[2]))
    return true;
#endif

    return false;
}

/**
 * dap_path_skip_root:
 * @file_name: (type filename): a file name
 *
 * Returns a pointer into @file_name after the root component,
 * i.e. after the "/" in UNIX or "C:\" under Windows. If @file_name
 * is not an absolute path it returns %NULL.
 *
 * Returns: (type filename) (nullable): a pointer into @file_name after the
 *     root component
 */
const char *dap_path_skip_root (const char *file_name)
{
    dap_return_val_if_fail(file_name != NULL, NULL);

    // Skip \\server\share or //server/share
    if(DAP_IS_DIR_SEPARATOR (file_name[0]) &&
            DAP_IS_DIR_SEPARATOR(file_name[1]) &&
            file_name[2] &&
            !DAP_IS_DIR_SEPARATOR(file_name[2]))
    {
        char *p;
        p = strchr(file_name + 2, DAP_DIR_SEPARATOR);

#ifdef _WIN32
      {
        char *q;
        q = strchr (file_name + 2, '/');
        if (p == NULL || (q != NULL && q < p))
        p = q;
      }
#endif

        if(p && p > file_name + 2 && p[1])
                {
            file_name = p + 1;

            while(file_name[0] && !DAP_IS_DIR_SEPARATOR(file_name[0]))
                file_name++;

            // Possibly skip a backslash after the share name
            if(DAP_IS_DIR_SEPARATOR(file_name[0]))
                file_name++;

            return (char*) file_name;
        }
    }

    // Skip initial slashes
    if(DAP_IS_DIR_SEPARATOR(file_name[0]))
            {
        while(DAP_IS_DIR_SEPARATOR(file_name[0]))
            file_name++;
        return (char*) file_name;
    }

#ifdef _WIN32
  /* Skip X:\ */
  if (dap_ascii_isalpha (file_name[0]) &&
      file_name[1] == ':' &&
      DAP_IS_DIR_SEPARATOR (file_name[2]))
    return (char *)file_name + 3;
#endif

    return NULL;
}


/**
 * dap_path_get_dirname:
 * @a_file_name: the name of the file
 *
 * Gets the directory components of a file name.
 *
 * If the file name has no directory components "." is returned.
 * The returned string should be freed when no longer needed.
 *
 * Returns: the directory components of the file
 */
char* dap_path_get_dirname(const char *a_file_name)
{
    log_it(L_DEBUG,"dap_path_get_dirname(a_file_name=\"%s\")", a_file_name);
    char *l_base;
    size_t l_len;

    dap_return_val_if_fail(a_file_name != NULL, NULL);

    l_base = strrchr(a_file_name, DAP_DIR_SEPARATOR);

#ifdef _WIN32
    {
        char *l_q;
        l_q = strrchr (a_file_name, '/');
        if (l_base == NULL || (l_q != NULL && l_q > l_base))
        l_base = l_q;
    }
#endif

    if(!l_base)
    {
#ifdef _WIN32
        if (dap_ascii_isalpha(a_file_name[0]) && a_file_name[1] == ':')
        {
            char l_drive_colon_dot[4];

            l_drive_colon_dot[0] = a_file_name[0];
            l_drive_colon_dot[1] = ':';
            l_drive_colon_dot[2] = '.';
            l_drive_colon_dot[3] = '\0';

            return dap_strdup (l_drive_colon_dot);
        }
#endif
        log_it(L_DEBUG,"l_base is NULL, return dup of .");
        return dap_strdup(".");
    }

    while(l_base > a_file_name && DAP_IS_DIR_SEPARATOR(*l_base))
        l_base--;

#ifdef _WIN32
    /* base points to the char before the last slash.
     *
     * In case file_name is the root of a drive (X:\) or a child of the
     * root of a drive (X:\foo), include the slash.
     *
     * In case file_name is the root share of an UNC path
     * (\\server\share), add a slash, returning \\server\share\ .
     *
     * In case file_name is a direct child of a share in an UNC path
     * (\\server\share\foo), include the slash after the share name,
     * returning \\server\share\ .
     */
    if (l_base == a_file_name + 1 &&
            dap_ascii_isalpha(a_file_name[0]) &&
            a_file_name[1] == ':')
    l_base++;
    else if (DAP_IS_DIR_SEPARATOR (a_file_name[0]) &&
            DAP_IS_DIR_SEPARATOR (a_file_name[1]) &&
            a_file_name[2] &&
            !DAP_IS_DIR_SEPARATOR (a_file_name[2]) &&
            l_base >= a_file_name + 2)
    {
        const char *l_p = a_file_name + 2;
        while (*l_p && !DAP_IS_DIR_SEPARATOR (*l_p))
        l_p++;
        if (l_p == l_base + 1)
        {
            l_len = (uint32_t) strlen (a_file_name) + 1;
            l_base = DAP_NEW_SIZE (char, l_len + 1);
            strcpy (l_base, a_file_name);
            l_base[l_len-1] = DAP_DIR_SEPARATOR;
            l_base[l_len] = 0;
            return l_base;
        }
        if (DAP_IS_DIR_SEPARATOR (*l_p))
        {
            l_p++;
            while (*l_p && !DAP_IS_DIR_SEPARATOR (*l_p))
            l_p++;
            if (l_p == l_base + 1)
            l_base++;
        }
    }
#endif

    l_len = (uint32_t) 1 + l_base - a_file_name;
    l_base = DAP_NEW_SIZE(char, l_len + 1);
    memcpy(l_base, a_file_name, l_len);
    l_base[l_len] = 0;
    log_it(L_DEBUG,"l_base=%s",l_base);
    return l_base;
}

dap_list_name_directories_t *dap_get_subs(const char *a_path_dir){
    dap_list_name_directories_t *list = NULL;
    dap_list_name_directories_t *element;
#ifdef _WIN32
    size_t m_size = strlen(a_path_dir);
    char *m_path = DAP_NEW_SIZE(char, m_size + 2);
    memcpy(m_path, a_path_dir, m_size);
    m_path[m_size] = '*';
    m_path[m_size + 1] = '\0';
    WIN32_FIND_DATA info_file;
    HANDLE h_find_file = FindFirstFileA(m_path, &info_file);
    while (FindNextFileA(h_find_file, &info_file)){
        if (info_file.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY){
            element = (dap_list_name_directories_t *)malloc(sizeof(dap_list_name_directories_t));
            element->name_directory = dap_strdup(info_file.cFileName);
            LL_APPEND(list, element);
        }
    }
    FindClose(h_find_file);
    DAP_FREE(m_path);
#else
    DIR *dir = opendir(a_path_dir);
    struct dirent *entry = readdir(dir);
    while (entry != NULL){
        if (strcmp(entry->d_name, "..") != 0 && strcmp(entry->d_name, ".") != 0 && entry->d_type == DT_DIR){
            element = (dap_list_name_directories_t *)malloc(sizeof(dap_list_name_directories_t));
            element->name_directory = dap_strdup(entry->d_name);
            LL_APPEND(list, element);
        }
        entry = readdir(dir);
    }
    closedir(dir);
#endif
    return list;
}




/**
 * dap_path_get_ext:
 * @a_file_name: the name of the file
 *
 * Gets the extension components of a file name.
 *
 * Returns: the extension components of the file
 */
const char* dap_path_get_ext(const char *a_filename)
{
    size_t l_len = dap_strlen(a_filename);
    const char *l_p = a_filename + l_len - 1;
    if(l_len < 2)
        return NULL ;

    while(l_p > a_filename)
    {
        if(*l_p == '.') {
            return ++l_p;
        }
        l_p--;
    }
    return NULL ;
}

static bool get_contents_stdio(const char *filename, FILE *f, char **contents, size_t *length)
{
    char buf[4096];
    size_t bytes; /* always <= sizeof(buf) */
    char *str = NULL;
    size_t total_bytes = 0;
    size_t total_allocated = 0;
    char *tmp;
    assert(f != NULL);
    while(!feof(f)) {
        int save_errno;

        bytes = fread(buf, 1, sizeof(buf), f);
        save_errno = errno;

        if(total_bytes > ULONG_MAX - bytes)
            goto file_too_large;

        /* Possibility of overflow eliminated above. */
        while(total_bytes + bytes >= total_allocated) {
            if(str) {
                if(total_allocated > ULONG_MAX / 2)
                    goto file_too_large;
                total_allocated *= 2;
            }
            else {
                total_allocated = MIN(bytes + 1, sizeof(buf));
            }

            tmp = DAP_REALLOC(str, total_allocated);

            if(tmp == NULL)
                goto error;

            str = tmp;
        }

        if(ferror(f))
            goto error;

        assert(str != NULL);
        memcpy(str + total_bytes, buf, bytes);
        total_bytes += bytes;
    }

    fclose(f);

    if(total_allocated == 0)
            {
        str = DAP_NEW_SIZE(char, 1);
        total_bytes = 0;
    }

    str[total_bytes] = '\0';

    if(length)
        *length = total_bytes;

    *contents = str;

    return true;

    file_too_large:
    error:

    DAP_DELETE(str);
    fclose(f);
    return false;
}

#ifndef _WIN32

static bool dap_get_contents_regfile(const char *filename, struct stat *stat_buf, int fd, char **contents,
        size_t *length)
{
    char *buf;
    size_t bytes_read;
    size_t size;
    size_t alloc_size;

    size = stat_buf->st_size;

    alloc_size = size + 1;
    buf = DAP_NEW_SIZE(char, alloc_size);

    if(buf == NULL) {
        goto error;
    }

    bytes_read = 0;
    while(bytes_read < size) {
        size_t rc;

        rc = read(fd, buf + bytes_read, size - bytes_read);

        if(rc < 0) {
            if(errno != EINTR) {
                DAP_DELETE(buf);
                goto error;
            }
        }
        else if(rc == 0)
            break;
        else
            bytes_read += rc;
    }

    buf[bytes_read] = '\0';

    if(length)
        *length = bytes_read;

    *contents = buf;

    close(fd);

    return true;

    error:

    close(fd);

    return false;
}

static bool dap_get_contents_posix(const char *filename, char **contents, size_t *length)
{
    struct stat stat_buf;
    int fd;

    /* O_BINARY useful on Cygwin */
    fd = open(filename, O_RDONLY | O_BINARY);

    if(fd < 0)
        return false;

    /* I don't think this will ever fail, aside from ENOMEM, but. */
    if(fstat(fd, &stat_buf) < 0) {
        close(fd);
        return false;
    }

    if(stat_buf.st_size > 0 && S_ISREG(stat_buf.st_mode)) {
        bool retval = dap_get_contents_regfile(filename,
                &stat_buf,
                fd,
                contents,
                length);
        return retval;
    }
    else {
        FILE *f;
        bool retval;
        f = fdopen(fd, "r");
        if(f == NULL)
            return false;
        retval = get_contents_stdio(filename, f, contents, length);
        return retval;
    }
}

#else  /* _WIN32 */

static bool dap_get_contents_win32(const char *filename, char **contents, size_t *length)
{
    FILE *f;
    bool retval;

    f = fopen(filename, "rb");

    if(f == NULL)
    {
        return false;
    }
    retval = get_contents_stdio (filename, f, contents, length);
    return retval;
}

#endif

/*
 * Reads an entire file into allocated memory, with error checking.
 */
bool dap_file_get_contents(const char *filename, char **contents, size_t *length)
{
    dap_return_val_if_fail(filename != NULL, false);
    dap_return_val_if_fail(contents != NULL, false);

    *contents = NULL;
    if(length)
        *length = 0;

#ifdef _WIN32
  return dap_get_contents_win32 (filename, contents, length);
#else
    return dap_get_contents_posix(filename, contents, length);
#endif
}




static char* dap_build_path_va(const char *separator, const char *first_element, va_list *args, char **str_array)
{
    dap_string_t *result;
    int separator_len = dap_strlen(separator);
    bool is_first = TRUE;
    bool have_leading = FALSE;
    const char *single_element = NULL;
    const char *next_element;
    const char *last_trailing = NULL;
    int i = 0;

    result = dap_string_new(NULL);

    if(str_array)
        next_element = str_array[i++];
    else
        next_element = first_element;

    while(TRUE)
    {
        const char *element;
        const char *start;
        const char *end;

        if(next_element)
        {
            element = next_element;
            if(str_array)
                next_element = str_array[i++];
            else
                next_element = va_arg(*args, char*);
        }
        else
            break;

        // Ignore empty elements
        if(!*element)
            continue;

        start = element;

        if(separator_len)
        {
            while(dap_strncmp(start, separator, separator_len) == 0)
                start += separator_len;
        }

        end = start + dap_strlen(start);

        if(separator_len)
        {
            while(end >= start + separator_len &&
                    dap_strncmp(end - separator_len, separator, separator_len) == 0)
                end -= separator_len;

            last_trailing = end;
            while(last_trailing >= element + separator_len &&
                    dap_strncmp(last_trailing - separator_len, separator, separator_len) == 0)
                last_trailing -= separator_len;

            if(!have_leading)
            {
                // If the leading and trailing separator strings are in the same element and overlap, the result is exactly that element
                if(last_trailing <= start)
                    single_element = element;

                dap_string_append_len(result, element, start - element);
                have_leading = TRUE;
            }
            else
                single_element = NULL;
        }

        if(end == start)
            continue;

        if(!is_first)
            dap_string_append(result, separator);

        dap_string_append_len(result, start, end - start);
        is_first = FALSE;
    }

    if(single_element)
    {
        dap_string_free(result, TRUE);
        return dap_strdup(single_element);
    }
    else
    {
        if(last_trailing)
            dap_string_append(result, last_trailing);

        return dap_string_free(result, FALSE);
    }
}

/**
 * dap_build_pathv:
 * @separator: a string used to separator the elements of the path.
 * @args: (array zero-terminated=1) (element-type filename): %NULL-terminated
 *     array of strings containing the path elements.
 *
 * Behaves exactly like g_build_path(), but takes the path elements
 * as a string array, instead of varargs. This function is mainly
 * meant for language bindings.
 *
 * Returns: (type filename) (transfer full): a newly-allocated string that
 *     must be freed with DAP_DELETE().
 *
 */
char* dap_build_pathv(const char *separator, char **args)
{
    if(!args)
        return NULL;

    return dap_build_path_va(separator, NULL, NULL, args);
}

/**
 * dap_build_path:
 * @separator: (type filename): a string used to separator the elements of the path.
 * @first_element: (type filename): the first element in the path
 * @...: remaining elements in path, terminated by %NULL
 *
 * Creates a path from a series of elements using @separator as the
 * separator between elements. At the boundary between two elements,
 * any trailing occurrences of separator in the first element, or
 * leading occurrences of separator in the second element are removed
 * and exactly one copy of the separator is inserted.
 *
 * Empty elements are ignored.
 *
 * The number of leading copies of the separator on the result is
 * the same as the number of leading copies of the separator on
 * the first non-empty element.
 *
 * The number of trailing copies of the separator on the result is
 * the same as the number of trailing copies of the separator on
 * the last non-empty element. (Determination of the number of
 * trailing copies is done without stripping leading copies, so
 * if the separator is `ABA`, then `ABABA` has 1 trailing copy.)
 *
 * However, if there is only a single non-empty element, and there
 * are no characters in that element not part of the leading or
 * trailing separators, then the result is exactly the original value
 * of that element.
 *
 * Other than for determination of the number of leading and trailing
 * copies of the separator, elements consisting only of copies
 * of the separator are ignored.
 *
 * Returns: (type filename) (transfer full): a newly-allocated string that
 *     must be freed with DAP_DELETE().
 **/
char* dap_build_path(const char *separator, const char *first_element, ...)
{
    char *str;
    va_list args;

    dap_return_val_if_fail(separator != NULL, NULL);

    va_start(args, first_element);
    str = dap_build_path_va(separator, first_element, &args, NULL);
    va_end(args);

    return str;
}

#ifdef _WIN32

static char* dap_build_pathname_va(const char *first_element, va_list *args, char **str_array)
{
    /* Code copied from g_build_pathv(), and modified to use two
     * alternative single-character separators.
     */
    dap_string_t *result;
    bool is_first = TRUE;
    bool have_leading = FALSE;
    const char *single_element = NULL;
    const char *next_element;
    const char *last_trailing = NULL;
    char current_separator = '\\';
    int i = 0;

    result = dap_string_new(NULL);

    if(str_array)
        next_element = str_array[i++];
    else
        next_element = first_element;

    while(TRUE)
    {
        const char *element;
        const char *start;
        const char *end;

        if(next_element)
        {
            element = next_element;
            if(str_array)
                next_element = str_array[i++];
            else
                next_element = va_arg(*args, char*);
        }
        else
            break;

        /* Ignore empty elements */
        if(!*element)
            continue;

        start = element;

        if(TRUE)
        {
            while(start &&
                    (*start == '\\' || *start == '/'))
            {
                current_separator = *start;
                start++;
            }
        }

        end = start + strlen(start);

        if(TRUE)
        {
            while(end >= start + 1 &&
                    (end[-1] == '\\' || end[-1] == '/'))
            {
                current_separator = end[-1];
                end--;
            }

            last_trailing = end;
            while(last_trailing >= element + 1 &&
                    (last_trailing[-1] == '\\' || last_trailing[-1] == '/'))
                last_trailing--;

            if(!have_leading)
            {
                // If the leading and trailing separator strings are in the same element and overlap, the result is exactly that element
                if(last_trailing <= start)
                    single_element = element;

                dap_string_append_len(result, element, start - element);
                have_leading = TRUE;
            }
            else
                single_element = NULL;
        }

        if(end == start)
            continue;

        if(!is_first)
            dap_string_append_len(result, &current_separator, 1);

        dap_string_append_len(result, start, end - start);
        is_first = FALSE;
    }

    if(single_element)
    {
        dap_string_free(result, TRUE);
        return dap_strdup(single_element);
    }
    else
    {
        if(last_trailing)
            dap_string_append(result, last_trailing);

        return dap_string_free(result, FALSE);
    }
}

#endif

static char* dap_build_filename_va(const char *first_argument, va_list *args, char **str_array)
{
    char *str;

#ifndef _WIN32
    str = dap_build_path_va(DAP_DIR_SEPARATOR_S, first_argument, args, str_array);
#else
    str = dap_build_pathname_va(first_argument, args, str_array);
#endif

    return str;
}

/**
 * dap_build_filename:
 * @first_element: (type filename): the first element in the path
 * @...: remaining elements in path, terminated by %NULL
 *
 * Creates a filename from a series of elements using the correct
 * separator for filenames.
 *
 * On Unix, this function behaves identically to `g_build_path
 * (G_DIR_SEPARATOR_S, first_element, ....)`.
 *
 * On Windows, it takes into account that either the backslash
 * (`\` or slash (`/`) can be used as separator in filenames, but
 * otherwise behaves as on UNIX. When file pathname separators need
 * to be inserted, the one that last previously occurred in the
 * parameters (reading from left to right) is used.
 *
 * No attempt is made to force the resulting filename to be an absolute
 * path. If the first element is a relative path, the result will
 * be a relative path.
 *
 * Returns: (type filename) (transfer full): a newly-allocated string that
 *     must be freed with DAP_DELETE().
 **/
char* dap_build_filename(const char *first_element, ...)
{
    char *str;
    va_list args;

    va_start(args, first_element);
    str = dap_build_filename_va(first_element, &args, NULL);
    va_end(args);

    return str;
}

/**
 * dap_canonicalize_filename:
 * @filename: (type filename): the name of the file
 * @relative_to: (type filename) (nullable): the relative directory, or %NULL
 * to use the current working directory
 *
 * Gets the canonical file name from @filename. All triple slashes are turned into
 * single slashes, and all `..` and `.`s resolved against @relative_to.
 *
 * Symlinks are not followed, and the returned path is guaranteed to be absolute.
 *
 * If @filename is an absolute path, @relative_to is ignored. Otherwise,
 * @relative_to will be prepended to @filename to make it absolute. @relative_to
 * must be an absolute path, or %NULL. If @relative_to is %NULL, it'll fallback
 * to g_get_current_dir().
 *
 * This function never fails, and will canonicalize file paths even if they don't
 * exist.
 *
 * No file system I/O is done.
 *
 * Returns: (type filename) (transfer full): a newly allocated string with the
 * canonical file path
 */
char* dap_canonicalize_filename(const char *filename, const char *relative_to)
{
    char *canon, *input, *output, *after_root, *output_start;

    dap_return_val_if_fail(relative_to == NULL || dap_path_is_absolute (relative_to), NULL);

    if(!dap_path_is_absolute(filename)) {
        char *cwd_allocated = NULL;
        const char *cwd;
        if(relative_to != NULL)
            cwd = relative_to;
        else
            cwd = cwd_allocated = dap_get_current_dir();

        canon = dap_build_filename(cwd, filename, NULL);
        DAP_DELETE(cwd_allocated);
    }
    else
    {
        canon = dap_strdup(filename);
    }

    after_root = (char*) dap_path_skip_root(canon);

    if(after_root == NULL)
    {
        // This shouldn't really happen
        DAP_DELETE(canon);
        return dap_build_filename(DAP_DIR_SEPARATOR_S, filename, NULL);
    }

    // Find the first dir separator and use the canonical dir separator.
    for(output = after_root - 1;
            (output >= canon) && DAP_IS_DIR_SEPARATOR(*output);
            output--)
        *output = DAP_DIR_SEPARATOR;

    /* 1 to re-increment after the final decrement above (so that output >= canon),
     * and 1 to skip the first `/`. There might not be a first `/` if
     * the @canon is a Windows `//server/share` style path with no
     * trailing directories. @after_root will be '\0' in that case. */
    output++;
    if(*output == DAP_DIR_SEPARATOR)
        output++;

    /* POSIX allows double slashes at the start to mean something special
     * (as does windows too). So, "//" != "/", but more than two slashes
     * is treated as "/".
     */
    if(after_root - output == 1)
        output++;

    input = after_root;
    output_start = output;
    while(*input)
    {
        /* input points to the next non-separator to be processed. */
        /* output points to the next location to write to. */
        assert(input > canon && DAP_IS_DIR_SEPARATOR(input[-1]));
        assert(output > canon && DAP_IS_DIR_SEPARATOR(output[-1]));
        assert(input >= output);

        /* Ignore repeated dir separators. */
        while(DAP_IS_DIR_SEPARATOR(input[0]))
            input++;

        /* Ignore single dot directory components. */
        if(input[0] == '.' && (input[1] == 0 || DAP_IS_DIR_SEPARATOR(input[1])))
                {
            if(input[1] == 0)
                break;
            input += 2;
        }
        /* Remove double-dot directory components along with the preceding
         * path component. */
        else if(input[0] == '.' && input[1] == '.' &&
                (input[2] == 0 || DAP_IS_DIR_SEPARATOR(input[2])))
                {
            if(output > output_start)
                    {
                do
                {
                    output--;
                }
                while(!DAP_IS_DIR_SEPARATOR(output[-1]) && output > output_start);
            }
            if(input[2] == 0)
                break;
            input += 3;
        }
        /* Copy the input to the output until the next separator,
         * while converting it to canonical separator */
        else
        {
            while(*input && !DAP_IS_DIR_SEPARATOR(*input))
                *output++ = *input++;
            if(input[0] == 0)
                break;
            input++;
            *output++ = DAP_DIR_SEPARATOR;
        }
    }

    /* Remove a potentially trailing dir separator */
    if(output > output_start && DAP_IS_DIR_SEPARATOR(output[-1]))
        output--;

    *output = '\0';

    return canon;
}


#if defined(MAXPATHLEN)
#define DAP_PATH_LENGTH MAXPATHLEN
#elif defined(PATH_MAX)
#define DAP_PATH_LENGTH PATH_MAX
#elif defined(_PC_PATH_MAX)
#define DAP_PATH_LENGTH sysconf(_PC_PATH_MAX)
#else
#define DAP_PATH_LENGTH 2048
#endif

/**
 * dap_get_current_dir:
 *
 * Gets the current directory.
 *
 * The returned string should be freed when no longer needed.
 * The encoding of the returned string is system defined.
 * On Windows, it is always UTF-8.
 *
 * Since GLib 2.40, this function will return the value of the "PWD"
 * environment variable if it is set and it happens to be the same as
 * the current directory.  This can make a difference in the case that
 * the current directory is the target of a symbolic link.
 *
 * Returns: (type filename) (transfer full): the current directory
 */
char* dap_get_current_dir(void)
{
#ifdef _WIN32

  char *dir = NULL;
  wchar_t dummy[2], *wdir;
  DWORD len;

  len = GetCurrentDirectoryW (2, dummy);
  wdir = DAP_NEW_Z_SIZE(wchar_t, len);

  if (GetCurrentDirectoryW (len, wdir) == len - 1)
    dir = dap_utf16_to_utf8 ((unichar2*)wdir, -1, NULL, NULL);

  DAP_DELETE(wdir);

  if (dir == NULL)
    dir = dap_strdup ("\\");

  return dir;

#else
    const char *pwd;
    char *buffer = NULL;
    char *dir = NULL;
    static u_long max_len = 0;
    struct stat pwdbuf, dotbuf;

    pwd = getenv("PWD");
    if(pwd != NULL &&
            stat(".", &dotbuf) == 0 && stat(pwd, &pwdbuf) == 0 &&
            dotbuf.st_dev == pwdbuf.st_dev && dotbuf.st_ino == pwdbuf.st_ino)
        return dap_strdup(pwd);

    if(max_len == 0)
        max_len = (DAP_PATH_LENGTH == -1) ? 2048 : DAP_PATH_LENGTH;

    while(max_len < ULONG_MAX / 2)
    {
        DAP_DELETE(buffer);
        buffer = DAP_NEW_SIZE(char, max_len + 1);
        *buffer = 0;
        dir = getcwd(buffer, max_len);

        if(dir || errno != ERANGE)
            break;

        max_len *= 2;
    }

    if(!dir || !*buffer)
            {
        /* hm, should we g_error() out here?
         * this can happen if e.g. "./" has mode \0000
         */
        buffer[0] = DAP_DIR_SEPARATOR;
        buffer[1] = 0;
    }

    dir = dap_strdup(buffer);
    DAP_DELETE(buffer);

    return dir;

#endif
}

static const char* dap_dir_read_name(DIR *dir)
{
#ifdef _WIN32_MSVS
  char *utf8_name;
  struct _wdirent *wentry;
#else
    struct dirent *entry;
#endif

    dap_return_val_if_fail(dir != NULL, NULL);

#ifdef _WIN32_MSVS
    while(1)
    {
        wentry = _wreaddir(dir->wdirp);
        while(wentry
                && (0 == wcscmp(wentry->d_name, L".") ||
                        0 == wcscmp(wentry->d_name, L"..")))
            wentry = _wreaddir(dir->wdirp);

        if(wentry == NULL)
            return NULL;

        utf8_name = dap_utf16_to_utf8(wentry->d_name, -1, NULL, NULL, NULL);

        if(utf8_name == NULL)
            continue; /* Huh, impossible? Skip it anyway */

        strcpy(dir->utf8_buf, utf8_name);
        DAP_DELETE(utf8_name);

        return dir->utf8_buf;
    }
#else
    entry = readdir(dir);
    while(entry
            && (0 == strcmp(entry->d_name, ".") ||
                    0 == strcmp(entry->d_name, "..")))
        entry = readdir(dir);

    if(entry)
        return entry->d_name;
    else
        return NULL;
#endif
}

/**
 * rm_rf
 *
 * A fairly naive `rm -rf` implementation
 */
void dap_rm_rf(const char *path)
{
    DIR *dir = NULL;
    const char *entry;

    dir = opendir(path);
    if(dir == NULL)
    {
        /* Assume it’s a file. Ignore failure. */
        remove(path);
        return;
    }

    while((entry = dap_dir_read_name(dir)) != NULL)
    {
        char *sub_path = dap_build_filename(path, entry, NULL);
        dap_rm_rf(sub_path);
        DAP_DELETE(sub_path);
    }

    closedir(dir);

    rmdir(path);
}

#ifdef DAP_BUILD_WITH_ZIP
static bool walk_directory(const char *a_startdir, const char *a_inputdir, zip_t *a_zipper)
{
    DIR *l_dir = opendir(a_inputdir);
    if(l_dir == NULL)
    {
        log_it(L_ERROR, "Failed to open input directory ");
        zip_close(a_zipper);
        return false;
    }

    struct dirent *l_dirp;
    while((l_dirp = readdir(l_dir)) != NULL) {
        if(strcmp(l_dirp->d_name, ".") && strcmp(l_dirp->d_name, "..")) {
            char *l_fullname = dap_build_filename(a_inputdir, l_dirp->d_name, NULL);
            if(dap_dir_test(l_fullname)) {

                if(zip_dir_add(a_zipper, l_fullname + dap_strlen(a_startdir) + 1, ZIP_FL_ENC_UTF_8) < 0) {
                    log_it(L_ERROR, "Failed to add directory to zip: %s", zip_strerror(a_zipper));
                    DAP_DELETE(l_fullname);
                    closedir(l_dir);
                    return false;
                }
                walk_directory(a_startdir, l_fullname, a_zipper);
            } else {
                zip_source_t *l_source = zip_source_file(a_zipper, l_fullname, 0, 0);
                if(l_source == NULL) {
                    log_it(L_ERROR, "Failed to add file to zip: %s", zip_strerror(a_zipper));
                    closedir(l_dir);
                    DAP_DELETE(l_fullname);
                    return false;
                }
                if(zip_file_add(a_zipper, l_fullname + dap_strlen(a_startdir) + 1, l_source, ZIP_FL_ENC_UTF_8) < 0) {
                    zip_source_free(l_source);
                    log_it(L_ERROR, "Failed to add file to zip: %s", zip_strerror(a_zipper));
                    DAP_DELETE(l_fullname);
                    closedir(l_dir);
                    return false;
                }
            }
            DAP_DELETE(l_fullname);
        }
    }
    closedir(l_dir);
    return true;
}

/*
 * Pack a directory to zip file
 *
 * @a_inputdir: input dir
 * @a_output_filename: output zip file path
 *
 * Returns: True, if successfully
 */
bool dap_zip_directory(const char *a_inputdir, const char *a_output_filename)
{
    int l_errorp;
    zip_t *l_zipper = zip_open(a_output_filename, ZIP_CREATE | ZIP_EXCL, &l_errorp);
    if(l_zipper == NULL) {
        zip_error_t l_ziperror;
        zip_error_init_with_code(&l_ziperror, l_errorp);
        if(l_errorp == ZIP_ER_EXISTS) {
            if(!remove(a_output_filename))
                return dap_zip_directory(a_inputdir, a_output_filename);
        }
        log_it(L_ERROR, "Failed to open output file %s: %s ", a_output_filename, zip_error_strerror(&l_ziperror));
        return false;
    }

    bool l_ret = walk_directory(a_inputdir, a_inputdir, l_zipper);

    zip_close(l_zipper);
    return l_ret;
}
#endif


// For TAR
/* values used in typeflag field */
#define REGTYPE  '0'            /* regular file */
#define AREGTYPE '\0'           /* regular file */
#define LNKTYPE  '1'            /* link */
#define SYMTYPE  '2'            /* reserved */
#define CHRTYPE  '3'            /* character special */
#define BLKTYPE  '4'            /* block special */
#define DIRTYPE  '5'            /* directory */
#define FIFOTYPE '6'            /* FIFO special */
#define CONTTYPE '7'            /* reserved */

#define BLOCKSIZE 512
/* The checksum field is filled with this while the checksum is computed.  */
#define CHKBLANKS   "        "  /* 8 blanks, no null */

struct tar_header
{ /* byte offset */
    char name[100]; /*   0 */
    char mode[8]; /* 100 */
    char uid[8]; /* 108 */
    char gid[8]; /* 116 */
    char size[12]; /* 124 */
    char mtime[12]; /* 136 */
    char chksum[8]; /* 148 */
    char typeflag; /* 156 */
    char linkname[100]; /* 157 */
    char magic[6]; /* 257 */
    char version[2]; /* 263 */
    char uname[32]; /* 265 */
    char gname[32]; /* 297 */
    char devmajor[8]; /* 329 */
    char devminor[8]; /* 337 */
    char prefix[155]; /* 345 */
/* 500 */
};

union tar_buffer {
    char buffer[BLOCKSIZE];
    struct tar_header header;
};

/*
 * Pack a directory with contents into a TAR archive
 *
 * @a_outfile: output file descriptor
 * @a_fname: file path relative archive start
 * @a_fpath: full dir path
 *
 * Returns: True, if successfully
 */
static bool s_tar_dir_add(int a_outfile, const char *a_fname, const char *a_fpath)
{
    union tar_buffer l_buffer;
    if(!a_outfile)
        return false;
    char *l_filebuf = NULL;
    size_t l_filelen = 0;
    struct stat l_stat_info;
    int remaining = l_filelen; // how much is left to write
    // fill header
    memset(&l_buffer, 0, BLOCKSIZE);
    // Trim a directory name if it's over 100 bytes
    size_t l_fname_len = MIN(dap_strlen(a_fname), sizeof(l_buffer.header.name) - 1);
    strncpy(l_buffer.header.name, a_fname, l_fname_len);
    l_buffer.header.name[l_fname_len] = '/';
    sprintf(l_buffer.header.mode, "0000777");
    sprintf(l_buffer.header.magic, "ustar");
    l_buffer.header.typeflag = DIRTYPE;
    sprintf(l_buffer.header.size, "%o", remaining);
    stat(a_fpath, &l_stat_info);
    sprintf(l_buffer.header.mtime, "%o", (unsigned int) l_stat_info.st_mtime);
    // Checksum calculation
    {
        memcpy(l_buffer.header.chksum, CHKBLANKS, sizeof l_buffer.header.chksum);
        int i, unsigned_sum = 0;
        char *p;
        p = (char*) &l_buffer;
        for(i = sizeof l_buffer; i-- != 0;) {
            unsigned_sum += 0xFF & *p++;
        }
        sprintf(l_buffer.header.chksum, "%6o", unsigned_sum);
    }

    // add header
    write(a_outfile, &l_buffer, BLOCKSIZE);

    return true;
}

/*
 * Pack a file into a TAR archive
 *
 * @a_outfile: output file descriptor
 * @a_fname: file path relative archive start
 * @a_fpath: full file path
 *
 * Returns: True, if successfully
 */
static bool s_tar_file_add(int a_outfile, const char *a_fname, const char *a_fpath)
{
    union tar_buffer l_buffer;
    if(!a_outfile)
        return false;
    char *l_filebuf = NULL;
    size_t l_filelen = 0;
    if(dap_file_get_contents(a_fpath, &l_filebuf, &l_filelen)) {
        struct stat l_stat_info;
        int remaining = l_filelen; // how much is left to write
        // fill header
        memset(&l_buffer, 0, BLOCKSIZE);
        // Trim filename if it's over 100 bytes
        strncpy(l_buffer.header.name, a_fname, MIN(dap_strlen(a_fname), sizeof(l_buffer.header.name) - 1));
        sprintf(l_buffer.header.mode, "0100644");
        sprintf(l_buffer.header.magic, "ustar");
        l_buffer.header.typeflag = REGTYPE;
        sprintf(l_buffer.header.size, "%o", remaining);
        stat(a_fpath, &l_stat_info);
        sprintf(l_buffer.header.mtime, "%o", (unsigned int) l_stat_info.st_mtime);
        // Checksum calculation
        {
            memcpy(l_buffer.header.chksum, CHKBLANKS, sizeof l_buffer.header.chksum);
            int i, unsigned_sum = 0;
            char *p;
            p = (char*) &l_buffer;
            for(i = sizeof l_buffer; i-- != 0;) {
                unsigned_sum += 0xFF & *p++;
            }
            sprintf(l_buffer.header.chksum, "%6o", unsigned_sum);
        }

        // add header
        write(a_outfile, &l_buffer, BLOCKSIZE);
        // add file body
        while(remaining)
        {
            unsigned int bytes = (remaining > BLOCKSIZE) ? BLOCKSIZE : remaining;
            memcpy(&l_buffer, l_filebuf + l_filelen - remaining, bytes);
            write(a_outfile, &l_buffer, bytes);
            remaining -= bytes;
            // the file is already written, but not aligned to the BLOCKSIZE boundary
            if(bytes != BLOCKSIZE && !remaining) {
                memset(&l_buffer, 0, BLOCKSIZE - bytes);
                write(a_outfile, &l_buffer, BLOCKSIZE - bytes);
            }
        }
        DAP_DELETE(l_filebuf);
        return true;
    };
    return false;
}

/*
 * Pack a file or direcrory to TAR file
 *
 * @a_start_path: start path for archive
 * @a_cur_path: current path for archive
 * @a_outfile: output file descriptor
 *
 * Returns: True, if successfully
 */
static bool s_tar_walk_directory(const char *a_start_path, const char *a_cur_path, int a_outfile)
{
    //
    char *l_start_basename = dap_path_get_basename(a_start_path);
    size_t l_start_name_len = dap_strlen(l_start_basename);
    size_t l_start_dir_len = dap_strlen(a_start_path);

    // add root dir
    if(dap_dir_test(a_start_path)) {

        if(!s_tar_dir_add(a_outfile, l_start_basename, a_start_path)) {
            log_it(L_ERROR, "Failed to add directory to tar");
            DAP_DELETE(l_start_basename);
            return false;
        }
    }
    else if(dap_file_test(a_cur_path)) {
        if(!s_tar_file_add(a_outfile, l_start_basename, a_cur_path)) {
            log_it(L_ERROR, "Failed to add file to tar");
            DAP_DELETE(l_start_basename);
            return false;
        }
        // just one file, not a directory, finish walking
        DAP_DELETE(l_start_basename);
        return true;
    }
    DAP_DELETE(l_start_basename);

    // add root content
    DIR *l_dir = opendir(a_cur_path);
    if(l_dir == NULL)
    {
        log_it(L_ERROR, "Failed to open input directory");
        return false;
    }
    struct dirent *l_dirp;
    while((l_dirp = readdir(l_dir)) != NULL) {
        if(strcmp(l_dirp->d_name, ".") && strcmp(l_dirp->d_name, "..")) {
            char *l_fullname = dap_build_filename(a_cur_path, l_dirp->d_name, NULL);
            if(dap_dir_test(l_fullname)) {
                if(!s_tar_dir_add(a_outfile, l_fullname - l_start_name_len + l_start_dir_len + 0, l_fullname)) {
                    log_it(L_ERROR, "Failed to add directory to tar");
                    closedir(l_dir);
                    DAP_DELETE(l_fullname);
                    return false;
                }
                // Pack subdirectory
                s_tar_walk_directory(a_start_path, l_fullname, a_outfile);
            } else {
                if(!s_tar_file_add(a_outfile, l_fullname - l_start_name_len + l_start_dir_len + 0, l_fullname)) {
                    log_it(L_ERROR, "Failed to add file to tar");
                    closedir(l_dir);
                    DAP_DELETE(l_fullname);
                    return false;
                }
            }
            DAP_DELETE(l_fullname);
        }
    }
    closedir(l_dir);
    return true;
}

/*
 * Pack a directory to tar file
 *
 * @a_inputdir: input dir
 * @a_output_filename: output tar file path
 *
 * Returns: True, if successfully
 */
bool dap_tar_directory(const char *a_inputdir, const char *a_output_tar_filename)
{
    int l_outfile = open(a_output_tar_filename, O_CREAT | O_WRONLY | O_BINARY, 0644);
    if(l_outfile < 0) {
        log_it(L_ERROR, "Failed to open output file");
        return false;
    }
    // Pack all files to l_outfile
    bool l_ret = s_tar_walk_directory(a_inputdir, a_inputdir, l_outfile);

    // Write two empty blocks to the end
    union tar_buffer buffer;
    memset(&buffer, 0, BLOCKSIZE);
    write(l_outfile, &buffer, BLOCKSIZE);
    write(l_outfile, &buffer, BLOCKSIZE);
    close(l_outfile);
    return l_ret;
}
