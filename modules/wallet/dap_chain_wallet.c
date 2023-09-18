/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
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

    MODIFICATION HISTORY:

    27-APR-2021 RRL Added password protected wallet support

*/

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef DAP_OS_UNIX
#include <sys/uio.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <io.h>
#endif

#include <pthread.h>

#include "dap_common.h"
#include "dap_cert_file.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_enc_key.h"
#include "crc32c_adler.h"

#define LOG_TAG "dap_chain_wallet"

#ifndef DAP_OS_WINDOWS                                    /* An argument for open()/create() */
static const mode_t s_fileprot =  ( S_IREAD | S_IWRITE) | (S_IREAD >> 3) | (S_IREAD >> 6) ;
#endif
static char s_wallet_ext [] = ".dwallet";

static  pthread_rwlock_t s_wallet_n_pass_lock = PTHREAD_RWLOCK_INITIALIZER; /* Coordinate access to the hash-table */
static  dap_chain_wallet_n_pass_t   *s_wallet_n_pass;                       /* A hash table to keep passwords for wallets */

#define     CRC32C_INIT    0xEDB88320

/*
 *  DESCRIPTION: Add/update a record for wallet into the internaly used table of name/password pair.
 *      Thhose records are supposed to be used for operations with the password-protected wallets.
 *
 *  INPUTS:
 *      a_name:     A name of the wallet
 *      a_name_len: A length of the wallet's name
 *      a_pass:     A password string
 *      a_pass_len: A length of the password string
 *      a_ttl:      A time  to live of the wallet's context, minutes
 *
 *  IMPLICITE OUTPUTS:
 *      s_wallet_n_pass
 *
 *  RETURNS:
 *      0   - Success
 *      <0  -   <errno>
 */

int     dap_chain_wallet_activate   (
                    const   char    *a_name,
                        ssize_t      a_name_len,
                    const   char    *a_pass,
                        ssize_t      a_pass_len,
                        unsigned     a_ttl
                                    )
{
int     l_rc, l_rc2;
dap_chain_wallet_n_pass_t   l_rec = {0}, *l_prec;
dap_chain_wallet_t  *l_wallet;
char *c_wallets_path;

    /* Sanity checks ... */
    if ( a_name_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  (int) a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( a_pass_len > DAP_WALLET$SZ_PASS )
        return  log_it(L_ERROR, "Wallet's password is too long (%d > %d)",  (int) a_pass_len, DAP_WALLET$SZ_PASS), -EINVAL;


    memcpy(l_rec.name, a_name, l_rec.name_len = a_name_len);            /* Prefill local record fields */
    memcpy(l_rec.pass, a_pass, l_rec.pass_len = a_pass_len);

    if ( (l_rc2 = pthread_rwlock_wrlock(&s_wallet_n_pass_lock)) )        /* Lock for WR access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc2), -l_rc2;

    HASH_FIND_STR(s_wallet_n_pass, a_name,  l_prec);                    /* Check for existen record */


    l_rc = 0;

    if ( !l_prec )
    {
        l_prec  = DAP_NEW_Z(dap_chain_wallet_n_pass_t);                 /* Get memory for new record */
        if (!l_prec) {
            log_it(L_CRITICAL, "Memory allocation error");
            return -EINVAL;
        }
        *l_prec = l_rec;                                                /* Fill it by data */
        HASH_ADD_STR(s_wallet_n_pass, name, l_prec);                    /* Add into the hash-table */
    } else {
        if ( !l_prec->pass_len )                                        /* Password field is empty ? */
            memcpy(l_prec->pass, a_pass, l_prec->pass_len = a_pass_len);/* Update password with new one */

        else l_rc = -EBUSY, log_it(L_ERROR, "Wallet has been activated, do deactivation first");
    }


    clock_gettime(CLOCK_REALTIME, &l_prec->exptm);
    l_prec->exptm.tv_sec += (a_ttl * 60);                               /* Compute context expiration time */


    if ( (l_rc2 = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )        /* Release lock */
        log_it(L_ERROR, "Error unlocking Wallet table, errno=%d", l_rc2);


    /*
     * Check password by open/close BMF Wallet file
    */
    if ( !(c_wallets_path = (char *) dap_chain_wallet_get_path(g_config)) ) /* No path to wallets - nothing to do */
    {
        memset(l_prec->pass, 0, l_prec->pass_len), l_prec->pass_len = 0;
        return  log_it(L_ERROR, "Wallet's path has been not configured"), -EINVAL;
    }

    if ( !(l_wallet = dap_chain_wallet_open (a_name, c_wallets_path)) )
    {
        memset(l_prec->pass, 0, l_prec->pass_len), l_prec->pass_len = 0;    /* Say <what> again ?! */
        return  log_it(L_ERROR, "Wallet's password is invalid, say <password> again"), -EAGAIN;
    }

    dap_chain_wallet_close( l_wallet);

    return  l_rc;
}

/*
 *  DESCRIPTION: Lookup and retrieve password for a given wallet. A buffer for a_pass should be enough
 *      to accept password string up to DAP_WALLET$SZ_PASS octets
 *
 *  INPUTS:
 *      a_name:     A name of the wallet
 *      a_name_len: A length of the wallet's name
        a_pass_len: A size of the buffer to accept password
 *
 *  IMPLICITE INPUTS:
 *      s_wallet_n_pass
 *
 *  OUTPUTS:
 *      a_pass:     A password string
 *      a_pass_len: A length of the password string
 *
 *  RETURNS:
 *      0   - Success, <a_pass> and a_pass_len contains actual data
 *      <0  -   <errno>
 */

int     s_dap_chain_wallet_pass   (
                    const   char    *a_name,
                        ssize_t      a_name_len,
                            char    *a_pass,
                        ssize_t     *a_pass_len
                                    )
{
int     l_rc;
dap_chain_wallet_n_pass_t   *l_prec;
struct timespec l_now;

    /* Sanity checks ... */
    if ( a_name_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  (int) a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( *a_pass_len < DAP_WALLET$SZ_PASS )
        return  log_it(L_ERROR, "Wallet's buffer for password is too small (%d < %d)", (int) *a_pass_len, DAP_WALLET$SZ_PASS), -EINVAL;


    clock_gettime(CLOCK_REALTIME, &l_now);


    if ( (l_rc = pthread_rwlock_rdlock(&s_wallet_n_pass_lock)) )        /* Lock for RD access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc), -l_rc;

    HASH_FIND_STR(s_wallet_n_pass, a_name, l_prec);                     /* Check for existen record */


    if (l_prec && (l_now.tv_sec > l_prec->exptm.tv_sec) )               /* Record is expired ? */
    {
                                                                        /* Reset password field */
        memset(l_prec->pass, l_prec->pass_len = 0, sizeof(l_prec->pass));
        l_prec = NULL; //log_it(L_ERROR, "Wallet's credential has been expired, need re-Activation ");
    }
    else if ( l_prec && !l_prec->pass_len )                             /* Is record has been deactivated ? */
        l_prec = NULL; // log_it(L_ERROR, "Wallet's credential has been zeroed, need re-Activation ");
    else if ( l_prec )                                                  /* Store password to given buffer */
        memcpy(a_pass, l_prec->pass, *a_pass_len = l_prec->pass_len);

    if ( (l_rc = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )        /* Release lock */
        log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc);

    return  l_prec ? 0 : -ENOENT;
}



/*
 *  DESCRIPTION: Deactivate a data for the wallet's name & password pair. For existen record just clearing password field.
 *      Use given password to additional verification. We don't remove record from the hash table - only reset to zero the password field !
 *
 *  INPUTS:
 *      a_name:     A name of the wallet
 *      a_name_len: A length of the wallet's name
 *      a_pass:     A password string
 *      a_pass_len: A length of the password string
 *
 *  IMPLICITE OUTPUTS:
 *      s_wallet_n_pass
 *
 *  RETURNS:
 *      0   - Success
 *      <0  -   <errno>
 */
int     dap_chain_wallet_deactivate   (
                    const   char    *a_name,
                        ssize_t      a_name_len,
                    const   char    *a_pass,
                        ssize_t      a_pass_len
                                    )
{
int     l_rc, l_rc2;
dap_chain_wallet_n_pass_t   *l_prec;

    if ( a_name_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  (int) a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( (l_rc = pthread_rwlock_wrlock(&s_wallet_n_pass_lock)) )        /* Lock for WR access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc), -l_rc;

    l_rc = -ENOENT;

    HASH_FIND_STR(s_wallet_n_pass, a_name, l_prec);                     /* Check for existen record */

    if ( l_prec )
    {
        if ( !l_prec->pass_len )                                        /* Password is zero - has been reset probably */
            l_rc = -EBUSY, log_it(L_WARNING, "The Wallet %.*s is not active", (int) a_name_len, a_name);

        else if ( (l_prec->pass_len != a_pass_len)                      /* Check that passwords is equivalent */
             || memcmp(l_prec->pass, a_pass, l_prec->pass_len) )
            l_rc = -EAGAIN, log_it(L_ERROR, "Wallet's password does not match");

        else    l_rc = 0, memset(l_prec->pass, l_prec->pass_len = 0, sizeof(l_prec->pass));
    }

    if ( (l_rc2 = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )       /* Release lock */
        log_it(L_ERROR, "Error unlocking Wallet table, errno=%d", l_rc2);

    return  l_rc;
}

/**
 * @brief check wallet folders and try open wallets
 * @return 0 if all ok
 */
int dap_chain_wallet_init()
{
    char *c_wallets_path = NULL, l_fspec[MAX_PATH] = {0};
    DIR * l_dir = NULL;
    struct dirent * l_dir_entry = NULL;
    dap_chain_wallet_t *l_wallet = NULL;
    size_t l_len = 0;

    if ( !(c_wallets_path = (char *) dap_chain_wallet_get_path(g_config)) ) /* No path to wallets - nothing to do */
        return -1;

    if ( !(l_dir = opendir(c_wallets_path)) ) {                               /* Path is not exist ? Create the dir and exit */
#ifdef _WIN32
        mkdir(c_wallets_path);
#else
        mkdir(c_wallets_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
#endif
        return  0;
    }

    /*
     * Load certificates from existing no-password-protected (!!!) wallets
     */
    while( (l_dir_entry = readdir(l_dir))) {
#ifndef DAP_OS_WINDOWS
        if ( l_dir_entry->d_type !=  DT_REG )                           /* Skip unrelated entries */
            continue;
#endif
        l_len = strlen(l_dir_entry->d_name);                            /* Check for *.dwallet */

        if ( l_len > 8 && !strcmp(l_dir_entry->d_name + l_len - (sizeof(s_wallet_ext) - 1), s_wallet_ext) ) {
            if (snprintf(l_fspec, sizeof(l_fspec) - 1, "%s/%s", c_wallets_path, l_dir_entry->d_name) < 0)
                continue;
            if ( (l_wallet = dap_chain_wallet_open_file(l_fspec, NULL)) )
                dap_chain_wallet_close(l_wallet);
        }
    }

    closedir(l_dir);
    return 0;
}

/**
 * @brief dap_chain_wallet_deinit
 */
void dap_chain_wallet_deinit(void)
{

}

/**
 * @brief dap_chain_wallet_get_path
 * @param[in] a_config Configuration
 * @return wallets path or NULL if error
 */
static char s_wallets_path[MAX_PATH];

const char* dap_chain_wallet_get_path(dap_config_t * a_config)
{
    char *l_cp = NULL;
    if (!a_config)
        a_config = g_config;
    if ( s_wallets_path[0] )                                                /* Is the path to the wallet's store has been defined ? */
        return  s_wallets_path;                                             /* Fine, just return existen value */

                                                                            /* Retrieve Wallet's store path from config */
    if ( !(l_cp = (char *) dap_config_get_item_str(a_config, "resources", "wallets_path")) )
        return  log_it(L_WARNING, "No path to wallet's store has been defined"), l_cp;


    return  strncpy(s_wallets_path, l_cp, sizeof(s_wallets_path) - 1 );     /* Make local copy , return it to caller */
}

/**
 * @brief dap_chain_wallet_create_with_seed
 * @param a_wallet_name
 * @param a_wallets_path
 * @param a_net_id
 * @param a_sig_type
 * @details Creates new wallet
 * @return Wallet, new wallet or NULL if errors
 */
dap_chain_wallet_t * dap_chain_wallet_create_with_seed (
                    const char * a_wallet_name,
                    const char * a_wallets_path,
                    dap_sign_type_t a_sig_type,
                    const void* a_seed,
                    size_t a_seed_size,
                    const char *a_pass
                                        )
{
dap_chain_wallet_t *l_wallet;
dap_chain_wallet_internal_t *l_wallet_internal;

    /* Sanity checks ... */
    if (a_wallet_name && DAP_WALLET$SZ_NAME < strnlen(a_wallet_name, DAP_WALLET$SZ_NAME + 1) )
        return  log_it(L_ERROR, "Wallet's name is too long ( > %d)",  DAP_WALLET$SZ_NAME), NULL;

    if ( a_pass && DAP_WALLET$SZ_PASS < strnlen(a_pass, DAP_WALLET$SZ_PASS + 1) )
        return  log_it(L_ERROR, "Wallet's password is too long ( > %d)", DAP_WALLET$SZ_PASS), NULL;

    if ( !(l_wallet = DAP_NEW_Z(dap_chain_wallet_t)) ) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }

    if ( !(l_wallet->_internal = l_wallet_internal = DAP_NEW_Z(dap_chain_wallet_internal_t)) ) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DELETE(l_wallet);
        return NULL;
    }

    strncpy(l_wallet->name, a_wallet_name, DAP_WALLET$SZ_NAME);
    l_wallet_internal->certs_count = 1;
    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_cert_t *,l_wallet_internal->certs_count * sizeof(dap_cert_t *));
    assert(l_wallet_internal->certs);
    if (!l_wallet_internal->certs) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_chain_wallet_close(l_wallet);
        return NULL;
    }

    snprintf(l_wallet_internal->file_name, sizeof(l_wallet_internal->file_name)  - 1, "%s/%s%s", a_wallets_path, a_wallet_name, s_wallet_ext);

    l_wallet_internal->certs[0] = dap_cert_generate_mem_with_seed(a_wallet_name, dap_sign_type_to_key_type(a_sig_type), a_seed, a_seed_size);

    if ( !dap_chain_wallet_save(l_wallet, a_pass) )
    {
        log_it(L_INFO, "Wallet %s has been created (%s)", a_wallet_name, l_wallet_internal->file_name);
        return l_wallet;
    }

    log_it(L_ERROR,"Can't save the new wallet (%s) to disk, errno=%d", l_wallet_internal->file_name, errno);
    dap_chain_wallet_close(l_wallet);

    return NULL;

}

/**
 * @brief dap_chain_wallet_create
 * @param a_wallet_name
 * @param a_wallets_path
 * @param a_net_id
 * @param a_sig_type
 * @details Creates new wallet
 * @return Wallet, new wallet or NULL if errors
 */
dap_chain_wallet_t * dap_chain_wallet_create(
                const char * a_wallet_name,
                const char * a_wallets_path,
                dap_sign_type_t a_sig_type,
                const char *a_pass
                                    )
{
    return dap_chain_wallet_create_with_seed(a_wallet_name, a_wallets_path, a_sig_type, NULL, 0, a_pass);
}

/**
 * @brief dap_chain_wallet_close
 * @param a_wallet
 */
void dap_chain_wallet_close(dap_chain_wallet_t *a_wallet)
{
dap_chain_wallet_internal_t * l_wallet_internal;

    if(!a_wallet)
        return;

    if ( (l_wallet_internal = a_wallet->_internal) )
    {
        if ( l_wallet_internal->certs )
        {
            for(size_t i = 0; i < l_wallet_internal->certs_count; i++)
                dap_cert_delete( l_wallet_internal->certs[i]);

            DAP_DELETE(l_wallet_internal->certs);
        }

        DAP_DELETE(l_wallet_internal);
    }

    DAP_DELETE(a_wallet);
}

/**
 * @brief dap_chain_wallet_get_addr
 * @param a_wallet
 * @param a_net_id
 * @return
 */
dap_chain_addr_t* dap_chain_wallet_get_addr(dap_chain_wallet_t * a_wallet, dap_chain_net_id_t a_net_id)
{
    if(!a_wallet)
        return NULL;

    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);

    return a_net_id.uint64 ? dap_cert_to_addr (l_wallet_internal->certs[0], a_net_id) : NULL;
}

/**
 * @brief dap_cert_to_addr
 * @param a_cert
 * @param a_net_id
 * @return
 */
dap_chain_addr_t *dap_cert_to_addr(dap_cert_t * a_cert, dap_chain_net_id_t a_net_id)
{
    dap_chain_addr_t *l_addr = DAP_NEW_Z(dap_chain_addr_t);
    if(!l_addr) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    dap_chain_addr_fill_from_key(l_addr, a_cert->enc_key, a_net_id);
    return l_addr;
}

/**
 * @brief dap_chain_wallet_get_pkey
 * @param a_wallet
 * @param a_pkey_idx
 * @return serialized object if success, NULL if not
 */
dap_pkey_t* dap_chain_wallet_get_pkey( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx )
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);

    if( l_wallet_internal->certs_count > a_pkey_idx )
        return dap_cert_to_pkey(l_wallet_internal->certs[a_pkey_idx]);


    log_it( L_WARNING, "No pkey with index %u in the wallet (total size %zu)", a_pkey_idx, l_wallet_internal->certs_count);
    return 0;

}

/**
 * @brief dap_chain_wallet_get_certs_number
 * @param a_wallet
 * @return
 */
size_t dap_chain_wallet_get_certs_number( dap_chain_wallet_t * a_wallet)
{
    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);
    return l_wallet_internal->certs_count;
}



/**
 * @brief dap_chain_wallet_get_key
 * @param a_wallet
 * @param a_pkey_idx
 * @return
 */
dap_enc_key_t *dap_chain_wallet_get_key(dap_chain_wallet_t *a_wallet, uint32_t a_pkey_idx)
{
    if(!a_wallet)
        return NULL;

    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);

    if( l_wallet_internal->certs_count > a_pkey_idx )
        return l_wallet_internal->certs[a_pkey_idx] ? l_wallet_internal->certs[a_pkey_idx]->enc_key : NULL;

    log_it( L_WARNING, "No key with index %u in the wallet (total size %zu)",a_pkey_idx,l_wallet_internal->certs_count);
    return 0;
}

/*
 *  DESCRIPTION: Save memory wallet's context into ta file  protected by given password.
 *
 *  INPUTS:
 *      a_wallet:   Wallet's context structure
 *      a_pass:     A password string to be used to protect wallet's content
 *
 *  OUTPUTS:
 *      NONE
 *
 *  RETURNS:
 *      0       -   SUCCESS
 *      <errno>
 */

int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet, const char *a_pass)
{
DAP_CHAIN_WALLET_INTERNAL_LOCAL (a_wallet);                                 /* Declare l_wallet_internal */
dap_file_handle_t l_fh = INVALID_HANDLE_VALUE;
size_t l_rc = 0;
uint32_t l_len = 0;
char *l_cp, *l_cert_raw, l_buf[32*1024];
dap_enc_key_t *l_enc_key = NULL;
uint32_t l_csum = CRC32C_INIT;
dap_errnum_t l_err = 0;

enum {
    WALLET$K_IOV_HEADER = 0,
    WALLET$K_IOV_BODY,
    WALLET$SZ_IOV_NR
};

if ( !a_wallet )
    return  log_it(L_ERROR, "Wallet is null, can't save it to file!"), -EINVAL;

if ( a_pass )
    if ( !(l_enc_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_GOST_OFB, NULL, 0, a_pass, strlen(a_pass), 0)) )
        return  log_it(L_ERROR, "Error create key context"), -EINVAL;

#ifdef DAP_OS_WINDOWS
    l_fh = CreateFile(l_wallet_internal->file_name, GENERIC_WRITE, /*FILE_SHARE_READ | FILE_SHARE_WRITE */ 0, NULL, CREATE_ALWAYS,
                          /*FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING*/ 0, NULL);
    if (l_fh != INVALID_HANDLE_VALUE) {
        SetEndOfFile(l_fh);
    } else {
        l_err = GetLastError();
#else
    if ( 0 > (l_fh = open(l_wallet_internal->file_name , O_CREAT | O_WRONLY | O_TRUNC, s_fileprot)) ) {
        l_err = errno;
#endif
        return log_it(L_ERROR, "Cant open file %s for writing, errno=%"DAP_FORMAT_ERRNUM,
                      l_wallet_internal->file_name, l_err), -l_err;
    }

    l_cp = a_wallet->name[0] ? a_wallet->name : "DefaultWalletName";

    dap_chain_wallet_file_hdr_t l_file_hdr = {
        .signature  = DAP_CHAIN_WALLETS_FILE_SIGNATURE,
        .version    = a_pass ? DAP_WALLET$K_VER_2 : DAP_WALLET$K_VER_1,
        .type       = a_pass ? DAP_WALLET$K_TYPE_GOST89 : DAP_WALLET$K_TYPE_PLAIN,
        .wallet_len = strnlen(l_cp, DAP_WALLET$SZ_NAME)
    };

    iovec_t l_iov[] = {
        { .iov_base = &l_file_hdr,  .iov_len = sizeof(l_file_hdr) },    /* WALLET$K_IOV_HEADER */
        { .iov_base = l_cp,         .iov_len = l_file_hdr.wallet_len }  /* WALLET$K_IOV_BODY */
    };

    l_rc = dap_writev(l_fh, l_cp, l_iov, WALLET$SZ_IOV_NR, &l_err);     /* Performs writting vectorized buffer */
    if (l_err || (l_len = sizeof(l_file_hdr) + l_file_hdr.wallet_len) != l_rc) {
        log_it(L_ERROR, "Error write Wallet header to file '%s', err %"DAP_FORMAT_ERRNUM, l_wallet_internal->file_name, l_err);
        dap_fileclose(l_fh);
        return -l_err;
    }
                                                                        /* CRC for file header part */
    l_csum = crc32c(l_csum, l_iov[WALLET$K_IOV_HEADER].iov_base, l_iov[WALLET$K_IOV_HEADER].iov_len);
                                                                        /* CRC for file body part */
    l_csum = crc32c(l_csum, l_iov[WALLET$K_IOV_BODY].iov_base, l_iov[WALLET$K_IOV_BODY].iov_len);

    /* Write certs */
    for ( size_t i = 0; i < l_wallet_internal->certs_count ; i++)
    {
                                                                        /* Get ceritificate body */
        if ( !(l_cert_raw  = (char *) dap_cert_mem_save(l_wallet_internal->certs[i], &l_len)) )
        {
            log_it(L_WARNING, "Certificate #%zu cannot be obtained, go next ...", i);
            continue;
        }

        l_csum = crc32c (l_csum, l_cert_raw, l_len);                        /* CRC for every certificate */

        if ( l_enc_key )
        {
            /* Encrypt buffer with cert to local storage,
             * be advised that we don't performs a source buffer aligment preparation according to
             * block nature of the GOST family and other block-cyphers. We expect that this work is performed
             * by the "enc_na" internaly. So , relax mothefackerzzz!
             */
            l_len = l_enc_key->enc_na(l_enc_key, l_cert_raw, l_len, l_buf, sizeof(l_buf) );
        }
        dap_chain_wallet_cert_hdr_t l_wallet_cert_hdr = { .type = DAP_WALLET$K_CERT, .cert_raw_size = l_len };

        /*
         * Gather chunks for I/O
        */
        l_len = 0;                                                          /* Total octets to be writtent to disk */

        l_iov[WALLET$K_IOV_HEADER].iov_base  = &l_wallet_cert_hdr;          /* Cert's record header */
        l_len += l_iov[WALLET$K_IOV_HEADER].iov_len  = sizeof(l_wallet_cert_hdr);

        l_iov[WALLET$K_IOV_BODY].iov_base  = l_enc_key ? l_buf : l_cert_raw;/* Cert itself or buffer with has been encrypted cert */
        l_len += l_iov[WALLET$K_IOV_BODY].iov_len  = l_wallet_cert_hdr.cert_raw_size;

        l_rc = dap_writev(l_fh, l_cp, l_iov, WALLET$SZ_IOV_NR, &l_err);
        DAP_DEL_Z (l_cert_raw);
        if (l_err || l_rc != l_len) {
            log_it(L_ERROR, "Error writing %d octets of cert to file '%s', err %"DAP_FORMAT_ERRNUM,
                   l_len, l_wallet_internal->file_name, l_err);
            dap_fileclose(l_fh);
            return -l_err;
        }
    }

    if ( l_file_hdr.version == DAP_WALLET$K_VER_2 )
    {
        dap_chain_wallet_cert_hdr_t l_wallet_cert_hdr = { .type = DAP_WALLET$K_MAGIC, .cert_raw_size = sizeof(l_csum) };
        l_len = 0;                                                          /* Total octets to be writtent to disk */
        l_iov[WALLET$K_IOV_HEADER].iov_base  = &l_wallet_cert_hdr;
        l_len += l_iov[WALLET$K_IOV_HEADER].iov_len  = sizeof(l_wallet_cert_hdr);

        l_iov[WALLET$K_IOV_BODY].iov_base  = &l_csum;
        l_len += l_iov[WALLET$K_IOV_BODY].iov_len  = sizeof(l_csum);

        l_rc = dap_writev(l_fh, l_cp, l_iov, WALLET$SZ_IOV_NR, &l_err);     /* Perform writting vectorized buffer */
        if (l_err || l_rc != l_len) {                                       /* Check a result of the I/O operation */
            log_it(L_ERROR, "Error writing %d octets of cert to file '%s', err %"DAP_FORMAT_ERRNUM,
                   l_len, l_wallet_internal->file_name, l_err);
        }
    }
    /* Cleanup and exit ... */
    dap_fileclose(l_fh);

    if ( l_enc_key )
        dap_enc_key_delete(l_enc_key);

#ifdef  DAP_SYS_DEBUG                                                       /* @RRL: For debug purpose only!!! */
    {
    dap_chain_wallet_t  *l_wallet;

    if ( (l_wallet = dap_chain_wallet_open_file (l_wallet_internal->file_name, a_pass)) )
        dap_chain_wallet_close(l_wallet);

    }
#endif      /* DAP_SYS_DEBUG */

    return log_it(L_NOTICE, "Wallet '%s' has been saved into the '%s'", a_wallet->name, l_wallet_internal->file_name), l_err;
}



/**
 * @brief dap_chain_wallet_open_file
 * @param a_file_name
 * @return
 */
dap_chain_wallet_t *dap_chain_wallet_open_file (
                    const char *a_file_name,
                    const char *l_pass
                    )
{
dap_chain_wallet_t *l_wallet;
dap_file_handle_t l_fh = INVALID_HANDLE_VALUE;
dap_errnum_t l_err = 0;
int l_certs_count, l_len;
dap_chain_wallet_file_hdr_t l_file_hdr = {0};
dap_chain_wallet_cert_hdr_t l_cert_hdr = {0};
char l_buf[32*1024], l_buf2[32*1024], *l_bufp, l_wallet_name [DAP_WALLET$SZ_NAME] = {0};
dap_enc_key_t *l_enc_key = NULL;
uint32_t    l_csum = CRC32C_INIT, l_csum2 = CRC32C_INIT;

#ifdef DAP_OS_WINDOWS
    DWORD l_rc = 0;
    if ((l_fh = CreateFile(a_file_name, GENERIC_READ, 0, 0,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, 0)) == INVALID_HANDLE_VALUE) {
        l_err = GetLastError();
#else
    ssize_t l_rc = 0;
    if ( 0 > (l_fh = open(a_file_name , O_RDONLY)) ) {                      /* Open file for ReadOnly !!! */
        l_err = errno;
#endif
        return  log_it(L_ERROR,"Cant open file %s for read, error %"DAP_FORMAT_ERRNUM, a_file_name, l_err), NULL;
    }
#ifdef DAP_OS_WINDOWS
    if (ReadFile(l_fh, &l_file_hdr, sizeof(l_file_hdr), &l_rc, 0) == FALSE || l_rc != sizeof(l_file_hdr)) {
        l_err = GetLastError();
#else
    if (sizeof(l_file_hdr) != read(l_fh, &l_file_hdr, sizeof(l_file_hdr))) {/* Get the file header record */
        l_err = errno;
#endif
        return  log_it(L_ERROR, "Error reading Wallet file (%s) header, err %"DAP_FORMAT_ERRNUM, a_file_name, l_err),
                dap_fileclose(l_fh), NULL;
    }
    if ( l_file_hdr.signature != DAP_CHAIN_WALLETS_FILE_SIGNATURE )  {       /* Check signature of the file */
        log_it(L_ERROR, "Wallet (%s) signature mismatch (%"DAP_UINT64_FORMAT_X" != %"DAP_UINT64_FORMAT_X")",
               a_file_name, l_file_hdr.signature, DAP_CHAIN_WALLETS_FILE_SIGNATURE);
        dap_fileclose(l_fh);
        return NULL;
    }

    if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (!l_pass) ) {
        log_it(L_DEBUG, "Wallet (%s) version 2 cannot be processed w/o password", a_file_name);
        dap_fileclose(l_fh);
        return NULL;
    }

    if ( l_file_hdr.wallet_len > DAP_WALLET$SZ_NAME ) {
        log_it(L_ERROR, "Invalid Wallet name (%s) length ( >%d)", a_file_name, DAP_WALLET$SZ_NAME);
        dap_fileclose(l_fh);
        return NULL;
    }

#ifdef DAP_OS_WINDOWS
    if (!ReadFile(l_fh, l_wallet_name, l_file_hdr.wallet_len, &l_rc, 0) || l_rc != l_file_hdr.wallet_len) {
        l_err = GetLastError();
#else
    if (l_file_hdr.wallet_len != read(l_fh, l_wallet_name, l_file_hdr.wallet_len)) { /* Read wallet's name */
        l_err = errno;
#endif
        return log_it(L_ERROR, "Error reading Wallet name, err %"DAP_FORMAT_ERRNUM, l_err),
               dap_fileclose(l_fh), NULL;
    }

    l_csum = crc32c(l_csum, &l_file_hdr, sizeof(l_file_hdr) );           /* Compute check sum of the Wallet file header */
    l_csum = crc32c(l_csum, l_wallet_name,  l_file_hdr.wallet_len);

    log_it(L_DEBUG, "Wallet file: %s, Wallet[Version: %d, type: %d, name: '%.*s']",
           a_file_name, l_file_hdr.version, l_file_hdr.type, l_file_hdr.wallet_len, l_wallet_name);

    /* First run - count certs in file */

#ifdef DAP_OS_WINDOWS
    for ( l_certs_count = 0; ReadFile(l_fh, &l_cert_hdr, sizeof(l_cert_hdr), &l_rc, NULL) && l_rc; ++l_certs_count) {
        if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (l_cert_hdr.type == DAP_WALLET$K_MAGIC) )
            break;
        if (!ReadFile(l_fh, l_buf, l_cert_hdr.cert_raw_size, &l_rc, NULL) || l_rc != l_cert_hdr.cert_raw_size) {
            l_err = GetLastError();
            break;
        }
    }
#else
    for ( l_certs_count = 0; sizeof(l_cert_hdr) == (l_rc = read (l_fh, &l_cert_hdr, sizeof(l_cert_hdr))); l_certs_count++ ) {
        if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (l_cert_hdr.type == DAP_WALLET$K_MAGIC) )
            break;
        if ( (int)l_cert_hdr.cert_raw_size != (l_rc = read(l_fh, l_buf, l_cert_hdr.cert_raw_size)) ) {
            l_err = errno;
            break;
        }
    }
#endif
    if (l_err)
        return log_it(L_ERROR, "Wallet file (%s) I/O error reading certificate body (%d != %zd), error %"DAP_FORMAT_ERRNUM,
                      a_file_name, l_cert_hdr.cert_raw_size, (ssize_t)l_rc, l_err), dap_fileclose(l_fh), NULL;

    if ( !l_certs_count ) {
        log_it(L_ERROR, "No certificate (-s) in the wallet file (%s)", a_file_name);
        dap_fileclose(l_fh);
        return NULL;
    }


    if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && l_pass )             /* Generate encryptor context  */
        if ( !(l_enc_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_GOST_OFB, NULL, 0, l_pass, strlen(l_pass), 0)) ) {
            log_it(L_ERROR, "Error create key context");
            dap_fileclose(l_fh);
            return NULL;
        }


    /* Create local instance of wallet,
     * allocate memory for array to keep loaded certs */
    l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    assert(l_wallet);
    if (!l_wallet) {
        log_it(L_CRITICAL, "Memory allocation error");
        dap_fileclose(l_fh);
        return NULL;
    }

    DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);
    assert(l_wallet_internal);
    if (!l_wallet_internal) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DEL_Z(l_wallet);
        dap_fileclose(l_fh);
        return NULL;
    }

    snprintf(l_wallet->name, DAP_WALLET$SZ_NAME + 1, "%.*s", l_file_hdr.wallet_len, l_wallet_name);
    strncpy(l_wallet_internal->file_name, a_file_name, sizeof(l_wallet_internal->file_name) - 1);

    l_wallet_internal->certs_count = l_certs_count;
    assert(l_wallet_internal->certs_count);
    if (!l_wallet_internal->certs_count) {
        log_it(L_ERROR, "Count is zero in dap_chain_wallet_open_file");
        DAP_DEL_Z(l_wallet);
        dap_fileclose(l_fh);
        return NULL;
    }

    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_cert_t *, l_wallet_internal->certs_count * sizeof(dap_cert_t *));
    assert(l_wallet_internal->certs);
    if (!l_wallet_internal->certs) {
        log_it(L_CRITICAL, "Memory allocation error");
        DAP_DEL_Z(l_wallet);
        dap_fileclose(l_fh);
        return NULL;
    }

#ifdef DAP_OS_WINDOWS
    LARGE_INTEGER l_offset;
    l_offset.QuadPart = sizeof(l_file_hdr) + l_file_hdr.wallet_len;
    if (SetFilePointerEx(l_fh, l_offset, &l_offset, FILE_BEGIN))
#else
    lseek(l_fh,  sizeof(l_file_hdr) + l_file_hdr.wallet_len, SEEK_SET);     /* Set file pointer to first record after cert file header */
#endif

#ifdef DAP_OS_WINDOWS
    for (size_t i = 0; (ReadFile(l_fh, &l_cert_hdr, sizeof(l_cert_hdr), &l_rc, NULL) == TRUE) && l_rc; ++i)
#else
    for ( size_t i = 0; sizeof(l_cert_hdr) == (l_rc = read (l_fh, &l_cert_hdr, sizeof(l_cert_hdr))); i++ )           /* Read Cert/Record header */
#endif
    {
#ifdef DAP_OS_WINDOWS
        if (!ReadFile(l_fh, l_buf, l_cert_hdr.cert_raw_size, &l_rc, NULL) || l_rc != l_cert_hdr.cert_raw_size) {
            l_err = GetLastError();
#else
        if ( (int)l_cert_hdr.cert_raw_size != (l_rc = read(l_fh, l_buf, l_cert_hdr.cert_raw_size)) ) {
            l_err = errno;
#endif
            log_it(L_ERROR, "Error read certificate's body (%d != %zd), error %"DAP_FORMAT_ERRNUM,
                   l_cert_hdr.cert_raw_size, (ssize_t)l_rc, l_err);
            break;
        }

        if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (l_cert_hdr.type == DAP_WALLET$K_MAGIC) ) {
            l_csum2 = *((uint32_t *) &l_buf);                               /* CRC32 must be terminal element in the wallet file */
            break;
        }


        l_bufp = l_buf;

        if ( l_enc_key )
        {
            l_len = l_enc_key->dec_na(l_enc_key, l_buf, l_rc, l_buf2, sizeof(l_buf2) );
            l_bufp = l_buf2;
            l_csum = crc32c(l_csum, l_bufp, l_len);                          /* CRC for every certificate */
        }

        l_wallet_internal->certs[ i ] = dap_cert_mem_load(l_bufp, l_cert_hdr.cert_raw_size);
    }



    /* Cleanup and exit ... */
    dap_fileclose(l_fh);

    if ( l_enc_key )
    {
        l_wallet->flags |= (DAP_WALLET$M_FL_PROTECTED | DAP_WALLET$M_FL_ACTIVE);
        if ( l_csum != l_csum2 )
        {
            log_it(L_ERROR, "Wallet checksum mismatch, %#x <> %#x", l_csum, l_csum2);
            dap_chain_wallet_close( l_wallet);
            l_wallet = NULL;
        }

        dap_enc_key_delete(l_enc_key);
    }

    return  l_wallet;
}





/**
 * @brief dap_chain_wallet_open
 * @param a_wallet_name
 * @param a_wallets_path
 * @return
 */
dap_chain_wallet_t *dap_chain_wallet_open (
                        const char *a_wallet_name,
                        const char *a_wallets_path
                                    )
{
char l_file_name [MAX_PATH] = {0}, l_pass [ DAP_WALLET$SZ_PASS + 3] = {0},
        *l_cp, l_wallet_name[DAP_WALLET$SZ_PASS + 3] = {0};
ssize_t     l_rc, l_pass_len;

    /* Sanity checks */
    if(!a_wallet_name || !a_wallets_path)
        return NULL;

    if ( (l_cp = strstr(a_wallet_name, s_wallet_ext)) )
        strncpy(l_wallet_name, a_wallet_name, l_cp - a_wallet_name);
    else strcpy(l_wallet_name, a_wallet_name);

    snprintf(l_file_name, sizeof(l_file_name) - 1, "%s/%s%s", a_wallets_path, l_wallet_name, s_wallet_ext);


    l_pass_len = DAP_WALLET$SZ_PASS;                                    /* Size of the buffer for password */
                                                                        /* Lookup password in the internal hash-table */
    if ( (l_rc = s_dap_chain_wallet_pass (l_wallet_name, strlen(l_wallet_name), l_pass, &l_pass_len)) )
        l_pass_len = 0;


    return  dap_chain_wallet_open_file(l_file_name, l_pass_len ? l_pass : NULL);
}

/**
 * @brief dap_chain_wallet_get_balance
 * @param a_wallet
 * @param a_net_id
 * @return
 */
uint256_t dap_chain_wallet_get_balance (
            dap_chain_wallet_t *a_wallet,
            dap_chain_net_id_t a_net_id,
            const char *a_token_ticker
                                    )
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    dap_chain_addr_t *l_addr = dap_chain_wallet_get_addr(a_wallet, a_net_id);

    return  (l_net)  ? dap_chain_ledger_calc_balance(l_net->pub.ledger, l_addr, a_token_ticker) : uint256_0;
}

/**
 * @brief cheack wallet to the Bliss sign
 * @param a_wallet
 * @return if sign Bliss - caution message, else ""
 */
const char* dap_chain_wallet_check_bliss_sign(dap_chain_wallet_t *a_wallet) {
    dap_chain_wallet_internal_t *l_wallet_internal = DAP_CHAIN_WALLET_INTERNAL(a_wallet);
    if (l_wallet_internal && SIG_TYPE_BLISS == dap_sign_type_from_key_type(l_wallet_internal->certs[0]->enc_key->type).type) {
        return "The Bliss signature is deprecated. We recommend you to create a new wallet with another available signature and transfer funds there.";
    }
    return "";
}
