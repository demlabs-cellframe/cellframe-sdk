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

#ifdef DAP_OS_UNIX
#include <sys/types.h>
#include <sys/stat.h>
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
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_cert_file.h"
#include "dap_chain_wallet.h"
#include "dap_chain_wallet_internal.h"
#include "dap_enc_key.h"

#define LOG_TAG "dap_chain_wallet"

                                                                            /* An argument for open()/create() */
static const mode_t s_fileprot =  ( S_IREAD | S_IWRITE) | (S_IREAD >> 3) | (S_IREAD >> 6) ;
static char s_wallet_ext [] = ".dwallet";


static  pthread_rwlock_t s_wallet_n_pass_lock = PTHREAD_RWLOCK_INITIALIZER; /* Coordinate access to the hash-table */
static  dap_chain_wallet_n_pass_t   *s_wallet_n_pass;                       /* A hash table to keep passwords for wallets */



/*	CRC32-C	*/
#define     CRC32C_INIT    0xEDB88320

static const  unsigned int s_crc32c_tab[] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

static inline unsigned int	s_crc32c (unsigned int crc, const void *buf, size_t buflen)
{
const unsigned char  *p = (unsigned char *) buf;

	crc = crc ^ ~0U;

	while (buflen--)
		crc = s_crc32c_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

	return crc ^ ~0U;
}


/*
 *  DESCRIPTION: Add/update a record for wallet into the internaly used table of name/password pair.
 *      This records is supposed to be used for operations with the password-protected wallets.
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

int     dap_chain_wallet_activate   (
                    const   char    *a_name,
                        ssize_t      a_name_len,
                    const   char    *a_pass,
                        ssize_t      a_pass_len
                                    )
{
int     l_rc;
dap_chain_wallet_n_pass_t   l_rec = {0}, *l_prec;

    /* Sanity checks ... */
    if ( a_name_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( a_pass_len > DAP_WALLET$SZ_PASS )
        return  log_it(L_ERROR, "Wallet's password is too long (%d > %d)",  a_pass_len, DAP_WALLET$SZ_PASS), -EINVAL;



    memcpy(l_rec.name, a_name, l_rec.name_len = a_name_len);            /* Prefill local record fields */
    memcpy(l_rec.pass, a_pass, l_rec.pass_len = a_pass_len);

    if ( (l_rc = pthread_rwlock_wrlock(&s_wallet_n_pass_lock)) )        /* Lock for WR access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc), -l_rc;

    HASH_FIND_STR(s_wallet_n_pass, a_name,  l_prec);                    /* Check for existen record */

    if ( !l_prec )
    {
        l_prec  = DAP_NEW_Z(dap_chain_wallet_n_pass_t);                 /* Get memory for new record */
        *l_prec = l_rec;                                                /* Fill it by data */
        HASH_ADD_STR(s_wallet_n_pass, name, l_prec);                    /* Add into the hash-table */
    }
    else {
        memcpy(l_prec->pass, a_pass, l_prec->pass_len = a_pass_len);    /* Update password with new one */
    }

    if ( (l_rc = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )        /* Release lock */
        log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc);


    return  0;
}

/*
 *  DESCRIPTIOB: Lookup and retrieve password for a given wallet. A buffer for a_pass should be enough
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

    /* Sanity checks ... */
    if ( a_name_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( *a_pass_len < DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Wallet's buffer for password is too small (%d < %d)",  *a_pass_len, DAP_WALLET$SZ_PASS), -EINVAL;



    if ( (l_rc = pthread_rwlock_rdlock(&s_wallet_n_pass_lock)) )        /* Lock for RD access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc), -l_rc;

    HASH_FIND_STR(s_wallet_n_pass, a_name, l_prec);                     /* Check for existen record */

    if ( l_prec && !l_prec->pass_len )                                  /* Is record has been deactivated ? */
        l_prec = NULL;
    else if ( l_prec )                                                  /* Store password to given buffer */
        memcpy(a_pass, l_prec->pass, *a_pass_len = l_prec->pass_len);

    if ( (l_rc = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )        /* Release lock */
        log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc);

    return  l_prec ? 0 : -ENOENT;
}



/*
 *  DESCRIPTION: Deactivate a data for the wallet's name & password pair. For existen record just clearing password field.
 *      Use given password to additional verification.
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
        return  log_it(L_ERROR, "Wallet's name is too long (%d > %d)",  a_name_len, DAP_WALLET$SZ_NAME), -EINVAL;

    if ( (l_rc = pthread_rwlock_wrlock(&s_wallet_n_pass_lock)) )        /* Lock for WR access */
        return  log_it(L_ERROR, "Error locking Wallet table, errno=%d", l_rc), -l_rc;

    l_rc = -ENOENT;

    HASH_FIND_STR(s_wallet_n_pass, a_name, l_prec);                     /* Check for existen record */

    if ( l_prec )
    {
                                                                        /* Check that passwords is equivalent */
        if ( (l_prec->pass_len != a_pass_len)
             || memcmp(l_prec->pass, a_pass, l_prec->pass_len) )
            l_rc = -EINVAL, l_prec = NULL;
        else    l_rc = 0, memset(l_prec->pass, l_prec->pass_len = 0, sizeof(l_prec->pass));
    }

    if ( (l_rc2 = pthread_rwlock_unlock(&s_wallet_n_pass_lock)) )       /* Release lock */
        log_it(L_ERROR, "Error unlocking Wallet table, errno=%d", l_rc2);

    return  l_rc;
}










/**
 * @brief dap_chain_wallet_init
 * @return
 */
int dap_chain_wallet_init(void)
{
char *c_wallets_path, l_fspec[MAX_PATH] = {0};
DIR * l_dir;
struct dirent * l_dir_entry;
dap_chain_wallet_t *l_wallet;
size_t l_len;

    if ( !(c_wallets_path = (char *) dap_chain_wallet_get_path(g_config)) ) /* No path to wallets - nothing to do */
        return 0;

    if ( !(l_dir = opendir(c_wallets_path)) )                               /* Path is not exist ? Create the dir and exit */
    {
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
    while( (l_dir_entry = readdir(l_dir)))
    {
        if ( l_dir_entry->d_type !=  DT_REG )                           /* Skip unrelated entries */
            continue;

        l_len = strlen(l_dir_entry->d_name);                            /* Check for *.dwallet */

        if ( (l_len > 8) && (strcmp(l_dir_entry->d_name + l_len - (sizeof(s_wallet_ext) - 1), s_wallet_ext) == 0) )
        {
            dap_snprintf(l_fspec, sizeof(l_fspec) - 1, "%s/%s", c_wallets_path, l_dir_entry->d_name);

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
char *l_cp;

    if ( s_wallets_path[0] )                                                /* Is the path to the wallet's store has been defined ? */
        return  s_wallets_path;                                             /* Fine, just return existen value */

                                                                            /* Retrieve Wallet's store path from config */
    if ( !(l_cp = (char *) dap_config_get_item_str(g_config, "resources", "wallets_path")) )
        return  log_it(L_WARNING, "No path to wallet's store has been defined"), s_wallets_path;


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

    l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    assert(l_wallet);

    l_wallet->_internal = l_wallet_internal = DAP_NEW_Z(dap_chain_wallet_internal_t);
    assert(l_wallet->_internal);

    strcpy(l_wallet->name, a_wallet_name);
    l_wallet_internal->certs_count = 1;
    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_cert_t *,l_wallet_internal->certs_count * sizeof(dap_cert_t *));
    assert(l_wallet->_internal);

    size_t l_file_name_size = strlen(a_wallet_name)+strlen(a_wallets_path)+13;
    l_wallet_internal->file_name = DAP_NEW_Z_SIZE (char, l_file_name_size);

    dap_snprintf(l_wallet_internal->file_name, l_file_name_size, "%s/%s%s", a_wallets_path, a_wallet_name, s_wallet_ext);

    l_wallet_internal->certs[0] = dap_cert_generate_mem_with_seed(a_wallet_name, dap_sign_type_to_key_type(a_sig_type), a_seed, a_seed_size);

    if ( !dap_chain_wallet_save(l_wallet, a_pass)  )
    {
        log_it(L_INFO, "%sWallet <%s> has been created (%s)", a_pass ? "Password protected" : "",
               a_pass, l_wallet_internal->file_name);
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
void dap_chain_wallet_close( dap_chain_wallet_t * a_wallet)
{
    if(!a_wallet)
        return;

    DAP_CHAIN_WALLET_INTERNAL_LOCAL(a_wallet);

    // TODO Make clean struct dap_chain_wallet_internal_t (certs, addr)
    if(l_wallet_internal)
    {
        if(l_wallet_internal->addr)
            DAP_DELETE(l_wallet_internal->addr);

        if(l_wallet_internal->file_name)
            DAP_DELETE(l_wallet_internal->file_name);

        if ( l_wallet_internal->certs )
            for(size_t i = 0; i < l_wallet_internal->certs_count; i++)
                dap_cert_delete( l_wallet_internal->certs[i]);

        DAP_DELETE(l_wallet_internal->certs);

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
dap_chain_addr_t * dap_cert_to_addr(dap_cert_t * a_cert, dap_chain_net_id_t a_net_id)
{
    dap_chain_addr_t * l_addr = DAP_NEW_Z(dap_chain_addr_t);
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
dap_enc_key_t* dap_chain_wallet_get_key( dap_chain_wallet_t * a_wallet,uint32_t a_pkey_idx )
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
 *  DESCRIPTION:
 *
 *  INPUTS:
 *
 *  OUTPUTS:
 *
 *  RETURNS:
 */

int dap_chain_wallet_save(dap_chain_wallet_t * a_wallet, const char *a_pass)
{
DAP_CHAIN_WALLET_INTERNAL_LOCAL (a_wallet);                                 /* Declare l_wallet_internal */
int l_fd = -1, l_rc;
uint32_t l_len = 0;
dap_chain_wallet_file_hdr_t l_file_hdr = {0};
dap_chain_wallet_cert_hdr_t l_wallet_cert_hdr = {0};
char *l_cp, *l_cert_raw, l_buf[32*1024];
dap_enc_key_t *l_enc_key;
uint32_t    csum = CRC32C_INIT;
enum    { WALLET$K_IOV_HEADER = 0, WALLET$K_IOV_BODY, WALLET$SZ_IOV_NR};
struct iovec l_iov [ WALLET$SZ_IOV_NR ];

    if ( !a_wallet )
        return  log_it(L_ERROR, "Wallet is null, can't save it to file!"), -EINVAL;

    if ( a_pass )
        if ( !(l_enc_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_GOST_OFB, NULL, 0, a_pass, strlen(a_pass), 0)) )
            return  log_it(L_ERROR, "Error create key context"), -EINVAL;

    if ( 0 > (l_fd = open(l_wallet_internal->file_name , O_CREAT | O_WRONLY, s_fileprot)) )
        return  log_it(L_ERROR,"Cant open file %s for writting, errno=%d", l_wallet_internal->file_name, errno), -errno;

    l_file_hdr.signature = DAP_CHAIN_WALLETS_FILE_SIGNATURE;                /* Fill and write Wallet's file header */
    l_file_hdr.type = a_pass ? DAP_WALLET$K_TYPE_GOST89 : DAP_WALLET$K_TYPE_PLAIN;
    l_file_hdr.version = a_pass ? DAP_WALLET$K_VER_2 : DAP_WALLET$K_VER_1;

    l_cp  = a_wallet->name ? a_wallet->name : "Bad-MotherFuqqer-Wallet";    /* What ?! */
    l_file_hdr.wallet_len = strlen(l_cp);
    l_file_hdr.wallet_len += 1;                                             /* Special ASCIZ for advanced programmers */

    l_iov[WALLET$K_IOV_HEADER].iov_base = &l_file_hdr;
    l_len = l_iov[WALLET$K_IOV_HEADER].iov_len = sizeof(l_file_hdr);

    l_iov[WALLET$K_IOV_BODY].iov_base = l_cp;
    l_len += l_iov[WALLET$K_IOV_BODY].iov_len = l_file_hdr.wallet_len;

    l_rc = writev (l_fd, l_iov, WALLET$SZ_IOV_NR );                         /* Performs writting vectorized buffer */
    if ( l_len != l_rc )
    {
        close(l_fd);
        return  log_it(L_ERROR, "Error write wallet header to file '%s', errno=%d", l_wallet_internal->file_name, errno), -EIO;
    }

                                                                            /* CRC for file header part */
    csum = s_crc32c (csum, l_iov[WALLET$K_IOV_HEADER].iov_base, l_iov[WALLET$K_IOV_HEADER].iov_len);
                                                                            /* CRC for file body part */
    csum = s_crc32c (csum, l_iov[WALLET$K_IOV_BODY].iov_base, l_iov[WALLET$K_IOV_BODY].iov_len);

    /* Write certs */
    for ( size_t i = 0; i < l_wallet_internal->certs_count ; i++)
    {
                                                                            /* Get ceritificate body */
        if ( !(l_cert_raw  = (char *) dap_cert_mem_save(l_wallet_internal->certs[i], &l_len)) )
        {
            log_it(L_WARNING, "Certificate #%zu cannot be obtained, go next ...", i);
            continue;
        }

        csum = s_crc32c (csum, l_cert_raw, l_len);                          /* CRC for every certificate */

        if ( l_enc_key )
        {
            /* Encrypt buffer with cert to local storage,
             * be advised that we don't performs a source buffer aligment preparation according to
             * block nature of the GOST family and other block-cyphers. We expect that this work is performed
             * by the "enc_na" internaly. So , relax mothefackerzzz!
             */
            l_len = l_enc_key->enc_na(l_enc_key, l_cert_raw, l_len, l_buf, sizeof(l_buf) );
        }

        l_wallet_cert_hdr.type = DAP_WALLET$K_CERT;                         /* Prepare on-disk cert record header */
        l_wallet_cert_hdr.cert_raw_size = l_len;

        /*
         * Gather chunks for I/O
        */
        l_len = 0;                                                          /* Total octets to be writtent to disk */

        l_iov[WALLET$K_IOV_HEADER].iov_base  = &l_wallet_cert_hdr;          /* Cert's record header */
        l_len += l_iov[WALLET$K_IOV_HEADER].iov_len  = sizeof(l_wallet_cert_hdr);

        l_iov[WALLET$K_IOV_BODY].iov_base  = l_enc_key ? l_buf : l_cert_raw;/* Cert itself or buffer with has been encrypted cert */
        l_len += l_iov[WALLET$K_IOV_BODY].iov_len  = l_wallet_cert_hdr.cert_raw_size;

        l_rc = writev (l_fd, l_iov, WALLET$SZ_IOV_NR );                      /* Perform writting vectorized buffer */
        DAP_DEL_Z (l_cert_raw);                                             /* Free cert's memory */
        if ( l_rc != l_len )                                                /* Check a result of the I/O operation */
        {
            close (l_fd);
            return  log_it(L_ERROR, "Error write %d octets of cert to  file '%s', errno=%d", l_len, l_wallet_internal->file_name, errno), errno;
        }
    }

    if ( l_file_hdr.version == DAP_WALLET$K_VER_2 )
    {
        l_wallet_cert_hdr.type = DAP_WALLET$K_MAGIC;
        l_wallet_cert_hdr.cert_raw_size = sizeof(csum);

        l_len = 0;                                                          /* Total octets to be writtent to disk */

        l_iov[WALLET$K_IOV_HEADER].iov_base  = &l_wallet_cert_hdr;
        l_len += l_iov[WALLET$K_IOV_HEADER].iov_len  = sizeof(l_wallet_cert_hdr);

        l_iov[WALLET$K_IOV_BODY].iov_base  = &csum;
        l_len += l_iov[WALLET$K_IOV_BODY].iov_len  = sizeof(csum);

        l_rc = writev (l_fd, l_iov, WALLET$SZ_IOV_NR );                      /* Perform writting vectorized buffer */
        if ( l_rc != l_len )                                                /* Check a result of the I/O operation */
            log_it(L_ERROR, "Error write %d octets of cert to  file '%s', errno=%d", l_len, l_wallet_internal->file_name, errno);
    }

    /* Cleanup and exit ... */
    close (l_fd);

    if ( l_enc_key )
        dap_enc_key_delete(l_enc_key);


    /* For debug purpose only */
    dap_chain_wallet_open_file (l_wallet_internal->file_name, a_pass);

    return  log_it(L_NOTICE, "Wallet '%s' has been saved into the '%s'", a_wallet->name, l_wallet_internal->file_name), 0;


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
int l_fd = -1, l_rc, l_certs_count, l_len;
dap_chain_wallet_file_hdr_t l_file_hdr = {0};
dap_chain_wallet_cert_hdr_t l_cert_hdr = {0};
char l_buf[32*1024], l_buf2[32*1024], *l_bufp, l_wallet_name [DAP_WALLET$SZ_NAME] = {0};
dap_enc_key_t *l_enc_key = NULL;
uint32_t    l_csum = CRC32C_INIT, l_csum2 = CRC32C_INIT;

    if ( 0 > (l_fd = open(a_file_name , O_RDONLY)) )                        /* Open file for ReadOnly !!! */
        return  log_it(L_ERROR,"Cant open file %s for read, errno=%d", a_file_name, errno), NULL;

    if ( sizeof(l_file_hdr) != read(l_fd, &l_file_hdr, sizeof(l_file_hdr)) )/* Get the file header record */
        return  log_it(L_ERROR, "Error read Wallet file header, errno=%d", errno), close(l_fd), NULL;

    if ( l_file_hdr.signature != DAP_CHAIN_WALLETS_FILE_SIGNATURE )         /* Check signature of the file */
        return  log_it(L_ERROR, "Wallet signature mismatch (%#lx != %#lx", l_file_hdr.signature, DAP_CHAIN_WALLETS_FILE_SIGNATURE),
                    close(l_fd), NULL;

    if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (!l_pass) )
        return  log_it(L_ERROR, "Wallet version 2 cannot be processed w/o password"), close(l_fd), NULL;

    if ( l_file_hdr.wallet_len > DAP_WALLET$SZ_NAME )
        return  log_it(L_ERROR, "Invalid Wallet name length ( >%d)", DAP_WALLET$SZ_NAME),
                    close(l_fd), NULL;

    if ( l_file_hdr.wallet_len != read(l_fd, l_wallet_name, l_file_hdr.wallet_len) ) /* Read wallet's name */
        return  log_it(L_ERROR, "Error Wallet's name, errno=%d", errno), close(l_fd), NULL;


    l_csum = s_crc32c (l_csum, &l_file_hdr, sizeof(l_file_hdr) );           /* Compute check sum of the Wallet file header */
    l_csum = s_crc32c (l_csum, l_wallet_name,  l_file_hdr.wallet_len);

    log_it(L_DEBUG, "Wallet file: %s, Wallet[Version: %d, type: %d, name: '%.*s']",
           a_file_name, l_file_hdr.version, l_file_hdr.type, l_file_hdr.wallet_len, l_wallet_name);

    /* First run - count certs in file */
    for ( l_certs_count = 0; sizeof(l_cert_hdr) == (l_rc = read (l_fd, &l_cert_hdr, sizeof(l_cert_hdr))); l_certs_count++ ) {
        if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && (l_cert_hdr.type == DAP_WALLET$K_MAGIC) )
            break;

        if ( l_cert_hdr.cert_raw_size != (l_rc = read(l_fd, l_buf, l_cert_hdr.cert_raw_size)) ) {
            log_it(L_ERROR, "Error read certificate's body (%d != %d), errno=%d", l_cert_hdr.cert_raw_size, l_rc, errno);
            break;
        }
    }

    if ( l_rc < 0 )
        return  log_it(L_ERROR, "Wallet file I/O error, errno=%d", errno), close(l_fd), NULL;

    if ( !l_certs_count )
        return  log_it(L_ERROR, "No certificate (-s) in the wallet file"), close(l_fd), NULL;


    if ( (l_file_hdr.version == DAP_WALLET$K_VER_2) && l_pass )             /* Generate encryptor context  */
        if ( !(l_enc_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_GOST_OFB, NULL, 0, l_pass, strlen(l_pass), 0)) )
            return  log_it(L_ERROR, "Error create key context"), close(l_fd), NULL;


    /* Create local instance of wallet,
     * allocate memory for array to keep loaded certs */
    l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);

    dap_snprintf(l_wallet->name, DAP_WALLET$SZ_NAME, "%.*s", l_file_hdr.wallet_len, l_wallet_name);
    l_wallet_internal->file_name = dap_strdup(a_file_name);
    l_wallet_internal->certs_count = l_certs_count;

    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_cert_t *, l_wallet_internal->certs_count * sizeof(dap_cert_t *));
    l_rc = errno;


    lseek(l_fd,  sizeof(l_file_hdr) + l_file_hdr.wallet_len, SEEK_SET);     /* Set file pointer to first record after cert file header */


    for ( size_t i = 0; sizeof(l_cert_hdr) == (l_rc = read (l_fd, &l_cert_hdr, sizeof(l_cert_hdr))); i++ )           /* Read Cert/Record header */
    {
        if ( l_cert_hdr.cert_raw_size != (l_rc = read(l_fd, l_buf, l_cert_hdr.cert_raw_size)) ) {
            log_it(L_ERROR, "Error read certificate's body (%d != %d), errno=%d", l_cert_hdr.cert_raw_size, l_rc, errno);
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
            l_csum = s_crc32c (l_csum, l_bufp, l_len);                          /* CRC for every certificate */
        }

        l_wallet_internal->certs[ i ] = dap_cert_mem_load(l_bufp, l_cert_hdr.cert_raw_size);
    }



    /* Cleanup and exit ... */
    close (l_fd);

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

    dap_snprintf(l_file_name, sizeof(l_file_name) - 1, "%s/%s%s", a_wallets_path, l_wallet_name, s_wallet_ext);


    l_pass_len = DAP_WALLET$SZ_PASS;                                    /* Size of the buffer for password */
                                                                        /* Lookup password in the internal hash-table */
    if ( (l_rc = s_dap_chain_wallet_pass (l_wallet_name, strlen(l_wallet_name), l_pass, &l_pass_len)) )
        l_pass_len = 0;


    return  dap_chain_wallet_open_file(l_file_name, l_pass_len ? l_pass : NULL);
}

#if 0   /* @RRL: #6131, to be removed in near future ! */
dap_chain_wallet_t *dap_chain_wallet_open_ext (
                    const char *a_wallet_name,
                    const char *a_wallets_path,
                    const char *pass
                                            )
{
    char l_file_name [MAX_PATH] = {0};

    if(!a_wallet_name || !a_wallets_path)
        return NULL;

    dap_snprintf(l_file_name, sizeof(l_file_name) - 1, "%s/%s%s", a_wallets_path, a_wallet_name, s_wallet_ext);

    return  dap_chain_wallet_open_file(l_file_name, pass);
}
#endif


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
 * @brief dap_chain_wallet_create_with_seed
 * @param a_wallet_name
 * @param a_wallets_path
 * @param a_net_id
 * @param a_sig_type
 * @details Creates new wallet
 * @return Wallet, new wallet or NULL if errors
 */
dap_chain_wallet_t * dap_chain_wallet_create_with_seed_ext (
                            const char * a_wallet_name,
                            const char * a_wallets_path,
                            dap_sign_type_t a_sig_type,
                            const void* a_seed,
                            size_t a_seed_size,
                            const char *a_pass_str
                                                        )
{
    dap_chain_wallet_t * l_wallet = DAP_NEW_Z(dap_chain_wallet_t);
    DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(l_wallet);
    strcpy(l_wallet->name, a_wallet_name);
    l_wallet_internal->certs_count = 1;
    l_wallet_internal->certs = DAP_NEW_Z_SIZE(dap_cert_t *, l_wallet_internal->certs_count * sizeof(dap_cert_t *));

    size_t l_file_name_size = strlen(a_wallet_name) + strlen(a_wallets_path) + 13;
    l_wallet_internal->file_name = DAP_NEW_Z_SIZE (char,  l_file_name_size);

    dap_snprintf(l_wallet_internal->file_name, l_file_name_size, "%s/%s%s", a_wallets_path, a_wallet_name, s_wallet_ext);

    l_wallet_internal->certs[0] = dap_cert_generate_mem_with_seed(a_wallet_name, dap_sign_type_to_key_type(a_sig_type), a_seed, a_seed_size);


    if ( !dap_chain_wallet_save (l_wallet, a_pass_str) )
        return l_wallet;

    log_it(L_ERROR,"Can't save the new wallet to disk, errno=%d ", errno);
    dap_chain_wallet_close(l_wallet);
    return NULL;

}
