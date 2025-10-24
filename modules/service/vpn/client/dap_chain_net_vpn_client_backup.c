/**
 * @file dap_chain_net_vpn_client_backup.c
 * @brief VPN Client Network Configuration Backup and Restore Implementation
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#include "dap_chain_net_vpn_client_backup.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_file_utils.h"
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <unistd.h>
#endif

#define LOG_TAG "dap_chain_net_vpn_client_backup"

// Platform-specific backup directories
#ifdef __linux__
#define BACKUP_DIR "/opt/cellframe-vpn-client/var/lib"
#elif defined(__APPLE__)
#define BACKUP_DIR "/Library/Application Support/CellframeVPNClient"
#elif defined(_WIN32)
#define BACKUP_DIR "C:\\ProgramData\\CellframeVPNClient"
#else
#define BACKUP_DIR "/tmp/cellframe-vpn-client"
#endif

dap_chain_net_vpn_client_backup_t* dap_chain_net_vpn_client_backup_new(void) {
    dap_chain_net_vpn_client_backup_t *l_backup = DAP_NEW_Z(dap_chain_net_vpn_client_backup_t);
    if (!l_backup) {
        log_it(L_CRITICAL, "Failed to allocate backup structure");
        return NULL;
    }
    
    l_backup->timestamp = (int64_t)time(NULL);
    l_backup->backup_valid = true;
    
#ifdef __linux__
    l_backup->platform = dap_strdup("linux");
#elif defined(__APPLE__)
    l_backup->platform = dap_strdup("macos");
#elif defined(_WIN32)
    l_backup->platform = dap_strdup("windows");
#else
    l_backup->platform = dap_strdup("unknown");
#endif
    
    return l_backup;
}

void dap_chain_net_vpn_client_backup_free(dap_chain_net_vpn_client_backup_t *a_backup) {
    if (!a_backup) return;
    
    DAP_DELETE(a_backup->platform);
    DAP_DELETE(a_backup->connection_state);
    DAP_DELETE(a_backup->vpn_server_ip);
    DAP_DELETE(a_backup->vpn_interface);
    DAP_DELETE(a_backup->vpn_gateway);
    DAP_DELETE(a_backup->original_gateway);
    DAP_DELETE(a_backup->original_interface);
    DAP_DELETE(a_backup->original_metric);
    
    // Free DNS arrays
    if (a_backup->original_dns_servers) {
        for (size_t i = 0; i < a_backup->original_dns_count; i++) {
            DAP_DELETE(a_backup->original_dns_servers[i]);
        }
        DAP_DELETE(a_backup->original_dns_servers);
    }
    
    if (a_backup->original_search_domains) {
        for (size_t i = 0; i < a_backup->original_search_domains_count; i++) {
            DAP_DELETE(a_backup->original_search_domains[i]);
        }
        DAP_DELETE(a_backup->original_search_domains);
    }
    
    DAP_DELETE(a_backup->original_resolv_conf);
    DAP_DELETE(a_backup->network_service);
    
    // Note: platform_specific_backup should be freed by platform-specific code
    
    DAP_DELETE(a_backup);
}

int dap_chain_net_vpn_client_backup_ensure_dir(void) {
    struct stat st = {0};
    if (stat(BACKUP_DIR, &st) == -1) {
        if (mkdir(BACKUP_DIR, 0700) != 0) {
            log_it(L_ERROR, "Failed to create backup directory %s: %s", 
                   BACKUP_DIR, strerror(errno));
            return -1;
        }
        log_it(L_INFO, "Created backup directory: %s", BACKUP_DIR);
    }
    return 0;
}

const char* dap_chain_net_vpn_client_backup_get_path(const char *a_custom_path) {
    if (a_custom_path) {
        return a_custom_path;
    }
    return DAP_CHAIN_NET_VPN_CLIENT_BACKUP_FILE;
}

int dap_chain_net_vpn_client_backup_save(const dap_chain_net_vpn_client_backup_t *a_backup,
                                          const char *a_path) {
    if (!a_backup) return -1;
    
    // Ensure backup directory exists
    if (dap_chain_net_vpn_client_backup_ensure_dir() != 0) {
        return -2;
    }
    
    const char *l_path = dap_chain_net_vpn_client_backup_get_path(a_path);
    
    // Create JSON object
    json_object *l_root = json_object_new_object();
    if (!l_root) {
        log_it(L_ERROR, "Failed to create JSON object");
        return -3;
    }
    
    // Add metadata
    json_object_object_add(l_root, "version", json_object_new_string("1.0"));
    json_object_object_add(l_root, "timestamp", json_object_new_int64(a_backup->timestamp));
    if (a_backup->platform) {
        json_object_object_add(l_root, "platform", json_object_new_string(a_backup->platform));
    }
    if (a_backup->connection_state) {
        json_object_object_add(l_root, "connection_state", json_object_new_string(a_backup->connection_state));
    }
    json_object_object_add(l_root, "backup_valid", json_object_new_boolean(a_backup->backup_valid));
    
    // Add VPN connection info
    if (a_backup->vpn_server_ip) {
        json_object_object_add(l_root, "vpn_server_ip", json_object_new_string(a_backup->vpn_server_ip));
    }
    if (a_backup->vpn_interface) {
        json_object_object_add(l_root, "vpn_interface", json_object_new_string(a_backup->vpn_interface));
    }
    if (a_backup->vpn_gateway) {
        json_object_object_add(l_root, "vpn_gateway", json_object_new_string(a_backup->vpn_gateway));
    }
    
    // Add original network configuration
    if (a_backup->original_gateway) {
        json_object_object_add(l_root, "original_gateway", json_object_new_string(a_backup->original_gateway));
    }
    if (a_backup->original_interface) {
        json_object_object_add(l_root, "original_interface", json_object_new_string(a_backup->original_interface));
    }
    if (a_backup->original_metric) {
        json_object_object_add(l_root, "original_metric", json_object_new_string(a_backup->original_metric));
    }
    
    // Add DNS servers array
    if (a_backup->original_dns_servers && a_backup->original_dns_count > 0) {
        json_object *l_dns_array = json_object_new_array();
        for (size_t i = 0; i < a_backup->original_dns_count; i++) {
            json_object_array_add(l_dns_array, json_object_new_string(a_backup->original_dns_servers[i]));
        }
        json_object_object_add(l_root, "original_dns_servers", l_dns_array);
    }
    
    // Add search domains array
    if (a_backup->original_search_domains && a_backup->original_search_domains_count > 0) {
        json_object *l_search_array = json_object_new_array();
        for (size_t i = 0; i < a_backup->original_search_domains_count; i++) {
            json_object_array_add(l_search_array, json_object_new_string(a_backup->original_search_domains[i]));
        }
        json_object_object_add(l_root, "original_search_domains", l_search_array);
    }
    
    // Add platform-specific fields
    if (a_backup->original_resolv_conf) {
        json_object_object_add(l_root, "original_resolv_conf", json_object_new_string(a_backup->original_resolv_conf));
    }
    if (a_backup->network_service) {
        json_object_object_add(l_root, "network_service", json_object_new_string(a_backup->network_service));
    }
    if (a_backup->interface_index > 0) {
        json_object_object_add(l_root, "interface_index", json_object_new_int64(a_backup->interface_index));
    }
    
    // Write to file with pretty formatting
    const char *l_json_str = json_object_to_json_string_ext(l_root, JSON_C_TO_STRING_PRETTY);
    if (!l_json_str) {
        log_it(L_ERROR, "Failed to serialize JSON");
        json_object_put(l_root);
        return -4;
    }
    
    FILE *l_file = fopen(l_path, "w");
    if (!l_file) {
        log_it(L_ERROR, "Failed to open backup file for writing: %s: %s", l_path, strerror(errno));
        json_object_put(l_root);
        return -5;
    }
    
    size_t l_len = strlen(l_json_str);
    size_t l_written = fwrite(l_json_str, 1, l_len, l_file);
    fclose(l_file);
    
    json_object_put(l_root);
    
    if (l_written != l_len) {
        log_it(L_ERROR, "Failed to write complete backup file");
        return -6;
    }
    
    log_it(L_INFO, "Backup saved to: %s", l_path);
    return 0;
}

int dap_chain_net_vpn_client_backup_load(const char *a_path,
                                          dap_chain_net_vpn_client_backup_t **a_out_backup) {
    if (!a_out_backup) return -1;
    
    const char *l_path = dap_chain_net_vpn_client_backup_get_path(a_path);
    
    // Read file
    FILE *l_file = fopen(l_path, "r");
    if (!l_file) {
        log_it(L_DEBUG, "Backup file not found: %s", l_path);
        return -2;
    }
    
    fseek(l_file, 0, SEEK_END);
    long l_size = ftell(l_file);
    fseek(l_file, 0, SEEK_SET);
    
    if (l_size <= 0 || l_size > 1024 * 1024) { // Max 1MB
        log_it(L_ERROR, "Invalid backup file size: %ld", l_size);
        fclose(l_file);
        return -3;
    }
    
    char *l_json_str = DAP_NEW_Z_SIZE(char, l_size + 1);
    if (!l_json_str) {
        fclose(l_file);
        return -4;
    }
    
    size_t l_read = fread(l_json_str, 1, l_size, l_file);
    fclose(l_file);
    
    if (l_read != (size_t)l_size) {
        log_it(L_ERROR, "Failed to read backup file");
        DAP_DELETE(l_json_str);
        return -5;
    }
    
    // Parse JSON
    json_object *l_root = json_tokener_parse(l_json_str);
    DAP_DELETE(l_json_str);
    
    if (!l_root) {
        log_it(L_ERROR, "Failed to parse backup JSON");
        return -6;
    }
    
    // Create backup structure
    dap_chain_net_vpn_client_backup_t *l_backup = DAP_NEW_Z(dap_chain_net_vpn_client_backup_t);
    if (!l_backup) {
        json_object_put(l_root);
        return -7;
    }
    
    // Extract fields
    json_object *l_obj;
    
    if (json_object_object_get_ex(l_root, "timestamp", &l_obj)) {
        l_backup->timestamp = json_object_get_int64(l_obj);
    }
    
    if (json_object_object_get_ex(l_root, "platform", &l_obj)) {
        l_backup->platform = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "connection_state", &l_obj)) {
        l_backup->connection_state = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "backup_valid", &l_obj)) {
        l_backup->backup_valid = json_object_get_boolean(l_obj);
    }
    
    if (json_object_object_get_ex(l_root, "vpn_server_ip", &l_obj)) {
        l_backup->vpn_server_ip = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "vpn_interface", &l_obj)) {
        l_backup->vpn_interface = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "vpn_gateway", &l_obj)) {
        l_backup->vpn_gateway = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "original_gateway", &l_obj)) {
        l_backup->original_gateway = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "original_interface", &l_obj)) {
        l_backup->original_interface = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "original_metric", &l_obj)) {
        l_backup->original_metric = dap_strdup(json_object_get_string(l_obj));
    }
    
    // Extract DNS servers array
    if (json_object_object_get_ex(l_root, "original_dns_servers", &l_obj)) {
        size_t l_count = json_object_array_length(l_obj);
        if (l_count > 0) {
            l_backup->original_dns_count = l_count;
            l_backup->original_dns_servers = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            for (size_t i = 0; i < l_count; i++) {
                json_object *l_item = json_object_array_get_idx(l_obj, i);
                l_backup->original_dns_servers[i] = dap_strdup(json_object_get_string(l_item));
            }
        }
    }
    
    // Extract search domains array
    if (json_object_object_get_ex(l_root, "original_search_domains", &l_obj)) {
        size_t l_count = json_object_array_length(l_obj);
        if (l_count > 0) {
            l_backup->original_search_domains_count = l_count;
            l_backup->original_search_domains = DAP_NEW_Z_SIZE(char*, l_count * sizeof(char*));
            for (size_t i = 0; i < l_count; i++) {
                json_object *l_item = json_object_array_get_idx(l_obj, i);
                l_backup->original_search_domains[i] = dap_strdup(json_object_get_string(l_item));
            }
        }
    }
    
    if (json_object_object_get_ex(l_root, "original_resolv_conf", &l_obj)) {
        l_backup->original_resolv_conf = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "network_service", &l_obj)) {
        l_backup->network_service = dap_strdup(json_object_get_string(l_obj));
    }
    
    if (json_object_object_get_ex(l_root, "interface_index", &l_obj)) {
        l_backup->interface_index = (uint32_t)json_object_get_int64(l_obj);
    }
    
    json_object_put(l_root);
    
    log_it(L_INFO, "Backup loaded from: %s", l_path);
    *a_out_backup = l_backup;
    return 0;
}

bool dap_chain_net_vpn_client_backup_validate(const dap_chain_net_vpn_client_backup_t *a_backup) {
    if (!a_backup) return false;
    
    // Check backup_valid flag
    if (!a_backup->backup_valid) {
        log_it(L_WARNING, "Backup marked as invalid");
        return false;
    }
    
    // Check required fields
    if (!a_backup->platform) {
        log_it(L_WARNING, "Backup missing platform");
        return false;
    }
    
    // Must have original gateway or interface
    if (!a_backup->original_gateway && !a_backup->original_interface) {
        log_it(L_WARNING, "Backup missing original network configuration");
        return false;
    }
    
    // Check timestamp (not older than 24 hours)
    int64_t l_now = (int64_t)time(NULL);
    int64_t l_age = l_now - a_backup->timestamp;
    if (l_age > 86400 || l_age < 0) { // 24 hours
        log_it(L_WARNING, "Backup too old or timestamp invalid: %ld seconds", (long)l_age);
        return false;
    }
    
    log_it(L_INFO, "Backup validation passed");
    return true;
}

int dap_chain_net_vpn_client_backup_remove(const char *a_path) {
    const char *l_path = dap_chain_net_vpn_client_backup_get_path(a_path);
    
    if (unlink(l_path) != 0) {
        if (errno != ENOENT) {
            log_it(L_WARNING, "Failed to remove backup file %s: %s", l_path, strerror(errno));
            return -1;
        }
    } else {
        log_it(L_INFO, "Backup file removed: %s", l_path);
    }
    
    return 0;
}

bool dap_chain_net_vpn_client_backup_exists(const char *a_path) {
    const char *l_path = dap_chain_net_vpn_client_backup_get_path(a_path);
    struct stat st;
    return (stat(l_path, &st) == 0);
}

int dap_chain_net_vpn_client_backup_auto_restore(void) {
    // Check if backup file exists
    if (!dap_chain_net_vpn_client_backup_exists(NULL)) {
        log_it(L_DEBUG, "No backup file found, no restore needed");
        return 0;
    }
    
    log_it(L_WARNING, "Backup file found - possible previous crash detected");
    
    // Load backup
    dap_chain_net_vpn_client_backup_t *l_backup = NULL;
    int l_ret = dap_chain_net_vpn_client_backup_load(NULL, &l_backup);
    if (l_ret != 0) {
        log_it(L_ERROR, "Failed to load backup file for auto-restore: %d", l_ret);
        return l_ret;
    }
    
    // Validate backup
    if (!dap_chain_net_vpn_client_backup_validate(l_backup)) {
        log_it(L_ERROR, "Backup validation failed, cannot auto-restore");
        dap_chain_net_vpn_client_backup_free(l_backup);
        dap_chain_net_vpn_client_backup_remove(NULL);
        return -1;
    }
    
    log_it(L_INFO, "Auto-restoring network configuration from backup...");
    
    // Call platform-specific restore
    // TODO: This needs to be implemented - call appropriate platform restore function
    // For now, just log and remove backup
    log_it(L_WARNING, "Platform-specific restore not yet implemented");
    
    // Remove backup file after restore
    dap_chain_net_vpn_client_backup_remove(NULL);
    dap_chain_net_vpn_client_backup_free(l_backup);
    
    log_it(L_INFO, "Auto-restore complete");
    return 0;
}

