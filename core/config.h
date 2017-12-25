#ifndef _CONFIG_H
#define _CONFIG_H
struct my_config{
	const char * db_type; /* Database type (sqlite3,pgsql or mysql) */
	const char * db_name; /* Name of database*/
	const char * db_path; /* Path to media files*/
	const char * contents_path; /* Path to media files*/
	const char * log_file; /* Path to the log file */
    const char * www_root;
    const char * dap_domain;
    const char * vpn_addr;
    const char * vpn_mask;

    const char * key_private;
    const char * key_public;

    const char * listen_address; /* Address to listen */
    int listen_port; /* Port to listen*/

    const char * posters_big_path;
    const char * posters_small_path;

    const char * servers_list_file;
    const char * report_template_file;

    const char * pid_path;

    int threads_cnt;

    long long gst_audio_precache_time; // Gst: Delta of positions between master and slave streams
    unsigned int TTL_session_key; // in minutes
};

extern struct my_config my_config;
extern int my_config_init();
extern void my_config_deinit();

#endif
