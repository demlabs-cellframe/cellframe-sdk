#include <libconfig.h>
#include <unistd.h>
#include "config.h"
#include "common.h"

#define LOG_TAG "config"

#define MY_CONFIG_PATH "/opt/dapserver/etc/dap_server.cfg"
config_t cfg;
struct my_config my_config={
    .pid_path = "/opt/dapserver/run/dapserver.pid"
};

//struct my_config my_config={"sqlite3","local.db","","/opt/dapserver/db/"};
int my_config_init()
{
	config_init(&cfg);
	/* Read the file. If there is an error, report it and exit. */
    if(CONFIG_FALSE == config_read_file(&cfg, MY_CONFIG_PATH))
	{
		fprintf(stderr, "Can't open %s\n", MY_CONFIG_PATH);
        config_destroy(&cfg);
		return -1;
    }

    config_lookup_string(&cfg, "log_file", &my_config.log_file);
	config_lookup_string(&cfg, "db_type", &my_config.db_type);
	config_lookup_string(&cfg, "db_path", &my_config.db_path);
    config_lookup_string(&cfg, "db_name", &my_config.db_name);
	config_lookup_string(&cfg, "contents_path", &my_config.contents_path);
    config_lookup_string(&cfg, "www_root", &my_config.www_root);
    config_lookup_string(&cfg, "dap_domain", &my_config.dap_domain);

    config_lookup_string(&cfg, "key_private", &my_config.key_private);
    config_lookup_string(&cfg, "key_public", &my_config.key_public);

    config_lookup_string(&cfg, "listen_address", &my_config.listen_address);
    config_lookup_int(&cfg, "listen_port", &my_config.listen_port);

    config_lookup_string(&cfg, "posters_big_path", &my_config.posters_big_path);
    config_lookup_string(&cfg, "posters_small_path", &my_config.posters_small_path);

    config_lookup_int64( &cfg, "gst_audio_precache_time", &my_config.gst_audio_precache_time);

    config_lookup_string(&cfg, "vpn_addr", &my_config.vpn_addr);
    config_lookup_string(&cfg, "vpn_mask", &my_config.vpn_mask);
    config_lookup_string(&cfg, "pid_path", &my_config.pid_path);

    config_lookup_int(&cfg, "threads_cnt", &my_config.threads_cnt);

	config_lookup_int(&cfg, "TTL_session_key", &my_config.TTL_session_key);
    config_lookup_string(&cfg, "servers_file", &my_config.servers_list_file);
    my_config.report_template_file = NULL;
    config_lookup_string(&cfg, "report_template_file", &my_config.report_template_file);



    //	log_it(DEBUG, "[config]  db_path=%s",my_config.db_path);

    if (!my_config.log_file)
        log_it(WARNING, "log_file not readet");
    if (!my_config.db_type)
        log_it(WARNING, "db_type not readet");
    if (!my_config.db_name)
        log_it(WARNING, " not readet");
    if (!my_config.db_path)
        log_it(WARNING, "db_path not readet");
    if (!my_config.contents_path)
        log_it(WARNING, "contents_path not readet");
    if (!my_config.www_root)
        log_it(WARNING, "www_root not readet");
    if (!my_config.key_private)
        log_it(WARNING, "key_private not readet");
    if (!my_config.key_public)
        log_it(WARNING, "key_public not readet");
    if (!my_config.listen_address)
        log_it(WARNING, "listen_address not readet");
    if (!my_config.posters_big_path)
        log_it(WARNING, "posters_big_path; not readet");
    if (!my_config.posters_small_path)
        log_it(WARNING, "posters_small_path not readet");
    if (!my_config.servers_list_file)
        log_it(WARNING, "servers_file not readet");
    if (!my_config.listen_port)
        log_it(WARNING, "listen_port not readet or not correct value");
    if (!my_config.gst_audio_precache_time)
        log_it(WARNING, "gst_audio_precache_time not readet or not correct value");
    if (!my_config.TTL_session_key)
        log_it(WARNING, "TTL_session_key not readet");

    if (!my_config.threads_cnt)
    {
        log_it(WARNING, "threads_cnt not readet");
        my_config.threads_cnt = sysconf(_SC_NPROCESSORS_ONLN);
        if (my_config.threads_cnt < 0)
        {
            log_it(WARNING, "threads_cnt can't get _SC_NPROCESSORS_ONLN, set default = 1");
            my_config.threads_cnt = 1;
        }
    }

	return 0;
}

void my_config_deinit()
{
	config_destroy(&cfg);
}

