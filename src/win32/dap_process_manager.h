
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>

/* Saves process pid into file by file_path.
 * If file exists he will be overwritten */
extern bool save_process_pid_in_file( const char* file_path );

/* File must consist only PID. Return 0 if file is clear. */
extern pid_t get_pid_from_file( const char* file_path );

/* Return true if process running */
extern bool is_process_running( pid_t pid );

/* Demonizes current process and exit from program */
extern bool daemonize_process( void );

/* Sends SIGKILL to process */
extern bool kill_process( pid_t pid );

