/*
 Copyright (c) 2017-2019 (c) Project "DeM Labs Inc" https://gitlab.demlabs.net/cellframe
  All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <windows.h>
//#include <winnt.h>
#include <winternl.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "dap_process_manager.h"
#include "dap_common.h"

#undef LOG_TAG
#define LOG_TAG "dap_process_manager"

/**
 * @brief is_process_running Check whether the process is running
 * @param[in] pid PID
 * @return
 */
bool is_process_running( pid_t pid ) {

  DWORD ExitCode = 0;

  HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );

  if ( !hProcess ) 
    return false;

  if ( !GetExitCodeProcess( hProcess, &ExitCode ) || ExitCode != STILL_ACTIVE ) {
    CloseHandle( hProcess );
    return false;
  }

  CloseHandle( hProcess );

  return true;
}

/**
 * @brief save_process_pid_in_file Saves process pid into file by file_path
 * @param[in] file_path File path
 * @return Execution result
 *
 * Saves process pid into file by file_path.
 * If file exists he will be overwritten
 */
bool save_process_pid_in_file( const char* file_path )
{
  FILE *fpid = fopen( file_path, "wb" );

  if ( fpid == NULL ) {
    log_it( L_ERROR, "Cant create/open file by path %s",file_path );
    return false;
  }

  fprintf( fpid, "%u", GetCurrentProcessId() );
  fclose( fpid );

  return true;
}

/**
 * @brief get_pid_from_file File must consist only PID. Return 0 if file is clear.
 * @param[in] file_path File path
 * @return Execution result
 */
pid_t get_pid_from_file( const char* file_path ) {

  FILE *fpid = fopen( file_path, "rb");

  if ( fpid == NULL ) {
    log_it( L_ERROR, "Cant create/open file by path %s", file_path );
    return false;
  }

  pid_t f_pid = 0;

  fscanf( fpid, "%u", &f_pid );
  fclose( fpid );

  return f_pid;
}

/**
 * @brief daemonize_process Demonizes current process and exit from program
 * @return
 */
bool daemonize_process( ) {

  STARTUPINFO start_info;
  PROCESS_INFORMATION proc_info;
  char fn_exe[256];
  DWORD status;

  memset( &start_info, 0, sizeof(STARTUPINFO) );
  memset( &proc_info, 0, sizeof(PROCESS_INFORMATION) );
  memset( &fn_exe[0], 0, 256 );

  status = GetModuleFileName( NULL, fn_exe, sizeof(fn_exe) );

  if ( !status || status == sizeof(fn_exe) ) {
    return false;
  }

  GetStartupInfo( &start_info );

  if ( CreateProcess(fn_exe, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &start_info, &proc_info) ) {

    CloseHandle( proc_info.hThread );
    CloseHandle( proc_info.hProcess );
    ExitProcess( 0 );
  }

  return false;
}

/**
 * @brief kill_process Sends SIGKILL to process
 * @param[in] pid
 * @return
 */
bool kill_process( pid_t pid ) {

  DWORD ExitCode;
  bool rezult = false;

  HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, FALSE, pid );

  if ( !hProcess ) {

    return false;
  }

  if ( !GetExitCodeProcess( hProcess, &ExitCode ) ) {

    return false;
    CloseHandle( hProcess );
  }

  if ( ExitCode == STILL_ACTIVE ) {
    rezult = TerminateProcess( hProcess, 0 );
  }

  CloseHandle( hProcess );

  return rezult;
}
