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

//#include <windows.h>
//#include <winnt.h>
#include <winternl.h>
#include <stdint.h>
#include <pdh.h>
#include <stdio.h>
#include <psapi.h>

#include "dap_process_memory.h"
#include "dap_common.h"

#define LOG_TAG "dap_process_mem"

static dap_process_memory_t _get_process_memory( uint32_t pid )
{
  HANDLE hProcess;
  PROCESS_MEMORY_COUNTERS pmc;
  dap_process_memory_t proc_mem = { 0, 0 };

  hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
  if ( !hProcess )
      return proc_mem;

  if ( !GetProcessMemoryInfo( hProcess, &pmc, sizeof(pmc)) ) {
    CloseHandle( hProcess );
    return proc_mem;
  }

  proc_mem.vsz = pmc.PagefileUsage;
  proc_mem.rss = pmc.WorkingSetSize;

  CloseHandle( hProcess );
  return proc_mem;
}

dap_process_memory_t get_proc_mem_current( void )
{
  return _get_process_memory( GetCurrentProcessId() );
}

dap_process_memory_t get_proc_mem_by_pid( uint32_t pid )
{
  return _get_process_memory( pid );
}
