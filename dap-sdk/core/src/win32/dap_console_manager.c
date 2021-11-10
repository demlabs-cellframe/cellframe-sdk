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

#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <memory.h>

#include <windows.h>

#define WM_SETCONSOLEINFO (WM_USER + 201) 

#pragma pack(push, 1) 
typedef struct _CONSOLE_INFO
{
  DWORD Length;
  COORD ScreenBufferSize;
  COORD WindowSize;
  DWORD WindowPosX;
  DWORD WindowPosY;
  COORD FontSize;
  DWORD FontFamily;
  DWORD FontWeight;
  WCHAR FaceName[32];
  DWORD CursorSize;
  DWORD FullScreen;
  DWORD QuickEdit;
  DWORD AutoPosition;
  DWORD InsertMode;
  USHORT ScreenColors;
  USHORT PopupColors;
  DWORD HistoryNoDup;
  DWORD HistoryBufferSize;
  DWORD NumberOfHistoryBuffers;
  COLORREF ColorTable[16];
  DWORD CodePage;
  HWND Hwnd;
  WCHAR ConsoleTitle[0x100];
} CONSOLE_INFO;
#pragma pack(pop) 

static uint32_t palette[ 16 ] =  {

  RGB(   0,   0,   0 ), // 0   black
  RGB(   0,   0, 128 ), // 1   blue
  RGB( 0,   128,   0 ), // 2   green
  RGB( 128, 128,   0 ), // 3   cyan 
  RGB( 128,   0,   0 ), // 4   red
  RGB( 128,   0, 128 ), // 5   magenta
  RGB(   0, 128, 128 ), // 6   yellow / brown
  RGB( 192, 192, 192 ), // 7   white / light gray
  RGB( 128, 128, 128 ), // 8   dark gray / bright black
  RGB(   0,   0, 255 ), // 9   bright blue
  RGB(   0, 255,   0 ), // 10  bright green
  RGB(   0, 255, 255 ), // 11  bright cyan
  RGB( 255,  0,    0 ), // 12  bright red
  RGB( 255,  0,  255 ), // 13  bright magenta
  RGB( 255, 255,   0 ), // 14  bright yellow
  RGB( 255, 255, 255 )  // 15  bright white
};

static void GetConsoleSizeInfo( CONSOLE_INFO *pci, HANDLE hConOut )
{
  CONSOLE_SCREEN_BUFFER_INFO csbi;

  GetConsoleScreenBufferInfo( hConOut, &csbi );

  pci->ScreenBufferSize = csbi.dwSize;
  pci->WindowSize.X = csbi.srWindow.Right - csbi.srWindow.Left + 1;
  pci->WindowSize.Y = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
  pci->WindowPosX = csbi.srWindow.Left;
  pci->WindowPosY = csbi.srWindow.Top;
}

static BOOL SetConsoleInfo( HWND hwndConsole, CONSOLE_INFO *pci )
{
  DWORD dwConsoleOwnerPid;
  HANDLE hProcess;
  HANDLE hSection, hDupSection;
  PVOID ptrView = 0;
  HANDLE hThread;
  
  GetWindowThreadProcessId( hwndConsole, &dwConsoleOwnerPid );

  hProcess = OpenProcess( MAXIMUM_ALLOWED, FALSE, dwConsoleOwnerPid );
  hSection = CreateFileMapping( INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, pci->Length, 0 );
  ptrView  = MapViewOfFile( hSection, FILE_MAP_WRITE|FILE_MAP_READ, 0, 0, pci->Length );

  memcpy( ptrView, pci, pci->Length );
  UnmapViewOfFile( ptrView );

  DuplicateHandle( GetCurrentProcess(), hSection, hProcess, &hDupSection, 0, FALSE, DUPLICATE_SAME_ACCESS );

  SendMessage( hwndConsole, WM_SETCONSOLEINFO, (WPARAM)hDupSection, 0 );

  hThread = CreateRemoteThread( hProcess, 0, 0, (LPTHREAD_START_ROUTINE)CloseHandle, hDupSection, 0, 0 );

  CloseHandle( hThread );
  CloseHandle( hSection );
  CloseHandle( hProcess );

  return TRUE;
}

typedef BOOL (WINAPI *PGetCurrentConsoleFontEx)(HANDLE hConsoleOutput, BOOL bMaximumWindow, PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);
typedef BOOL (WINAPI *PSetCurrentConsoleFontEx)(HANDLE hConsoleOutput, BOOL bMaximumWindow, PCONSOLE_FONT_INFOEX lpConsoleCurrentFontEx);
typedef BOOL (WINAPI *PGetConsoleScreenBufferInfoEx)(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx);
typedef BOOL (WINAPI *PSetConsoleScreenBufferInfoEx)(HANDLE hConsoleOutput, PCONSOLE_SCREEN_BUFFER_INFOEX lpConsoleScreenBufferInfoEx);

////Lucida Console 12 20

void SetupConsole( const char *title, const uint16_t *fontName, int fontx, int fonty )
{
  HANDLE hConOut;
  HANDLE hConIn;

  HWND hwndConsole = GetConsoleWindow( );
  if ( !hwndConsole ) { // daemon ?
    return;
  }

  uint32_t console_owner_proc_id;

  GetWindowThreadProcessId( hwndConsole, (LPDWORD)&console_owner_proc_id );

  if ( console_owner_proc_id != GetCurrentProcessId() ) {
    return;
  }

  SetConsoleTitleA( (LPCSTR)title );

  hConOut = GetStdHandle( STD_OUTPUT_HANDLE );
  hConIn  = GetStdHandle( STD_INPUT_HANDLE );

  int sx = GetSystemMetrics( SM_CXSCREEN );
  int sy = GetSystemMetrics( SM_CYSCREEN );

//  COORD conmax = GetLargestConsoleWindowSize( hConOut );

  PGetCurrentConsoleFontEx pGetCurrentConsoleFontEx = (PGetCurrentConsoleFontEx)(void *)
    GetProcAddress( GetModuleHandleA("kernel32.dll"), "GetCurrentConsoleFontEx" );
  PSetCurrentConsoleFontEx pSetCurrentConsoleFontEx = (PSetCurrentConsoleFontEx)(void *)
    GetProcAddress( GetModuleHandleA("kernel32.dll"), "SetCurrentConsoleFontEx" );
  PGetConsoleScreenBufferInfoEx pGetConsoleScreenBufferInfoEx = (PGetConsoleScreenBufferInfoEx)(void *)
    GetProcAddress( GetModuleHandleA("kernel32.dll"), "GetConsoleScreenBufferInfoEx" );
  PSetConsoleScreenBufferInfoEx pSetConsoleScreenBufferInfoEx = (PSetConsoleScreenBufferInfoEx)(void *)
    GetProcAddress( GetModuleHandleA("kernel32.dll"), "SetConsoleScreenBufferInfoEx" );

  if ( pGetCurrentConsoleFontEx && pSetCurrentConsoleFontEx &&
      pGetConsoleScreenBufferInfoEx && pSetConsoleScreenBufferInfoEx )
  {
    CONSOLE_SCREEN_BUFFER_INFOEX conBufferInfo; 
    CONSOLE_FONT_INFOEX conFontInfo = {};

    conFontInfo.cbSize = sizeof( CONSOLE_FONT_INFOEX );
    pGetCurrentConsoleFontEx( hConOut, TRUE, &conFontInfo );

//    printf("conFontInfo.nFont %u \n", conFontInfo.nFont );
//    printf("conFontInfo.dwFontSize.X %u \n", conFontInfo.dwFontSize.X );
//    printf("conFontInfo.dwFontSize.Y %u \n", conFontInfo.dwFontSize.Y );
//    printf("conFontInfo.FontFamily %u \n", conFontInfo.FontFamily );
//    printf("conFontInfo.FontWeight %u \n", conFontInfo.FontWeight );

    conFontInfo.nFont = 20;
    conFontInfo.dwFontSize.X = 12;
    conFontInfo.dwFontSize.Y = 20;
    conFontInfo.FontFamily = 0;
    conFontInfo.FontWeight = 0;
    lstrcpyW( conFontInfo.FaceName, fontName );

    pSetCurrentConsoleFontEx( hConOut, TRUE, &conFontInfo );

    conBufferInfo.cbSize = sizeof( CONSOLE_SCREEN_BUFFER_INFOEX );
    pGetConsoleScreenBufferInfoEx( hConOut, &conBufferInfo );

    memcpy( &conBufferInfo.ColorTable[0], &palette[0], 4 * 16 );
    pSetConsoleScreenBufferInfoEx( hConOut, &conBufferInfo );
  }
  else {
//    printf("XP ?...\n" );

    CONSOLE_INFO ci = { .Length = sizeof(ci) };

    GetConsoleSizeInfo( &ci, hConOut );

    ci.FontSize.X = 12;
    ci.FontSize.Y = 20;
    ci.FontFamily = 0;
    ci.FontWeight = 0;

    lstrcpyW( ci.FaceName, fontName );

//    ci.CursorSize = 100;
    ci.FullScreen = FALSE;
    ci.QuickEdit = FALSE;
    ci.AutoPosition = 0x10000;
    ci.InsertMode = TRUE;
    ci.ScreenColors = MAKEWORD(0x7, 0x0);
    ci.PopupColors = MAKEWORD(0x5, 0xf); 
    ci.HistoryNoDup = TRUE; 
    ci.HistoryBufferSize = 50; 
    ci.NumberOfHistoryBuffers = 4; 

    memcpy( &ci.ColorTable[0], &palette[0], 4 * 16 );

    ci.CodePage = 0; 
    ci.Hwnd = hwndConsole;

    SetConsoleInfo( hwndConsole, &ci ); 
  }

  int bx = sx / 12;
  int by = sy / 20;

  SMALL_RECT Rect = { 0, 0, bx, by };
  COORD coord = { bx, by };

  SetConsoleWindowInfo( hConOut, TRUE, &Rect );
  SetConsoleScreenBufferSize( hConOut, coord );

  SetWindowPos( hwndConsole, HWND_TOP, 0, 0, sx-1, sy-1, SWP_NOSIZE );
  ShowWindow( hwndConsole, SW_MAXIMIZE );
}
