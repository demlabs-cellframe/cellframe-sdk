#ifndef CONSOLE_COLOURS
#define CONSOLE_COLOURS

#define TERM_WRAP_FORMAT(code) "\e[" code "m"

#define TERM_FORMATTING_RESET "0"

#define TERM_BOLD "1"
#define TERM_DIM "2"
#define TERM_UNDERLINED "4"
#define TERM_BLINK "5"
#define TERM_INVERT "7"

#define TERM_COLOR_DEFAULT "39"
#define TERM_RED "31"
#define TERM_GREEN "32"
#define TERM_YELLOW "33"
#define TERM_BLUE "34"
#define TERM_MAGENTA "35"
#define TERM_CYAN "36"
#define TERM_LGRAY "37"
#define TERM_DGRAY "90"
#define TERM_LRED "91"
#define TERM_LGREEN "92"
#define TERM_LYELLOW "93"
#define TERM_LBLUE "94"
#define TERM_LMAGENTA "95"
#define TERM_LCYAN "96"
#define TERM_WHITE "97"

#define TERM_256COLOR(code) "\e[38;5;" code "m"

#define TERM_BGCOLOR_DEFAULT "49"
#define TERM_BGBLACK "40"
#define TERM_BGRED "41"
#define TERM_BGGREEN "42"
#define TERM_BGYELLOW "43"
#define TERM_BGBLUE "44"
#define TERM_BGMAGENTA "45"
#define TERM_BGCYAN "46"
#define TERM_BGLGRAY "47"
#define TERM_BGDGRAY "100"
#define TERM_BGLRED "101"
#define TERM_BGLGREEN "102"
#define TERM_BGLYELLOW "103"
#define TERM_BGLBLUE "104"
#define TERM_BGLMAGENTA "105"
#define TERM_BGLCYAN "106"
#define TERM_BGWHITE "107"


#define TERM_256BGCOLOR(code) "\e[48;5;" code "m"

#define CONSOLE_PAINT(COLOR, text) TERM_WRAP_FORMAT(COLOR) text TERM_WRAP_FORMAT(TERM_FORMATTING_RESET) //Multiple codes can be added with semicolon delimiter (";"). Need to specify whether invoked via TTY or otherwise
#define CONSOLE_DESCRIPTION(text) CONSOLE_PAINT(TERM_WHITE";"TERM_BOLD,text)
#define CONSOLE_SYNTAX(text) CONSOLE_PAINT(TERM_COLOR_DEFAULT,text)
#define CONSOLE_DETAILS(text) CONSOLE_PAINT(TERM_DGRAY,text)
#define CONSOLE_EXAMPLE(text) CONSOLE_PAINT(TERM_YELLOW,text)
//#define CONCATENATE_ARGS(...) ";"__VA_ARGS__ ";"
//#define TERM_WRAP_FORMAT_COMPLICATED(...) "\e[" CONCATENATE_ARGS(__VA_ARGS__) "m"
//#define CONSOLE_PAINT_COMPLICATED(text,...) TERM_WRAP_FORMAT_COMPLICATED(__VA_ARGS__) text TERM_WRAP_FORMAT(TERM_FORMATTING_RESET)

#endif
