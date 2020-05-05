/** @file 
 * @brief Реализация функций вывода информации на экран
 *
 * @copyright InfoTeCS. All rights reserved.
 */

#include <memory.h>
#include <string.h>
#include <stdio.h>
#include "print_data.h"

int PrintTest(const char* caption, int result)
{
     const char ok[] = "OK.";
     const char failed[] = "FAILED.";
     char line[LINE_WIDTH] = "";
     const char * testResult;
     
     memset(line, ' ', LINE_WIDTH-1);
     line[LINE_WIDTH-1] = '\0';
     
     testResult = result ? failed : ok; 

     memcpy(line, caption, strlen(caption));
     memcpy(line + LINE_WIDTH - strlen(testResult) - 1, testResult, strlen(testResult));

     PrintLine(line);
     PrintSplitLine();
     return result;
}

void PrintCharSingle(char c)
{
     printf("%c", c);
}

void PrintChar(char c, size_t count)
{
     size_t i;
     for(i = 0; i < count; ++i)
     {
          PrintCharSingle(c);
     }
}

void PrintStr(const char* s)
{
     printf("%s", s);
}

void PrintStrAlign(const char* s, size_t width)
{
     size_t len = strlen(s);
     
     PrintStr(s);

     if(len < width)
     {
          PrintChar(' ', width - len);
     }
}

void PrintBlockLeft(const char* label, unsigned int d)
{
     PrintChar(' ', TAB_WIDTH);
     PrintStr(label);
     PrintUInt32(d);
     PrintEmptyLine();
}

void PrintLineLeft(const char* label)
{
     PrintChar(' ', TAB_WIDTH);
     PrintStr(label);
     PrintEmptyLine();
}

void PrintLine(const char* line)
{
     PrintStr(line);
     PrintEmptyLine();
}

void PrintEmptyLine()
{
     printf("\n");
}

void PrintSplitLine()
{

     PrintChar('-', LINE_WIDTH);
     PrintEmptyLine();
}

void PrintLabel(const char* label)
{
     PrintSplitLine();
     PrintLine(label);
     PrintEmptyLine();
}


void PrintHex(unsigned char value)
{
     unsigned char a, b , c;

     a = (value & 0xf0) >> 4;
     c = a < 0xa ? a + 48 : a + 87;
     PrintCharSingle(c);

     b = (value & 0x0f);
     c = b < 0xa ? b + 48 : b + 87;
     PrintCharSingle(c);
}

void PrintHexArray(unsigned char* value, size_t size)
{
     size_t i;

     for(i = 0; i < size; ++i)
     {
          PrintHex(value[i]);
     }
}

void PrintUInt32(unsigned int d)
{
     printf("%x", d);
}

void PrintBlockInt(const char* label, unsigned int value)
{
     PrintChar(' ', TAB_WIDTH);
     PrintStrAlign(label, LINE_WIDTH - TAB_WIDTH - 8);
     PrintUInt32(value);
     PrintEmptyLine();
}

void PrintBlock(const char* label, unsigned char* value, size_t valueSize, size_t blockSize)
{
     unsigned char a, b, c;
     size_t width, tab; 
     size_t j, i;

     width = LINE_WIDTH;
     tab = TAB_WIDTH;

     PrintChar(' ', tab);
     PrintStrAlign(label, width - tab - (blockSize*2));
     PrintHexArray(value, blockSize > valueSize ? valueSize : blockSize);
     PrintEmptyLine();

     for(j = 1; j < valueSize / blockSize; ++j)
     {
          PrintChar(' ', width-(blockSize*2));

          for(i = 0; i < blockSize; ++i)
          {
               a = (value[ j * blockSize + i] & 0xf0) >> 4;
               c = a < 0xa ? a + 48 : a + 87;
               PrintCharSingle(c);

               b = (value[ j * blockSize + i] & 0x0f);
               c = b < 0xa ? b + 48 : b + 87;
               PrintCharSingle(c);
          }
          PrintEmptyLine();
     }
}

void DLL_IMPORT print_array(const char* label, unsigned char* value, unsigned int valueSize)
{
     unsigned int i;

     printf("%s ", label);

     for(i = 0; i < valueSize; ++i)
     {
          printf("%02x", value[i]);
     }

     printf("\n");
}

void DLL_IMPORT print_uint_array(const char* label, unsigned int* value, unsigned int valueSize)
{
     unsigned int i;

     printf("%s ", label);

     for(i = 0; i < valueSize; ++i)
     {
          printf("%08x", value[i]);
     }

     printf("\n");
}
