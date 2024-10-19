/*
The MIT License (MIT)

Copyright (c) 2024 Thiadmer Riemersma, CompuPhase

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcl.h"

#if defined FORTIFY
# include "fortify.h"	/* malloc tracking & debugging library */
#endif

int main(int argc,char *argv[])
{
  if (argc!=2) {
    printf("Usage: %s <script>\n",argv[0]);
    return 1;
  }

  /* load the script file as a string */
  FILE *fp=fopen(argv[1],"rt");
  if (!fp) {
    perror("Error reading script file");
    return 1;
  }
  fseek(fp,0L,SEEK_END);
  size_t size=ftell(fp);
  char *script=calloc(size+1,1);  /* +1 for zero-terminator */
  if (!script) {
    perror("Error reading script file: memory allocation error\n");
    return 1;
  }
  fseek(fp,0L,SEEK_SET);
  fread(script,1,size,fp);
  fclose(fp);

  /* run the script */
  struct tcl tcl;
  tcl_init(&tcl,NULL);
  if (tcl_eval(&tcl,script,strlen(script))!=1) {
    struct tcl_value *retval=tcl_return(&tcl);
    printf("Return: %.*s\n",tcl_length(retval),tcl_data(retval));
  } else {
    int line;
    const char *msg=tcl_errorinfo(&tcl,&line);
    printf("Error on or after line %d: %s\n",line,msg);
  }
  tcl_destroy(&tcl);

  free(script);
  fflush(stdout);
# if defined FORTIFY
    printf("----------\n");
    Fortify_CheckAllMemory();
    Fortify_ListAllMemory();
# endif

  return 0;
}
