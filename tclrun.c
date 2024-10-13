#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tcl.h"

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
  return 0;
}
