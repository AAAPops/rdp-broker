#ifndef _UTILS_H
#define _UTILS_H

#include <stdint.h>

void memdump(char *title, void *buff, size_t len, uint8_t column_n);

void s_gets(char* str, int n);

char * redirect_to_ip(char *url);

#endif