#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IP_ADDR_LEN_MIN   7 // 1.1.1.1


/* Convert memory dump to hex */
void memdump(char *title, void *buff, size_t len, uint8_t column_n) {
  size_t idx;
  uint8_t *buff_p = (uint8_t *)buff;

  printf("%s: ============== memory dump from 0x%p  [len=%ld]\n", title, buff, len);

  for( idx = 0; idx < len; idx++) {
    if( idx > 0 && idx%column_n == 0)
      printf("\n  ");
    printf("%02x ", *(buff_p + idx));
  }

  printf("\n");
}


char * redirect_to_ip(char *url) {
    // Input URL: "tcp://127.0.0.1:5552"
    int start = 0;
    int end = 0;

    if ( url == NULL )
        return NULL;

    if ( strlen(url) < IP_ADDR_LEN_MIN )
        return NULL;

    //printf("*** %s ***\n", label);
    //printf("Redirect to Srv: %s\n", url);

    for (int i = 0; i < strlen(url); ++i) {
        if ( url[i] >= '0' &&   url[i] <= '9' ) {
            start = i;
            break;
        }
    }

    for (int i = start; i < strlen(url); ++i) {
        if ( url[i] == ':' ) {
            end = i;
            break;
        }
    }

    if ( end > start && (end - start) >= IP_ADDR_LEN_MIN ) {
        char *str = calloc(end - start, 1);

        memcpy(str, url + start, end - start);

        return str;
    } else
        return NULL;
}

// Read at most `n` characters (newline included) into `str`.
// If present, the newline is removed (replaced by the null terminator).
void s_gets(char* str, int n)
{
    char* str_read = fgets(str, n, stdin);
    if (!str_read)
        return;

    int i = 0;
    while (str[i] != '\n' && str[i] != '\0')
        i++;

    if (str[i] == '\n')
        str[i] = '\0';
}