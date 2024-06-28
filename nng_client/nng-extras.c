#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nng/nng.h>


void
nng_fatal(const char *func, int rv)
{
    fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
    exit(1);
}

void
nng_err(const char *func, int rv)
{
    fprintf(stderr, "%s: %s\n", func, nng_strerror(rv));
}


int nng_msg_append_str(nng_msg *msg, char *str) {
    int rv;

    size_t str_sz = strlen(str) + 1;

    if ((rv = nng_msg_append(msg, str, str_sz)) != 0) {
        return rv;
    }

    return 0;
}


char * nng_msg_trim_str(nng_msg *msg) {

    size_t msg_len = nng_msg_len(msg);
    char   *msg_ptr = (char *)nng_msg_body(msg);

    size_t  str_sz = 0;
    uint8_t zstring = 0;

    for (size_t i = 0; i < msg_len; i++) {
        if ( msg_ptr[i] == 0 ) {
            if ( i == 0 )
                return NULL;

            zstring = 1;
            str_sz++;
            break;
        }

        str_sz++;
    }

    if ( zstring != 1 )
        return NULL;

    char *new_str = malloc(str_sz);

    strcpy(new_str, msg_ptr);

    if ( nng_msg_trim(msg, str_sz) != 0) {
        return NULL;
    }


    return new_str;
}