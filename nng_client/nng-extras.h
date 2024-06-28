#ifndef _NNG_EXTTRAS_H
#define _NNG_EXTTRAS_H

void nng_fatal(const char *func, int rv);
void nng_err(const char *func, int rv);

int nng_msg_append_str(nng_msg *msg, char *str);

char * nng_msg_trim_str(nng_msg *msg);


#endif