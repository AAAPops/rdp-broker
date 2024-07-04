#include <stdio.h>
//#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <freerdp/freerdp.h>
#include <ini.h>

#include "version.h"
#include "broker-config.h"

/*
[WLOG_DEBUG] = "LOG_DEBUG" --> WLog_DBG()
[WLOG_INFO]  = "LOG_INFO"  --> WLog_INFO()
[WLOG_WARN]  = "LOG_WARN"  --> WLog_WARN()
[WLOG_ERROR] = "LOG_ERR"   --> WLog_ERR()
[WLOG_OFF]   = "LOG_OFF"

[NNG_LOG_DEBUG]  = "LOG_DEBUG" --> nng_log_debug()
[NNG_LOG_INFO]   = "LOG_INFO"  --> nng_log_info()
[NNG_LOG_WARN]   = "LOG_WARN"  --> nng_log_warn()
[NNG_LOG_ERR]    = "LOG_ERR"   --> nng_log_err()
[NNG_LOG_NONE]   = "LOG_OFF"
*/
const char* logNames[] = { [WLOG_DEBUG] = "LOG_DEBUG", [WLOG_INFO]  = "LOG_INFO",
                           [WLOG_WARN]  = "LOG_WARN",  [WLOG_ERROR] = "LOG_ERR",
                           [WLOG_OFF]   = "LOG_OFF"};

typedef struct _cmd {
    const char *confFile;
    int        debugMode;
} cmd_t;


static int PathFileExists(const char *filePath) {

    return  access(filePath, R_OK);
}

static void ini_parsing_error(const char* ini_file_name, const char* invalid) {
    FILE *fp = stdout;

    fprintf(fp, "Error in configuration file \"%s\"\n", ini_file_name);

    fprintf(fp, "...option \"%s\"\n", invalid);

    exit (EXIT_FAILURE);
}

static void usage(const char* app, const char* invalid) {
    FILE *fp = stdout;

    fprintf(fp, "Ver. %s\n", VERSION);

    fprintf(fp, "Usage: %s [-h] [-f /path/to/conf.ini] [-d] \n", app);
    fprintf(fp, "\t -d  - run in foreground debug mode\n");

    if ( invalid != NULL ) {
        fprintf(fp, "\n");
        fprintf(fp, ">>> Error argument: \"%s\"\n", invalid);
        exit (EXIT_FAILURE);
    }

    exit (EXIT_SUCCESS);
}


static int pars_app_cmd(const int argc, char **argv, cmd_t *my_cmd) {

    int c;
    if ( argc == 1 )
        usage(argv[0], NULL);

    while ((c = getopt (argc, argv, "hdf:")) != -1)
        switch (c)
        {
             case 'f':
                my_cmd->confFile = optarg;
                if ( PathFileExists(my_cmd->confFile) != 0 )
                    usage(argv[0], my_cmd->confFile);
                break;
            case 'd':
                my_cmd->debugMode = 1;
                break;
            default:
                usage(argv[0], NULL);
        }

    return 0;
}


static int config_cb(void* user, const char* section, const char* name,
                     const char* value)
{
    errno = 0;
    srv_conf_t *pconfig = (srv_conf_t *)user;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
#define MATCH_1(s, n) strcmp(section, s) == 0 && strstr(name, n) != NULL

    if ( MATCH("server", "interface") ) {
        if ( strcmp(value, "All") == 0 )
            pconfig->interface = NULL;
        else
            pconfig->interface = strdup(value);

    } else if ( MATCH("server", "port") ) {
        pconfig->port = strtol(value, NULL, 10);

        if ((pconfig->port < 1) || (pconfig->port > UINT16_MAX) || (errno != 0))
            return 0;

    } else if ( MATCH("logs", "level") ) {
        //LOG_ERR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_OFF

        if ( strcmp(value, "LOG_OFF") == 0 )
            pconfig->log_level = WLOG_OFF;
        else if ( strcmp(value, "LOG_ERR") == 0 )
            pconfig->log_level = WLOG_ERROR;
        else if ( strcmp(value, "LOG_WARN") == 0 )
            pconfig->log_level = WLOG_WARN;
        else if ( strcmp(value, "LOG_INFO") == 0 )
            pconfig->log_level = WLOG_INFO;
        else
            pconfig->log_level = WLOG_DEBUG;

    } else if ( MATCH("tls", "cert") ) {
        pconfig->cert = strdup(value);

    } else if ( MATCH("tls", "key") ) {
        pconfig->key = strdup(value);

    } else if (MATCH_1("agents", "url-")) {
        pconfig->url_list[pconfig->url_count] = strdup(value);
        pconfig->url_count++;
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


static void dump_configuration(const char* conf_file, srv_conf_t *srv_conf) {
    FILE *fp = stdout;

    fprintf(fp, "Config loaded from \"%s\"\n", conf_file);
    fprintf(fp, "   interface = %s \n", ( srv_conf->interface ) ? srv_conf->interface : "All" );
    fprintf(fp, "   port      = %d \n", srv_conf->port);
    fprintf(fp, "   cert      = %s \n", srv_conf->cert);
    fprintf(fp, "   key       = %s \n", srv_conf->key);
    fprintf(fp, "   run mode  = %s \n",
            ( srv_conf->run_mode == RUN_MODE_NORMAL) ? "Normal" : "Daemon");
    for (int i = 0; i < srv_conf->url_count; ++i) {
        fprintf(fp, "   url[%d]  = %s \n", i, srv_conf->url_list[i]);
    }
    fprintf(fp, "\n");
}

int init_server_config(int argc, char **argv, srv_conf_t *srv_conf) {

    cmd_t appCmd = {0};

    pars_app_cmd(argc, argv, &appCmd);
    //printf("--- appCmd.confFile  = %s\n", appCmd.confFile);
    //printf("--- appCmd.debugMode = %d\n", appCmd.debugMode);
    srv_conf->run_mode = ( appCmd.debugMode == 1 )? RUN_MODE_NORMAL : RUN_MODE_DAEMON;

    if (ini_parse(appCmd.confFile, config_cb, srv_conf) != 0)
        usage(argv[0], NULL);

    if ( PathFileExists(srv_conf->cert) != 0 )
        ini_parsing_error(appCmd.confFile, srv_conf->cert);
    if ( PathFileExists(srv_conf->key) != 0 )
        ini_parsing_error(appCmd.confFile, srv_conf->key);

    dump_configuration(appCmd.confFile, srv_conf);

    return 0;
}