#include <stdio.h>
//#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ini.h>

#include "../version.h"
#include "nng-common.h"
#include "agent-config.h"

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

const char* logNames[] = { [NNG_LOG_NONE]  = "LOG_OFF",  [NNG_LOG_ERR]  = "LOG_ERR",
                           [NNG_LOG_WARN]  = "LOG_WARN", [NNG_LOG_INFO] = "LOG_INFO",
                           [NNG_LOG_DEBUG] = "LOG_DEBUG"};

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
    srv_conf_t * pconfig = (srv_conf_t *)user;

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
#define MATCH_1(s, n) strcmp(section, s) == 0 && strstr(name, n) != NULL

    if ( MATCH("server", "interface") ) {
        pconfig->start_url = strdup(value);

    } else if ( MATCH("logs", "level") ) {

        if ( strcmp(value, "LOG_OFF") == 0 )
            pconfig->log_level = NNG_LOG_NONE;
        else if ( strcmp(value, "LOG_ERR") == 0 )
            pconfig->log_level = NNG_LOG_ERR;
        else if ( strcmp(value, "LOG_WARN") == 0 )
            pconfig->log_level = NNG_LOG_WARN;
        else if ( strcmp(value, "LOG_INFO") == 0 )
            pconfig->log_level = NNG_LOG_INFO;
        else
            pconfig->log_level = NNG_LOG_DEBUG;

    } else if (MATCH("bash_script", "file")) {
        pconfig->bash_file = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}

static void dump_configuration(const char* conf_file, srv_conf_t *srv_conf) {
    FILE *fp = stdout;

    fprintf(fp, "Config loaded from file \"%s\" \n", conf_file);
    fprintf(fp, "   interface = %s \n", srv_conf->start_url);
    fprintf(fp, "   log level = %s \n", logNames[srv_conf->log_level]);
    fprintf(fp, "   bash file = %s \n", srv_conf->bash_file);
    fprintf(fp, "   run mode  = %s \n",
            ( srv_conf->run_mode == RUN_MODE_NORMAL) ? "Normal" : "Daemon");
}

int init_server_config(int argc, char **argv, srv_conf_t *srv_conf) {

    cmd_t appCmd = {0};

    pars_app_cmd(argc, argv, &appCmd);
    //printf("--- appCmd.confFile  = %s\n", appCmd.confFile);
    //printf("--- appCmd.debugMode = %d\n", appCmd.debugMode);
    srv_conf->run_mode = ( appCmd.debugMode == 1 )? RUN_MODE_NORMAL : RUN_MODE_DAEMON;

    if (ini_parse(appCmd.confFile, config_cb, srv_conf) != 0)
        usage(argv[0], NULL);

    if ( PathFileExists(srv_conf->bash_file) != 0 )
        ini_parsing_error(appCmd.confFile, srv_conf->bash_file);

    dump_configuration(appCmd.confFile, srv_conf);

    return 0;
}