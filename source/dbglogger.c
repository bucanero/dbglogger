/* 
 *
 *   DBGLOGGER - debug logger library / (c) 2019 El Bucanero  <www.bucanero.com.ar>
 *
 *   Small library for network and local file debug logging in PSL1GHT/Open Orbis SDKs.
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef __PS4__
#include <arpa/inet.h>
#define netConnect        connect
#define netClose          close
#define netSend           send
#define netSocket         socket
#define netInitialize(...)
#define netDeinitialize(...)
#else
#include <net/net.h>
#include <sys/thread.h>
#include <lv2/process.h>
#endif

#include <netinet/in.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>

#include "dbglogger.h"

typedef enum {
    ENCODE_BASE64,
    ENCODE_UUENCODE
} B64ENC_MODES;

static int loggerMode = NO_LOGGER;
static int socketFD;
static char logFile[256];

#define UDP_INI_STR         "udp"
#define TCP_INI_STR         "tcp"
#define FILE_INI_STR        "file"
#define DEBUG_PORT          18194
#define B64_SRC_BUF_SIZE    45  // This *MUST* be a multiple of 3
#define B64_DST_BUF_SIZE    4 * ((B64_SRC_BUF_SIZE + 2) / 3)


static const char encode_table[2][65] = {
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    "`!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"};

/*
 *  Copyright (C) 2000 by Glenn McGrath
 *
 *  based on the function base64_encode from http.c in wget v1.6
 *  Copyright (C) 1995, 1996, 1997, 1998, 2000 Free Software Foundation, Inc.
 *
 * Encode the string S of length LENGTH to base64 format and place it
 * to STORE.  STORE will be 0-terminated, and must point to a writable
 * buffer of at least 1+BASE64_LENGTH(length) bytes.
 * where BASE64_LENGTH(len) = (4 * ((LENGTH + 2) / 3))
 */
static void uuencode(const unsigned char *s, const char *store, const int length, const char *tbl)
{
    int i;
    unsigned char *p = (unsigned char *)store;

    /* Transform the 3x8 bits to 4x6 bits, as required by base64.  */
    for (i = 0; i < length; i += 3) {
        *p++ = tbl[s[0] >> 2];
        *p++ = tbl[((s[0] & 0x03) << 4) + (s[1] >> 4)];
        *p++ = tbl[((s[1] & 0x0f) << 2) + (s[2] >> 6)];
        *p++ = tbl[s[2] & 0x3f];
        s += 3;
    }
    /* Pad the result if necessary...  */
    if (i == length + 1) {
        *(p - 1) = tbl[64];
    }
    else if (i == length + 2) {
        *(p - 1) = *(p - 2) = tbl[64];
    }
    /* ...and zero-terminate it.  */
    *p = '\0';
}

static int dbglogger_base64(const char *filename, const unsigned int encode)
{
    FILE *src_stream;
    size_t size;
    unsigned char *src_buf;
    char *dst_buf;

    src_stream = fopen(filename, "rb");
    if (!src_stream) {
        return(0);
    }
    src_buf = malloc(B64_SRC_BUF_SIZE + 1);
    dst_buf = malloc(B64_DST_BUF_SIZE + 1);

    dbglogger_printf("begin%s %o %s", encode == ENCODE_UUENCODE ? "" : "-base64", 0644, strrchr(filename, '/')+1);
    while ((size = fread(src_buf, 1, B64_SRC_BUF_SIZE, src_stream)) > 0) {
        if (size != B64_SRC_BUF_SIZE) {
            /* pad with 0s so we can just encode extra bits */
            memset(&src_buf[size], 0, B64_SRC_BUF_SIZE - size);
        }
        /* Encode the buffer we just read in */
        uuencode(src_buf, dst_buf, size, encode_table[encode]);

        switch (encode) {
            case ENCODE_BASE64:
                dbglogger_printf("\n%s", dst_buf);
                break;
            case ENCODE_UUENCODE:
                dbglogger_printf("\n%c%s", encode_table[encode][size], dst_buf);
                break;
        }
    }
    dbglogger_printf(encode == ENCODE_UUENCODE ? "\n`\nend\n" : "\n====\n");

    free(src_buf);
    free(dst_buf);
    fclose(src_stream);
    return(1);
}

int dbglogger_b64encode(const char *filename)
{
    return dbglogger_base64(filename, ENCODE_BASE64);
}

#ifdef __PPU__
// check if we receive a connection and kill the process
static void debug_netkill_thread(void *port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    
    sa.sin_family = AF_INET;
    sa.sin_port = htons(strtoul(port, NULL, 0));
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    
    int list_s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if ((bind(list_s, (struct sockaddr *)&sa, sizeof(sa)) == -1) || (listen(list_s, 4) == -1))
    {
        return;
    }
    
    while(accept(list_s, NULL, NULL) <= 0)
    {
        usleep(1000*1000);
    }
    
    shutdown(list_s, SHUT_RDWR);
    dbglogger_stop();
    sysProcessExit(1);
}

// check if the file exists and kill the process
static void debug_kill_thread(void* path)
{
    struct stat sb;

    while ((stat((char*) path, &sb) != 0) || !S_ISREG(sb.st_mode))
    {
        usleep(1000*1000);
    }

    chmod((char*) path, 0777);
    sysLv2FsUnlink((char*) path);
    dbglogger_stop();
    sysProcessExit(1);
}

int dbglogger_failsafe(const char* fpath)
{
    sys_ppu_thread_t tid;

    return sysThreadCreate(&tid, (fpath[0] == '/' ? debug_kill_thread : debug_netkill_thread), (void*) fpath, 1000, 16*1024, THREAD_JOINABLE, "debug_wait");
}
#endif

static void networkInit(const char* dbglog_ip, const unsigned short dbglog_port) {
    struct sockaddr_in stSockAddr;

    memset(&stSockAddr, 0, sizeof(stSockAddr));
    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(dbglog_port);
    inet_pton(AF_INET, dbglog_ip, &stSockAddr.sin_addr);

    netConnect(socketFD, (struct sockaddr *)&stSockAddr, sizeof(stSockAddr));
}

static int logFileInit(const char* file_path) {
    snprintf(logFile, sizeof(logFile), "%s", file_path);
    FILE *fp = fopen(logFile, "a");
    
    if (fp) {
        fclose(fp);
    } else {
        loggerMode = NO_LOGGER;
    }
    return(loggerMode);
}

static void fileLog(const char* str) {
    FILE *fp = fopen(logFile, "a");
    
    if (fp) {
        fputs(str, fp);
        fclose(fp);
    }
}

void dbglogger_printf(const char* fmt, ...) {
    if (loggerMode) {
        char buffer[0x800];
        va_list arg;
        va_start(arg, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, arg);
        va_end(arg);
    
        switch (loggerMode) {
            case UDP_LOGGER:
            case TCP_LOGGER:
                netSend(socketFD, buffer, strlen(buffer), 0);
                break;

            case FILE_LOGGER:
                fileLog(buffer);
                break;
        }
    }
}

void dbglogger_log(const char* fmt, ...) {
    if (loggerMode) {
        char buffer[0x800];

        va_list arg;
        va_start(arg, fmt);
        vsnprintf(buffer, sizeof(buffer), fmt, arg);
        va_end(arg);
    
        struct tm t = *gmtime(&(time_t){time(NULL)});
    
        dbglogger_printf("[%d-%02d-%02d %02d:%02d:%02d] %s\n", t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, buffer);
    }
}

int dbglogger_init_mode(const unsigned char log_mode, const char* dest, const unsigned short port) {
    loggerMode = log_mode;
    switch (log_mode) {
        case UDP_LOGGER:
            netInitialize();
            socketFD = netSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            networkInit(dest, port);
            dbglogger_log("------ UDP (%s:%d) network debug logger initialized -----", dest, port);
            break;

        case TCP_LOGGER:
            netInitialize();
            socketFD = netSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            networkInit(dest, port);
            dbglogger_log("------ TCP (%s:%d) network debug logger initialized -----", dest, port);
            break;

        case FILE_LOGGER:
            if (logFileInit(dest))
                dbglogger_log("----- File (%s) debug logger initialized -----", dest) ;
            break;

        default:
            loggerMode = NO_LOGGER;
            // Logging disabled
            break;
    }
    
    return(loggerMode);
}

int dbglogger_init_str(const char* ini_str) {
    char str[128];    
    strcpy(str, ini_str);

    char *mode = strtok(str, ":");
    char *data = strtok(NULL, ":");
    char *tmp  = strtok(NULL, ":");
    unsigned short port = DEBUG_PORT;
        
    if (tmp)
        port = strtoul(tmp, NULL, 0);
    
    if (strcmp(mode, UDP_INI_STR) == 0) {
        return dbglogger_init_mode(UDP_LOGGER, data, port);
    } else 
    if (strcmp(mode, TCP_INI_STR) == 0) {
        return dbglogger_init_mode(TCP_LOGGER, data, port);
    } else 
    if (strcmp(mode, FILE_INI_STR) == 0) {
        return dbglogger_init_mode(FILE_LOGGER, data, 0);
    }
    
    return(NO_LOGGER);
}

int dbglogger_init_file(const char* ini_file) {
    char str[128];
    FILE *fp = fopen(ini_file, "r");
    
    if (fp) {
        fgets(str, sizeof(str), fp);
        fclose(fp);
        return(dbglogger_init_str(str));
    }
    return(NO_LOGGER);
}

int dbglogger_init(void) {
    return(dbglogger_init_str(DEFAULT_LOG_INIT));
}

int dbglogger_stop(void) {
    switch (loggerMode) {
        case UDP_LOGGER:
        case TCP_LOGGER:
            dbglogger_log("------ network debug logger terminated -----");
            netClose(socketFD);
            netDeinitialize();
            break;

        case FILE_LOGGER:
            dbglogger_log("------ file debug logger terminated -----");
            break;

        default:
            // Logging disabled
            break;
    }    
    loggerMode = NO_LOGGER;
    return(loggerMode);
}
