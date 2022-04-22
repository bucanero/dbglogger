// http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#simpleserver
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "dbglogger.h"
#include "systhread.h"

#define BACKLOG         32      // how many pending connections queue will hold
#define NUM_THREADS     4

#define N_ELEMS(x)  (sizeof(x) / sizeof((x)[0]))

const char ERROR_PAGE[] = "<HTML><HEAD><TITLE>.:: HTTP/Error</TITLE></HEAD>"
             "<BODY BGCOLOR=\"#FFFFFF\" ALINK=\"#000000\" VLINK=\"#000000\" LINK=\"#000000\">"
             "<FONT FACE=\"Arial\"><H1>.:: <I>HTTP/Error</I></H1></FONT>"
             "<CENTER><IMG SRC=\"https://bucanero.github.io/bucanero/error.gif\" WIDTH=\"228\" HEIGHT=\"155\" BORDER=\"0\" ALT=\"Error\"></CENTER>"
             "<P ALIGN=\"RIGHT\"><B><FONT FACE=\"Arial\" SIZE=\"3\">&lt;&lt; <A HREF=\"javascript:history.go(-1);\">go back</A> ::.</FONT></B></P></BODY></HTML>";

typedef struct {
    int idx;
    int sockfd;
    dWebReqHandler_t reqHandler;
} threadData_t;


static struct { 
    char *ext;
    char *filetype;
} extensions[] = {
    {".zip", "application/octet-stream"},
    {".html", "text/html"},
    {".txt", "text/plain"},
    {".png", "image/png"},
    {".PNG", "image/png"},
    {".jpg", "image/jpeg"},
    {".xml", "application/xml"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"}
};

static void* threads = NULL;
static int run_server = 0;

static char* getContentType(const char *path)
{
    char *ext = strrchr(path, '.');
    int length = N_ELEMS(extensions);

    for(int i = 0; i < length; i++)
        if(!strcmp(ext, extensions[i].ext))
            return extensions[i].filetype;

    return extensions[0].filetype;
}

static int serveFile(int socket, const char* path)
{
    FILE *fd;
    int readRet = strlen(path);
    char buf[BUFSIZ];

    dbglogger_log("Serving (%s)...", path);

    if ((readRet > 0 && path[readRet-1] == '/') || (fd = fopen(path, "rb")) == NULL)
    {
        snprintf(buf, BUFSIZ, "HTTP/1.0 404 Not Found\r\nContent-Type: text/html\r\n\r\n%s\r\n", ERROR_PAGE);
        if (send(socket, buf, strlen(buf), 0) == -1)
            dbglogger_log("(error) send");

        return 404;
    }

    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // Write header
    snprintf(buf, BUFSIZ, "HTTP/1.0 200 OK\r\nContent-Length: %ld\r\n"
        "Content-Type: %s\r\nServer: dbglogger\r\n\r\n", fsize, getContentType(path));
    send(socket, buf, strlen(buf), 0);

    // Read file and Write to body
    while((readRet = fread(buf, 1, BUFSIZ, fd)) > 0)
    {
        if (send(socket, buf, readRet, 0) == -1) {
            dbglogger_log("(error) send");
            break;
        }
    }

    fclose(fd);
    dbglogger_log("Sent OK");

    return 200;
}

static dWebRequest_t * parseRequest(const char *buf)
{
    dWebRequest_t *newRequest;
    const char *start = buf;
    const char *end;

    if(strncmp("GET", start, 3) != 0)
    {
        dbglogger_log("[!] Unsupported HTTP Method");
        return NULL;
    }

    newRequest = malloc(sizeof(dWebRequest_t));
    memset(newRequest, 0, sizeof(dWebRequest_t));

    strncpy(newRequest->method, "GET", sizeof(newRequest->method));
    // Jump past: "GET "
    start += 4;

    end=start;
    while(*end && !isspace(*end))
        ++end;

    size_t pathLen = (end - start);
    strncpy(newRequest->resource, start, pathLen);
//    newRequest->resource[pathLen] = '\0';

    return newRequest;
}

static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*) sa)->sin_addr);

    return NULL;
}

static void thread_handler(void* td)
{
    int new_fd;
    threadData_t* data = (threadData_t*) td;
    struct sockaddr_in their_addr; // connector's address
    socklen_t sin_size = sizeof(their_addr);
    char buf[BUFSIZ];

    while (run_server)
    {
        dbglogger_printf("Thread #%d running (0x%08X)\n", data->idx, data->sockfd);

        new_fd = accept(data->sockfd, (struct sockaddr*) &their_addr, &sin_size);
        if (new_fd == -1 || !run_server)
        {
            dbglogger_log("(error) accept");
            free(td);
            sys_thread_exit(0);
        }

        inet_ntop(their_addr.sin_family, get_in_addr((struct sockaddr*) &their_addr), buf, sizeof(buf));
        dbglogger_printf("Thread #%d: got connection from %s\n", data->idx, buf);

        memset(buf, 0, BUFSIZ);
        recv(new_fd, buf, BUFSIZ, 0);

        dbglogger_printf("---\n%s\n---\n", buf);
        dWebRequest_t *newRequest = parseRequest(buf);

        // If parsing failed shutdown and exit
        if(newRequest)
        {
            if(data->reqHandler && data->reqHandler(newRequest, buf))
                serveFile(new_fd, buf);

            free(newRequest);
        } 

        close(new_fd);
    }

    dbglogger_log("(end)");
    free(td);
    sys_thread_exit(0);
}

int web_start(int port, dWebReqHandler_t handler)
{
    int sockfd, yes = 1;
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int)) == -1) {
        dbglogger_log("(error) setsockopt");
//        return 0;
    }

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
        close(sockfd);
        dbglogger_log("(error) server:bind");
        return 0;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        dbglogger_log("(error) listen");
        return 0;
    }

    if ((threads = sys_thread_alloc(NUM_THREADS)) == NULL) {
        dbglogger_log("(error) thread alloc");
        return 0;
    }

    run_server = port;
    dbglogger_log("webserver:%d starting threads...", port);

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        threadData_t *tdata = malloc(sizeof(threadData_t));
        tdata->idx = i;
        tdata->sockfd = sockfd;
        tdata->reqHandler = handler;

        sys_thread_create2(threads, i, &thread_handler, tdata);
    }

    dbglogger_log("webserver:%d running", port);
    return 1;
}

static void end_socket(int port)
{
    struct sockaddr_in stSockAddr;
    int socketFD = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    memset(&stSockAddr, 0, sizeof(stSockAddr));
    stSockAddr.sin_family = AF_INET;
    stSockAddr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &stSockAddr.sin_addr);

    connect(socketFD, (struct sockaddr *)&stSockAddr, sizeof(stSockAddr));
    close(socketFD);
}

void web_stop()
{
    int port = run_server;
    run_server = 0;

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        dbglogger_log("stop %d", i);
        end_socket(port);
    }

    sys_thread_free(threads);
}
