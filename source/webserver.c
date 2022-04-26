// http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#simpleserver
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __PPU__
#include <net/poll.h>
#else
#include <poll.h>
#endif

#include "dbglogger.h"
#include "systhread.h"

#define BACKLOG         32      // how many pending connections queue will hold
#define NUM_THREADS     4

#define N_ELEMS(x)  (sizeof(x) / sizeof((x)[0]))

const char ERROR_PAGE[] = "<HTML><HEAD><TITLE>.:: HTTP/Error</TITLE></HEAD>"
             "<BODY BGCOLOR=\"#FFFFFF\" ALINK=\"#000000\" VLINK=\"#000000\" LINK=\"#000000\">"
             "<FONT FACE=\"Arial\"><H1>.:: <I>HTTP/Error</I></H1></FONT>"
             "<CENTER><IMG SRC=\"https://bucanero.github.io/bucanero/error.gif\" WIDTH=\"228\" HEIGHT=\"155\" BORDER=\"0\" ALT=\"Error\"></CENTER>"
             "<P ALIGN=\"RIGHT\"><B><FONT FACE=\"Arial\" SIZE=\"3\">&lt;&lt; <A HREF=\"javascript:history.go(-1);\">go back</A> ::.</FONT></B></P></BODY></HTML>\r\n";

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
    {".gif", "image/gif"},
    {".jpg", "image/jpeg"},
    {".xml", "application/xml"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".json", "application/json"}
};

static void* threads = NULL;
static int run_server = 0;
static int sockfd;


static char* getContentType(const char *path)
{
    char *ext = strrchr(path, '.');
    int length = N_ELEMS(extensions);

    for(int i = 0; i < length; i++)
        if(!strcmp(ext, extensions[i].ext))
            return extensions[i].filetype;

    return extensions[0].filetype;
}

static void sendResponse(int fd, char* buf, const char* code, const char* type, long len, const char* page)
{
    snprintf(buf, BUFSIZ, "HTTP/1.0 %s\r\n"
        "Connection: close\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: dbglogger/1.0 (PlayStation)\r\n\r\n%s", code, type, len, page ? page : "");
    if (send(fd, buf, strlen(buf), 0) == -1)
        dbglogger_log("(error) send");
}

static inline void errorPage(int fd, char* buf)
{
    sendResponse(fd, buf, "404 Not Found", "text/html", strlen(ERROR_PAGE), ERROR_PAGE);
}

static int serveFile(int socket, const char* path, char method)
{
    FILE *fd;
    int readRet = strlen(path);
    char buf[BUFSIZ];

    dbglogger_log("Serving (%s)...", path);

    if ((readRet > 0 && path[readRet-1] == '/') || (fd = fopen(path, "rb")) == NULL)
    {
        errorPage(socket, buf);
        return 404;
    }

    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // Write header
    sendResponse(socket, buf, "200 OK", getContentType(path), fsize, NULL);

    // skip data for HEAD method
    if (method == 'H') {
        fclose(fd);
        return 200;
    }

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

static dWebRequest_t * parseRequest(const char *start)
{
    dWebRequest_t *newRequest;
    const char *end;

    if(strncmp("GET", start, 3) != 0 && strncmp("HEAD", start, 4) != 0)
    {
        dbglogger_log("[!] Unsupported HTTP Method");
        return NULL;
    }

    newRequest = malloc(sizeof(dWebRequest_t));
    memset(newRequest, 0, sizeof(dWebRequest_t));

    newRequest->method = start[0];
    // Jump past: "GET "
    start = strchr(start, ' ') + 1;
    end = strchr(start, ' ');

    strncpy(newRequest->resource, start, end - start);
//    newRequest->resource[pathLen] = '\0';

    return newRequest;
}

static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*) sa)->sin_addr);

    return NULL;
}

static void client_handler(void* td)
{
    threadData_t* data = (threadData_t*) td;
    char buf[BUFSIZ];

    dbglogger_printf("Thread #%d started (0x%08X)\n", data->idx, data->sockfd);

    while (run_server)
    {
        if (data->sockfd < 0)
        {
            usleep(5000);
            continue;
        }

        dbglogger_printf("Client #%d running (0x%08X)\n", data->idx, data->sockfd);

        memset(buf, 0, BUFSIZ);
        recv(data->sockfd, buf, BUFSIZ, 0);

        dbglogger_printf("%d>>\n---\n%s\n---\n", data->idx, buf);
        dWebRequest_t *newRequest = parseRequest(buf);

        // If parsing failed shutdown and exit
        if(newRequest)
        {
            if(data->reqHandler && data->reqHandler(newRequest, buf))
                serveFile(data->sockfd, buf, newRequest->method);
            else
                errorPage(data->sockfd, buf);

            free(newRequest);
        }
        else sendResponse(data->sockfd, buf, "501 Not Implemented", "text/plain", 0, NULL);

        shutdown(data->sockfd, SHUT_RDWR);
        close(data->sockfd);
        data->sockfd = -1;
    }

    dbglogger_log("(end) #%d", data->idx);
    sys_thread_exit(0);
}

static void httpd(void *td)
{
    int new_fd;
    threadData_t* data = (threadData_t*) td;
    struct pollfd pfds[1];
    struct sockaddr_in their_addr; // connector's address
    socklen_t sin_size = sizeof(their_addr);
    char str[INET_ADDRSTRLEN];

    pfds[0].fd = data->sockfd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;

    while (run_server)
    {
        dbglogger_log("webserver:%d running (0x%08X)", run_server, data->sockfd);

        new_fd = poll(pfds, 1, 500);
        if (new_fd <= 0 || !(pfds[0].revents & POLLIN) || !run_server)
            continue;

        new_fd = accept(data->sockfd, (struct sockaddr*) &their_addr, &sin_size);
        if (new_fd < 0)
        {
            dbglogger_log("(error) accept");
            continue;
        }

        inet_ntop(their_addr.sin_family, get_in_addr((struct sockaddr*) &their_addr), str, sizeof(str));
        dbglogger_printf("httpd #%d: got connection from %s\n", data->idx, str);

        while (new_fd)
        {
            for (int i=1; new_fd && i <= NUM_THREADS; i++)
                if (data[i].sockfd < 0)
                {
                    data[i].sockfd = new_fd;
                    new_fd = 0;
                }
            usleep(new_fd ? 1000 : 0);
        }
    }

    shutdown(data->sockfd, SHUT_RDWR);
    close(data->sockfd);

    dbglogger_log("(stop) httpd");
    free(td);
    sys_thread_exit(0);
}

int web_start(int port, dWebReqHandler_t handler)
{
    int yes = 1;
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

    if ((threads = sys_thread_alloc(NUM_THREADS+1)) == NULL) {
        dbglogger_log("(error) thread alloc");
        return 0;
    }

    run_server = port;
    dbglogger_log("webserver:%d starting httpd...", port);

    threadData_t *tdata = malloc(sizeof(threadData_t) * (NUM_THREADS+1));
    tdata[0].idx = 0;
    tdata[0].sockfd = sockfd;
    tdata[0].reqHandler = NULL;

    sys_thread_create2(threads, 0, &httpd, tdata);

    for (int i = 1; i <= NUM_THREADS; i++)
    {
        tdata[i].idx = i;
        tdata[i].sockfd = -1;
        tdata[i].reqHandler = handler;

        sys_thread_create2(threads, i, &client_handler, &tdata[i]);
    }

    return 1;
}

void web_stop()
{
    if (!run_server)
        return;

    run_server = 0;
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    sys_thread_free(threads);

    dbglogger_log("webserver:off");
}
