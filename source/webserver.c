// http://beej.us/guide/bgnet/output/html/singlepage/bgnet.html#simpleserver
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __PPU__
#include <net/poll.h>
#elif __PSP__
// PSP: poll is not supported
#else
#include <poll.h>
#endif

#include "dbglogger.h"
#include "systhread.h"
#include "html.h"

#ifdef __PSVITA__
#define IS_DIR(X)     (X->d_stat.st_mode & SCE_S_IFDIR)
#else
#define IS_DIR(X)     (X->d_type == DT_DIR)
#endif

#define BACKLOG         32      // how many pending connections queue will hold
#define NUM_THREADS     4

#define N_ELEMS(x)  (sizeof(x) / sizeof((x)[0]))

typedef struct {
    int idx;
    int sockfd;
    dWebReqHandler_t reqHandler;
    void* usrData;
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

    for(int i = 0; ext && i < length; i++)
        if(!strcasecmp(ext, extensions[i].ext))
            return extensions[i].filetype;

    return extensions[0].filetype;
}

static int urlDecode(char *dStr)
{
    int i, j;
    char hex[] = "00"; /* for a hex code */

    for(i=0, j=0; dStr[i]; i++, j++)
    {
        if(dStr[i] != '%' || dStr[i+1] == 0)
        {
            dStr[j] = dStr[i];
            continue;
        }

        if(isxdigit((int)dStr[i+1]) && isxdigit((int)dStr[i+2]))
        {
            /* combine the next two numbers into one */
            hex[0] = dStr[i+1];
            hex[1] = dStr[i+2];

            /* convert it to decimal */
            dStr[j] = strtol(hex, NULL, 16);
            i += 2; /* move to the end of the hex */
        }
    }
    dStr[j] = 0; /* null terminate the string */

    return (i != j);
}

static void sendResponse(int fd, const char* code, const char* type, long len, const char* page)
{
    char* buf;

    asprintf(&buf, "HTTP/1.0 %s\r\n"
        "Connection: close\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %ld\r\n"
        "Server: dbglogger/1.0 (PlayStation)\r\n\r\n", code, type, len);
    if (send(fd, buf, strlen(buf), 0) == -1)
        dbglogger_log("(error) send");

    if (page && send(fd, page, len, 0) == -1)
        dbglogger_log("(error) send body");

    free(buf);
}

static inline void errorPage(int fd)
{
    sendResponse(fd, "404 Not Found", "text/html", strlen(ERROR_PAGE), ERROR_PAGE);
}

static int serveFile(int socket, const dWebResponse_t* response, char method)
{
    FILE *fd;
    int readRet;
    char buf[BUFSIZ];

    if (response->size)
    {
        sendResponse(socket, "200 OK", getContentType(response->type), response->size, method == 'H' ? NULL : response->data);
        return 200;
    }
        
    if (!response->data || (fd = fopen(response->data, "rb")) == NULL)
    {
        errorPage(socket);
        return 404;
    }
    dbglogger_log("Serving (%s)...", response->data);

    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    // Write header
    sendResponse(socket, "200 OK", getContentType(response->data), fsize, NULL);

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
    *strchr(start, ' ') = 0;

    newRequest->resource = strdup(start);
    urlDecode(newRequest->resource);

    return newRequest;
}

static void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
        return &(((struct sockaddr_in*) sa)->sin_addr);

    return NULL;
}

static void client_process(threadData_t* data)
{
    dWebResponse_t response;
    char buf[BUFSIZ];

    dbglogger_log("Client #%d running (0x%08X)", data->idx, data->sockfd);

    memset(buf, 0, BUFSIZ);
    recv(data->sockfd, buf, BUFSIZ, 0);

    dbglogger_printf("%d>>\n---\n%s\n---\n", data->idx, buf);
    dWebRequest_t *newRequest = parseRequest(buf);

    // If parsing failed shutdown and exit
    if(newRequest)
    {
        memset(&response, 0, sizeof(dWebResponse_t));
        if(data->reqHandler && data->reqHandler(newRequest, &response, data->usrData))
            serveFile(data->sockfd, &response, newRequest->method);
        else
            errorPage(data->sockfd);

        free(response.data);
        free(newRequest->resource);
        free(newRequest);
    }
    else sendResponse(data->sockfd, "501 Not Implemented", "text/plain", 0, NULL);

    shutdown(data->sockfd, SHUT_RDWR);
    close(data->sockfd);
    data->sockfd = -1;
}

static void client_handler(void* td)
{
    threadData_t* data = (threadData_t*) td;

    dbglogger_log("Thread #%d started (0x%08X)", data->idx, data->sockfd);

    while (run_server)
    {
        if (data->sockfd < 0)
        {
            usleep(5000);
            continue;
        }

        client_process(data);
    }

    dbglogger_log("(end) #%d", data->idx);
    sys_thread_exit(0);
}

static void httpd(void *td)
{
    int new_fd;
    threadData_t* data = (threadData_t*) td;
    struct sockaddr_in their_addr; // connector's address
    socklen_t sin_size = sizeof(their_addr);
    char str[INET_ADDRSTRLEN];
#ifndef __PSP__
    struct pollfd pfds[1];

    pfds[0].fd = data->sockfd;
    pfds[0].events = POLLIN;
    pfds[0].revents = 0;
#endif

    dbglogger_log("webserver:%d running (0x%08X)", run_server, data->sockfd);
    while (run_server)
    {
#ifndef __PSP__
        new_fd = poll(pfds, 1, 500);
        if (new_fd <= 0 || !(pfds[0].revents & POLLIN) || !run_server)
            continue;
#endif

        new_fd = accept(data->sockfd, (struct sockaddr*) &their_addr, &sin_size);
        if (new_fd < 0)
        {
            dbglogger_log("(error) accept");
            continue;
        }

        inet_ntop(their_addr.sin_family, get_in_addr((struct sockaddr*) &their_addr), str, sizeof(str));
        dbglogger_printf("httpd #%d: got connection from %s\n", data->idx, str);

#ifdef __PSP__
        data[1].sockfd = new_fd;
        client_process(&data[1]);
#else
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
#endif
    }

    shutdown(data->sockfd, SHUT_RDWR);
    close(data->sockfd);

    dbglogger_log("(stop) httpd");
    free(td);
    sys_thread_exit(0);
}

int dbg_webserver_start(int port, dWebReqHandler_t handler, void* usrdata)
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

    threadData_t *tdata = calloc(NUM_THREADS+1, sizeof(threadData_t));
    tdata[0].sockfd = sockfd;

    sys_thread_create2(threads, 0, &httpd, tdata);

#ifdef __PSP__
    tdata[1].reqHandler = handler;
    tdata[1].usrData = usrdata;
#else
    for (int i = 1; i <= NUM_THREADS; i++)
    {
        tdata[i].idx = i;
        tdata[i].sockfd = -1;
        tdata[i].usrData = usrdata;
        tdata[i].reqHandler = handler;

        sys_thread_create2(threads, i, &client_handler, &tdata[i]);
    }
#endif

    return 1;
}

void dbg_webserver_stop()
{
    void* ret;
    if (!run_server)
        return;

    run_server = 0;
    shutdown(sockfd, SHUT_RDWR);
    close(sockfd);
    sys_thread_join2(threads, 0, &ret);
    sys_thread_free(threads);

    dbglogger_log("webserver:off");
}

int dbg_simpleWebServerHandler(dWebRequest_t* req, dWebResponse_t* res, void* data)
{
    DIR *dir;
    char *tmp;
    struct dirent *d;
    const char *path = req->resource;

    memset(res, 0, sizeof(dWebResponse_t));
#ifdef __PSVITA__
    // on Vita "/" path is a special case, if we are here we
    // have to send the list of devices (aka mountpoints).
    if (strcmp(req->resource, "/") == 0)
    {
        struct stat st;
        const char *devices[] = {
            "gro0:", "grw0:", "imc0:", "os0:", "pd0:", "sa0:", "sd0:", "tm0:",
            "ud0:", "uma0:", "ur0:", "ux0:", "vd0:", "vs0:", "xmc0:", "host0:", NULL };

        snprintf(res->type, sizeof(res->type), ".html");
        asprintf(&res->data, LIST_HEADER, req->resource, req->resource, req->resource);

        for (int i = 0; devices[i]; i++)
        {
            if (stat(devices[i], &st) < 0)
                continue;

            asprintf(&tmp, "%s<li><a href=\"/%s/\" title=\"%s\" class=\"folder\">%s</a></li>", res->data, devices[i], devices[i], devices[i]);
            free(res->data);
            res->data = tmp;
        }
        
        asprintf(&tmp, "%s%s", res->data, LIST_END);
        free(res->data);
        res->data = tmp;
        res->size = strlen(res->data);

        return 1;
    }
    path++;
#endif

    if ((dir = opendir(path)) == NULL)
    {
        res->data = strdup(path);
        return 1;
    }
    dbglogger_log("Listing (%s)...", path);

    snprintf(res->type, sizeof(res->type), ".html");
    asprintf(&res->data, LIST_HEADER, req->resource, req->resource, req->resource);

    while ((d = readdir(dir)) != NULL)
    {
        if (strcmp(d->d_name, ".") == 0)
            continue;

        if (strcmp(d->d_name, "..") == 0)
        {
            size_t len = strlen(req->resource);
            if (len > 1 && req->resource[len-1] == '/')
                strrchr(req->resource, '/')[0] = 0;

            strrchr(req->resource, '/')[0] = 0;
            asprintf(&tmp, "%s<li><a href=\"%s/\" title=\"%s\" class=\"folder\">%s</a></li>", res->data, req->resource, req->resource, d->d_name);

            free(res->data);
            res->data = tmp;
            continue;
        }

        char *ext = strrchr(d->d_name, '.');
        asprintf(&tmp, "%s<li><a href=\"./%s%s\" title=\"%s\" class=\"%s %s\">%s</a></li>", res->data, d->d_name, (IS_DIR(d) ? "/" : ""), d->d_name, (IS_DIR(d) ? "folder" : "file"), (ext ? ext+1 : ""), d->d_name);

        free(res->data);
        res->data = tmp;
    }
    closedir(dir);

    asprintf(&tmp, "%s%s", res->data, LIST_END);
    free(res->data);
    res->data = tmp;
    res->size = strlen(res->data);

    return 1;
}
