#ifdef __PS4__
#pragma message("PS4: debug screenshot is not supported.")
#else
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/memory.h>
#include <rsx/gcm_sys.h>

#include "dbglogger.h"
#include "svpng.h"

#define BASE          0xC0000000UL      // local memory base ea

// get pixel offset into framebuffer by x/y coordinates
#define OFFSET(x, y) ((((uint32_t)offset) + ((((int16_t)x) + \
                     (((int16_t)y) * (((uint32_t)pitch) / \
                     ((int32_t)4)))) * ((int32_t)4))) + (BASE))


/***********************************************************************
*
* game screenshot
*
***********************************************************************/
int dbglogger_screenshot(const char *path, const unsigned char alpha)
{
    uint32_t offset = 0, pitch = 0;
    FILE *fd = NULL;
    uint8_t id;
    const gcmDisplayInfo *info = gcmGetDisplayInfo();
    
    gcmGetCurrentDisplayBufferId(&id);
    if (!info[id].offset) {
      return(0);
    }
    
    // create png file
    fd = fopen(path, "wb");
    if (!fd) {
        return(0);
    }    

    // access screen memory buffer
    offset = info[id].offset;
    pitch = info[id].pitch;
    uint8_t *screen_buf = (uint8_t*)(OFFSET(0, 0));

    // save dump as PNG
    svpng(fd, info[id].width, info[id].height, screen_buf, alpha);
    fclose(fd);

    return(1);
}


int dbglogger_screenshot_tmp(const unsigned char alpha) {
    char sfile[64];
    struct tm t = *gmtime(&(time_t){time(NULL)});

    // build file path (screenshots will be placed in /dev_hdd0/tmp/ folder)
    sprintf(sfile, "/dev_hdd0/tmp/screenshot_%d_%02d_%02d_%02d_%02d_%02d.png", t.tm_year+1900, t.tm_mon+1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    
    return(dbglogger_screenshot(sfile, alpha));
}
#endif
