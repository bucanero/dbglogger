/* Now double buffered with animation.
 */ 

#include <ppu-lv2.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sysutil/video.h>
#include <rsx/gcm_sys.h>
#include <rsx/rsx.h>

#include <io/pad.h>
#include <dbglogger.h>
#include "rsxutil.h"

#define MAX_BUFFERS 2

void drawFrame(rsxBuffer *buffer, long frame) {
  s32 i, j;
  for(i = 0; i < buffer->height; i++) {
    s32 color = (i / (buffer->height * 1.0) * 256);
    // This should make a nice black to green graident
    color = (color << 8) | ((frame % 255) << 16);
    for(j = 0; j < buffer->width; j++)
      buffer->ptr[i* buffer->width + j] = color;
  }
}

int handleGet(const dWebRequest_t *request, char* fpath)
{
    snprintf(fpath, BUFSIZ, "/dev_hdd0/tmp%s", request->resource);
    dbglogger_log("Handle %s: %s -> %s", request->method, request->resource, fpath);
    return 1;
}

int main(s32 argc, const char* argv[])
{
  gcmContextData *context;
  void *host_addr = NULL;
  rsxBuffer buffers[MAX_BUFFERS];
  int currentBuffer = 0;
  padInfo padinfo;
  padData paddata;
  u16 width;
  u16 height;
  int i;

/* 
* By default the logger will send debug messages to UDP multicast address 239.255.0.100:30000. 
* To receive them you can use socat on your PC:
* $ socat udp4-recv:30000,ip-add-membership=239.255.0.100:0.0.0.0 -
*/
  
  dbglogger_init();  
  dbglogger_log("If you see this you've set up dbglogger correctly.");

// Other initialization options:
//
//    dbglogger_init_str("file:/dev_hdd0/tmp/libdebug.log");
//    dbglogger_init_mode(TCP_LOGGER, "192.168.1.123", 18999);
//    dbglogger_init_str("tcp:192.168.1.123:18999");  

  web_start(8099, &handleGet);

  /* Allocate a 1Mb buffer, alligned to a 1Mb boundary                          
   * to be our shared IO memory with the RSX. */
  host_addr = memalign (1024*1024, HOST_SIZE);
  context = initScreen (host_addr, HOST_SIZE);
  ioPadInit(7);

  getResolution(&width, &height);
  for (i = 0; i < MAX_BUFFERS; i++)
    makeBuffer( &buffers[i], width, height, i);

  flip(context, MAX_BUFFERS - 1);

  long frame = 0; // To keep track of how many frames we have rendered.
	
  // Ok, everything is setup. Now for the main loop.
  while(1){
    // Check the pads.
    ioPadGetInfo(&padinfo);
    for(i=0; i<MAX_PADS; i++){
      if(padinfo.status[i]){
        ioPadGetData(i, &paddata);

          if (paddata.BTN_TRIANGLE) {
            // save a PNG screenshot without alpha channel in '/dev_hdd0/tmp/screenshot_YYYY_MM_DD_HH_MM_SS.png'
            dbglogger_log("Saving a screenshot to /dev_hdd0/tmp/ ...");
            dbglogger_screenshot_tmp(0);
          }

          if(paddata.BTN_START){
              web_stop();
            goto end;
          }
        }
    }

    waitFlip(); // Wait for the last flip to finish, so we can draw to the old buffer
    drawFrame(&buffers[currentBuffer], frame++); // Draw into the unused buffer
    flip(context, buffers[currentBuffer].id); // Flip buffer onto screen

    currentBuffer++;
    if (currentBuffer >= MAX_BUFFERS)
      currentBuffer = 0;
  }
  
 end:

  gcmSetWaitFlip(context);
  for (i = 0; i < MAX_BUFFERS; i++)
    rsxFree(buffers[i].ptr);

  rsxFinish(context, 1);
  free(host_addr);
  ioPadEnd();

  // close debug logger
  dbglogger_stop();
	
  return 0;
}
