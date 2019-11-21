#include "main.h"

void* server_acceptthread(void *arg);
void* server_recvthread(void *arg);
void server_setsock(int sock);
int server_getsock(void);
void server_setconn(int conn);
int server_getconn(void);
int server_disconnect(void);
int server_close(void);
int server_open(void);
int server_tcpsend(uint8_t *data, int length);

static int serversock = -1;
static int serverconn = -1;

void server_setsock(int sock){
	serversock = sock;
}

int server_getsock(void)
{
	return serversock;
}

void server_setconn(int conn)
{
	serverconn = conn;
}

int server_getconn(void)
{
	return serverconn;
}

int server_disconnect(void)
{	
	int conn = 0;
	conn = server_getconn();
	server_setconn(-1);
	if(conn>=0)
	{
		//shutdown(conn,SHUT_RDWR);
		close(conn);
		printf("Server TCP conn[%d] disconnect\n",conn);
	}
	return conn;
}

int server_close(void)
{	
	int sock = 0;
	sock = server_getsock();
	server_setsock(-1);
	if(sock>0)
	{
		close(sock);
		printf("Server TCP sock[%d] close\n",sock);
	}
	return sock;
}

SKMIB_t skmib;
CONFIG_t cfg;

int server_open(void)
{
	int sock = 0;
	struct linger optval;
	struct sockaddr_in serv_addr;
	struct timeval tv;
	char *serverip;
	int keepalive = 1;
	int option = 1;
	int rbind = 0;
	int rlisten = 0;
	int port = 0;
	int size = SERVERBUFMAX;
	char *dev = "wlan0";       //serport & center connection

	if(skmib._main == 1){
		port = cfg.maindeviceport;
	}else if(skmib._userSetup == 1){
		port = cfg.userport;
	}

	sock = socket(PF_INET,SOCK_STREAM,0);
	if(sock>=0)
	{
		optval.l_onoff = 1;
		optval.l_linger = 10;
		setsockopt(sock,SOL_SOCKET,SO_LINGER,(char*)&optval,sizeof(optval));
		setsockopt(sock,SOL_SOCKET,SO_SNDBUF,&size,sizeof(int));
		setsockopt(sock,SOL_SOCKET,SO_RCVBUF,&size,sizeof(int));
		memset(&tv,0,sizeof(tv));
		tv.tv_sec = 0;
		tv.tv_usec = SERVERRECVTIMEOUT;
		setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv,sizeof(tv));
		tv.tv_usec = SERVERSENDTIMEOUT;
		setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,(char *)&tv,sizeof(tv));
		setsockopt(sock,SOL_SOCKET,SO_BINDTODEVICE,(char*)&dev,strlen(dev));
		setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,(char*)&option,sizeof(option));//for bind -1 error
		setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,(char*)&keepalive,sizeof(keepalive));//for bind -1 error

		//port = SERVERPORT;

		memset(&serv_addr,0,sizeof(serv_addr));
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		serv_addr.sin_port = htons(port);
		serverip = inet_ntoa(serv_addr.sin_addr);
		rbind = bind(sock,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
		rlisten = listen(sock,2);
		printf("Server TCP sock[%d] open[%d,%d] port[%d]\n",sock,rbind,rlisten,port);
		if((rbind<0)||(rlisten<0)){
			printf("Server TCP sock[%d] bind error Process exit.\n",sock);
			exit(1);
		}
	} else {
		printf("Server TCP sock[%d] open[%d,%d] port error Process exit.[%d]\n",sock,rbind,rlisten,port);
		exit(1);
	}
	server_setsock(sock);
	return sock;
}

int server_tcpsend(uint8_t *data, int length)
{
	int conn = 0;
	int result = 0;
	int i = 0;
	
	conn = server_getconn();
	if(conn>=0)
	{
		result = send(conn,data,length,MSG_NOSIGNAL);
		printf("server send time :%d\n",clock());
		if(result<0)
		{
			server_disconnect();
		}
		printf("Server TCP con[%d] send[%d]\n",conn,result);
#if 0
		for(i=0;i<result;i++)
		{
			dbg_printf(PRINT_SBSM,"%02x ",data[i]);
			if((i%16)==15)dbg_printf(PRINT_SBSM,"\n");
		}
		dbg_printf(PRINT_SBSM,"\n");
#endif
	}
	return result;
}

void* server_recvthread(void *arg){
	int conn = 0;
	int sock = 0;
	int result = 0;
	uint8_t buf[SERVERBUFMAX] = {0};
	int len = 0;
	int i = 0;
	int j = 0;
	uint32_t timeout = 0;

	printf("Create Server TCP RX Thread\n");

	while(1)
	{
		conn = server_getconn();
		if(conn>=0)
		{
			len = recv(conn,buf,sizeof(buf),MSG_NOSIGNAL);
			if(len>0){
				printf("Server recv time: %d\n", clock());
				parse_role(buf);
			}
		}
		/*
		timeout = gettimeout(&servertimeout);
		if(timeout>(SERVERBSMRESPONSETIMEOUT-1)){
			settimeout(&serverbsmtimeout);
			server_disconnect();
		}
		*/
		usleep(1000);
	}
}

void* server_acceptthread(void *arg){
	int sock = 0;
	int conn = 0;
	struct sockaddr_in client_addr;
	int clientlen = sizeof(client_addr);
	char *clientip;

	printf("Create Server TCP Accept Thread\n");

	sock = server_open();

	while(1){
		sock = server_getsock();
		if(sock>=0){
			conn = accept(sock,(struct sockaddr*)&client_addr,&clientlen);
			if(conn>0){
				clientip = inet_ntoa(client_addr.sin_addr);
				printf("Server TCP sock[%d] accept[%d] client[%s:%d]\n",sock,conn,clientip,client_addr.sin_port);
				server_setconn(conn);
			} else {
				//perror("accept error:");
			}
		}
		sleep(1);
	}
	printf("Exit Server TCP Accept Thread\n");
}

void* tcp_server_thread(void *arg){

	pthread_t acceptid;
	pthread_t recvid;
	int ret = 0;
	int err = 0;

	err = pthread_create(&acceptid,NULL,server_acceptthread,NULL);
	if(err!=0) printf("Create Server TCP Accept Thread Error[%d]\n",err);
	
	err = pthread_create(&recvid,NULL,server_recvthread,NULL);
	if(err!=0) printf("Create Server TCP Recv Thread Error[%d]\n",err);

	err = pthread_join(acceptid,(void**)&ret);
	if(err!=0) printf("Server TCP Accept Thread Return[%d][%d]\n",err,ret);

	err = pthread_join(recvid,(void**)&ret);
	if(err!=0) printf("Server TCP Recv Thread Return[%d][%d]\n",err,ret);

}
