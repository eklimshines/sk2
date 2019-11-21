#include "main.h"

static int blue_sock = -1;
static int blue_conn = -1;
static CLTSESSION_t bluesession = 0;
SKMIB_t skmib;
CHECK_t auth[8];

void client_setconn(int conn);
int client_getconn(void);

void blue_setsock(int sock);
int blue_getsock(void);
int blue_disconnect(void);
int blue_open(void);
void blue_send(uint8_t *data, int length);
void* sdp_search_thread(void *arg);

CLTSESSION_t blue_setsession(CLTSESSION_t session){
    bluesession = session;
    return bluesession;
}

CLTSESSION_t blue_getsession(void){
    return bluesession;
}

void blue_setconn(int conn){
	blue_conn = conn;
}

int blue_getconn(void){
	return blue_conn;
}

void blue_setsock(int sock){
    blue_sock = sock;
}

int blue_getsock(void){
    return blue_sock;
}

int blue_disconnect(void){	
	int sock = -1;
	sock = blue_getsock();
	if(sock>=0) close(sock);
	blue_setsock(-1);
	blue_setconn(-1);
	return sock;
}

int blue_open(){
	struct sockaddr_l2 loc_addr = { 0 }, rem_addr = { 0 };
	
	int ss, client, status;
    	int psm = 0x1001;
	int rbind = -1, rlisten = -1;
	socklen_t opt = sizeof(rem_addr);

	printf("Bluetooth socket open\n");

	// allocate socket
    	ss = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

    	// bind socket to port 0x1001 of the first available 
    	// bluetooth adapter
    	loc_addr.l2_family = AF_BLUETOOTH;
	loc_addr.l2_bdaddr = *BDADDR_ANY;
	//loc_addr.l2_psm = htobs(0x1001);

	loc_addr.l2_psm = htobs(psm);
	rbind = bind(ss, (struct sockaddr *)&loc_addr, sizeof(loc_addr));
	
	// put socket into listening mode
	rlisten = listen(ss, 1);

	printf("Bluetooth L2cap Server sock[%d] open[%d,%d] port[%d]\n", ss, rbind, rlisten, psm);

	blue_setsock(ss);

	return ss;
}

void* bluetooth_recv_thread(void *arg){
	char buf[1024] = { 0 };
	int bytes_read;
	int client = 0;
	int i = 0;
	printf("Bluetooth RECV thread\n");

	while(1){
		for(i = 0; i <8; i++){
		//client = blue_getconn();
		client = auth[i].socket;
		// read data from the client
		if(client > 0){

			bytes_read = read(client, buf, sizeof(buf));
	    		if( bytes_read > 0 ) {
        			printf("received [%d]\n", bytes_read);
				//parse_role(buf);
				parse_role_socket(buf, i);
			}
		}
		}
		usleep(1000);
	}
}
/*
void* bluetooth_accpet_thread(void *arg){

    struct sockaddr_l2 loc_addr = { 0 }, rem_addr = { 0 };
    char buf[1024] = { 0 };
    int s, client, bytes_read;
    socklen_t opt = sizeof(rem_addr);

    // allocate socket
    s = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);

    // bind socket to port 0x1001 of the first available 
    // bluetooth adapter
    loc_addr.l2_family = AF_BLUETOOTH;
    loc_addr.l2_bdaddr = *BDADDR_ANY;
    loc_addr.l2_psm = htobs(0x1001);

    bind(s, (struct sockaddr *)&loc_addr, sizeof(loc_addr));

    // put socket into listening mode
    listen(s, 1);

    // accept one connection
    client = accept(s, (struct sockaddr *)&rem_addr, &opt);

    ba2str( &rem_addr.l2_bdaddr, buf );
    fprintf(stderr, "accepted connection from %s\n", buf);

    memset(buf, 0, sizeof(buf));

    // read data from the client
    bytes_read = read(client, buf, sizeof(buf));
    if( bytes_read > 0 ) {
        printf("received [%s]\n", buf);
    }

    // close connection
    close(client);
    close(s);

}
*/
void* bluetooth_accpet_thread(void *arg){
	int ss= 0, conn = 0,client = 0;
	char ID[1024] = { 0 }, buf[1024] = {0};
	struct sockaddr_l2 rem_addr = { 0 };
	int i = 0;
	socklen_t opt = sizeof(rem_addr);

	ss= blue_open();

	printf("bluetooth_accpet_threadthread\n");

	while(1){
    		ss = blue_getsock();
		//listen(ss, 1);
		printf("blue sock : %d\n", ss);
		if(ss >=0){
			// accept one connection
			client = accept(ss, (struct sockaddr *)&rem_addr, &opt);
			printf("client :%d\n",client);
			if(client >0){
			
				memset(ID, 0, sizeof(ID));
    				ba2str( &rem_addr.l2_bdaddr, ID );
    				fprintf(stderr, "accepted connection from %s\n", ID);
				memset(buf, 0, sizeof(buf));
				blue_setconn(client);
				
				//Gen Enc
				//sendEnc(ID);
				
				for(i = 0; i < 8; i++){
					if(strcmp(ID, auth[i].MAC)==0){
						printf("ID:%s, MAC:%s\n",ID, auth[i].MAC);
						auth[i].socket = client;
						sendEnc(ID, i);
						break;
					}
				}
			}
	    		
		}
    	}

    //close connection
    close(client);
    close(ss);
}

void blue_send_sock(unsigned char* data, int len, int sock){
	//int sock = blue_getconn();
	int status = 0;

	printf("Blue_Send_Sock \n");

	if(sock>0){
		status = write(sock, data, len);
		if(status < 0) printf("Blue Server L2CAP SOCK Send[%d] Failed %d\n", len, status);
		else printf("Blue Server SOCK Send Success\n");
	}
}

void blue_send(unsigned char* data, int len){
	int sock = blue_getconn();
	int status = 0;

	printf("Blue_Send \n");

	if(sock>0){
		status = write(sock, data, len);
		if(status < 0) printf("Blue Server L2CAP Send[%d] Failed %d\n", len, status);
		else printf("Blue Server  Send Success\n");
	}
}

pthread_mutex_t mutex_lock;

void search_sdp_r(){
	int i = 0;
	int psm = 0;
	int rst = 0;
	int err = 0;
	int ret = 0;
	int j =0;
	clock_t start, end;
	pthread_t findsdpid[8];
	pthread_t sdpid[8];
	//pthread_t l2capid;
	pthread_t l2capid[8];

	start = clock();

	
	/*for(i = 0; i < 8; i++){
		printf("[%d]SDP Search[%s]:%s\n",i,auth[i].MAC, auth[i].UUID);
	}*/

	for(i = 0; i < 8; i++){
		psm = 0;
		//pthread_mutex_lock(&mutex_lock);

		if(auth[i].devId != 0){
			
			printf("__[%d]SDP Search[%s]:%s\n",i,auth[i].MAC, auth[i].UUID);
			rst = _sdp_search(auth[i].MAC, auth[i].UUID, &auth[i].psm);
			//auth[i].psm = 4097;
			auth[i].session = SESSION_CLOSE;
			printf("[%d]SDP[%d] Search Result:%d %d\n",auth[i].devId,i, rst,auth[i].psm);

			//usleep(1000);
			//err = pthread_create(&l2capid[i], NULL ,sdp_search_thread,(void *)&i);

			err = pthread_create(&l2capid[i], NULL ,l2cap_thread,(void *)&i);
			//usleep(250);
		}

		//pthread_mutex_unlock(&mutex_lock);
	}
	end = clock();
	printf("The search_sdp_r func elapse time : %fs\n",(double) (end - start)/CLOCKS_PER_SEC);
	//err = pthread_create(&l2capid, NULL ,l2cap_thread,NULL);
/*	
	for (i = 0; i < 8; i++){
		if(auth[i].devId !=0 && auth[i].psm > 0){
	err = pthread_create(&l2capid[i], NULL ,l2cap_thread,(void *)&i);
	if(err!=0) printf("Create L2CAP Thread Error[%d]\n",err);
		}
	}
*/
	for (i = 0; i < 8; i++){

		if(auth[i].devId !=0 && auth[i].psm > 0){
	err = pthread_join(l2capid[i], (void**)&ret);
	if(err!=0) printf("Bluetooth L2CAP Thread Return[%d][%d]\n",err,ret);
		}
	}
	/*
	for (i = 0; i < 8; i++){
		if(auth[i].devId !=0 && auth[i].psm > 0){
		err = pthread_create(&findsdpid[i], NULL ,sdp_search_thread,(void *)&i);
		if(err!=0) printf("Create Bluetooth SDP Thread[%d] Error[%d]\n",i, err);
	
		}
	}
	*/
			//if(rst == 1){
				
				//auth[i].psm = psm;
				//err = pthread_create(&findsdpid[i], NULL ,sdp_search_thread,(void *)&i);
				//if(err!=0) printf("Create Bluetooth SDP Thread[%d] Error[%d]\n",i, err);
			//}
		//}
		//usleep(1000);
	//}	
	/*
	for(i = 0; i < 8; i++){
		err = pthread_join(findsdpid[i], (void**)&ret);
		if(err!=0) printf("Bluetooth SDP Thread[%d] Return[%d][%d]\n",i,err,ret);
	}
	*/
}

void* sdp_search_thread(void *arg){
	int rst = -2;
	pthread_t l2capid;
	int ret = 0;
	int err = 0;
	int psm = 0;
	printf("SDP SEARCH thread\n");
	//sleep(1);
	while(1){
		rst = sdp_search(&psm);
		printf("SDP Search Result:%d\n", rst);
		if(rst == 1) {
			err = pthread_create(&l2capid, NULL ,l2cap_thread,(void *)&psm);
			if(err!=0) printf("Create L2CAP Thread Error[%d]\n",err);
			
			err = pthread_join(l2capid, (void**)&ret);
			if(err!=0) printf("Bluetooth L2CAP Thread Return[%d][%d]\n",err,ret);
			break;
		}
		//sleep(1);
	}
}
/*
void* sdp_search_thread(void *arg){
	int rst = -2;
	pthread_t l2capid;
	int ret = 0;
	int err = 0;
	int i = 0;
	clock_t start, end;
	
	printf("SDP SEARCH thread\n");
	
	//sleep(1);
	i = *(int *)arg;

	printf("%d\n",i);

	if(i>=8) return;

	start = clock();
	printf("[%d]SDP Search[%s]:%s\n",i,auth[i].MAC, auth[i].UUID);
	rst = _sdp_search(auth[i].MAC, auth[i].UUID, &auth[i].psm);
	end = clock();
	printf("SDP[%d] Search Result:%d %d\n",i, rst,auth[i].psm);

	if(rst == 1){
		err = pthread_create(&l2capid, NULL ,l2cap_thread,(void *)&i);
		//err = pthread_create(&l2capid, NULL ,l2cap_thread,NULL);
		if(err!=0) printf("Create L2CAP Thread Error[%d]\n",err);
			
		err = pthread_join(l2capid, (void**)&ret);
		if(err!=0) printf("Bluetooth L2CAP Thread Return[%d][%d]\n",err,ret);
	}
}
*/
void* bluetooth_thread(void *arg){
	pthread_t blueid;
	pthread_t blue_rxid;
	pthread_t findsdpid;
	int ret = 0;
	int err = 0;


	if(skmib._neighborAuth == 1){

		err = pthread_create(&findsdpid, NULL ,sdp_search_thread,NULL);
		if(err!=0) printf("Create Bluetooth SDP Thread Error[%d]\n",err);
	}
	if(skmib._main == 1){

		err = pthread_create(&blueid, NULL ,bluetooth_accpet_thread,NULL);
		if(err!=0) printf("Create Bluetooth Thread Error[%d]\n",err);

		err = pthread_create(&blue_rxid, NULL, bluetooth_recv_thread,NULL);
		if(err!=0) printf("Create Bluetooth RX Thread Error[%d]\n",err);
	}

	if(skmib._main == 1){
		err = pthread_join(blueid, (void**)&ret);
		if(err!=0) printf("Bluetooth Thread Return[%d][%d]\n",err,ret);

		err = pthread_join(blue_rxid, (void**)&ret);
		if(err!=0) printf("Bluetooth RX Thread Return[%d][%d]\n",err,ret);
	}
	if(skmib._neighborAuth == 1){

		err = pthread_join(findsdpid, (void**)&ret);
		if(err!=0) printf("Bluetooth SDP Thread Return[%d][%d]\n",err,ret);
	}

}
