#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <pbc.h>
#include <pbc_test.h>
#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <sqlite3.h>

#define DEV_ID 0x05

#define SERVERPORT 30005
#define SERVERBUFMAX 2048
#define SERVERSENDTIMEOUT 50000// 50ms
#define SERVERRECVTIMEOUT 50000// 50ms
#define SERVERRESPONSETIMEOUT 5000

#define CLIENTSENDTIMEOUT 1000000 //1s
#define CLIENTRECVTIMEOUT 2000000 //3s
#define MAXCLIENTBUFSIZE 8192
#define MAXNETBUFSIZE 8192*10

#define eprintfExit(x, ...) { fprintf(stderr, __VA_ARGS__); exit(x); }
#define eprintfReturn(x, ...) { fprintf(stderr, __VA_ARGS__); return (x); }


typedef enum{
	SESSION_CLOSE = 0,
	SESSION_CONNECTED = 1
}CLTSESSION_t;

typedef struct _SKMIB{
	int _main;
	int _userSetup;
	int _userAuth;
	int _neighbor;
	int _userAuthReq;
	int _neighborAuth;
}SKMIB_t;

typedef struct tCONFIG{
	char maindeviceip[16];
	char maindevicemac[20];
	char maindeviceuuid[40];
	char myuuid[40];
	char userip[20];
	int maindeviceport;
	int userport;
	int L2capport;
}CONFIG_t;

typedef struct _AUTHMIB{
	char _neighborMAC[20];
	char _KEY[128];
	char _ENC[1024];
}AUTHMIB_t;


typedef struct _AUTH2{
	int cnt_neighbor;
	int cnt_auth;
	int cnt_authed;
}AUTH_t;

typedef struct _CHECK{
	unsigned char MAC[20];
	unsigned char KEY[128];
	unsigned char CIPHER[260];
	unsigned char UUID[50];
	int socket;
	int devId;
	int psm;
	int result;
	CLTSESSION_t session;
}CHECK_t;

int aes_encrypt(unsigned char* in, unsigned char* out, int size, unsigned char* key, int KEY_BIT);
int aes_decrypt(unsigned char* in, unsigned char* out, int size, unsigned char* key, int KEY_BIT);

unsigned char* encData(element_t U, element_t V, element_t W);

unsigned char* decryption(pairing_t pairing, unsigned char *ID, unsigned char *cipher, element_t Da, element_t Ppub);
unsigned char* encryption(pairing_t pairing, unsigned char *ID, element_t P1, element_t P2, element_t Ppub, element_t g);

unsigned char* extractDa(pairing_t pairing, unsigned char *ID, element_t s, element_t P2);

unsigned char* aes_hmac_decryption(pairing_t pairing, unsigned char *ID, unsigned char *cipher, element_t Da, element_t Ppub);
unsigned char* aes_hmac_encryption(pairing_t pairing, unsigned char *ID, element_t P1, element_t P2, element_t Ppub, element_t g);


void printf_byte(unsigned char* data, int len);
void concate_byte(unsigned char* out, unsigned char* in1, int in1Len, unsigned char *in2, int in2Len);

unsigned char* message_padding(unsigned char* data, int dataLen, int padding);

void* bluetooth_thread(void *arg);
void* network_thread(void *arg);

void* tcp_server_thread(void *arg);
void* tcp_client_thread(void *arg);

char* get_bt_addr();
char* get_bt_name();
char* get_bt_uuid();

unsigned char* enc_setup_neighbor(int *len);
unsigned char* enc_setup_neighborList(int row, int col, char** result, int* len);
//unsigned char* enc_auth_to_main(int authNeighborLen, int* neighborNum);
unsigned char* enc_auth_to_main(int* len);

void init_sqlite3();
void init_sqlite3_param();

void insert_param_neighbor(int dev_num, unsigned char* P1, unsigned char* P2, unsigned char* PUB, unsigned char* Da);
void insert_param(int dev_num, unsigned char* P1, unsigned char* P2, unsigned char* s);
void insert_neighbor(int dev_num, char* mac, char* uuid, char* name);
void insert_Da(int dev_num, char* _Da);
void _sqlite3_close();
unsigned char* select_neighborList(int *len);
void select_param();
int select_neighborByMAC(char* MAC);
char** select_neighborLista(int* r, int* c);

void _sk_setup();
void _sk_close();
unsigned char* _sk_gen_key(unsigned char* ID);
void checkTag(unsigned char* data, int len, int index);
void _sk_setup_load(int row, int col, char** result);
void _sk_setup_param(unsigned char* _P1, unsigned char* _P2, unsigned char* _Ppub);

int client_send(uint8_t *data, int lenght);
int server_tcpsend(uint8_t *data, int lenght);

void parse_role(unsigned char* data);
void parse_role_socket(unsigned char* data, int socket);

sdp_session_t *register_service();
int sdp_search(int* psm);
int _sdp_search(char* mac, char* uuid, int* psm);
void* t_sdp_search(void *arg);
void search_sdp_r();

int _str2uuid(const char* uuid_str, uuid_t* uuid);

void setPublicParam(unsigned char* data, int len);
unsigned char* getPublicParam(int *len);
unsigned char* getPpub(int *len);
void setPublicParamNeighbor(unsigned char* data, int len);
void setPublicParamController(unsigned char* data, int len);

unsigned char* HMAC_SHA512(unsigned char *key, int keyLen, unsigned char *data, unsigned int *len2);

void sendTag(unsigned char* data);
void sendEnc(char* ID, int index);
unsigned char* _sk_kem_enc(unsigned char *ID, int* len, int index);
unsigned char* _sk_kem_dec(unsigned char* _enc, int* keyLen);

void* l2cap_thread(void *arg);

void config_init(CONFIG_t *config);

void blue_send_sock(unsigned char* data, int len, int sock);
void l2cap_send_sock(unsigned char* data, int len, int sock);
void l2cap_send(unsigned char* data, int len);
//void saveParamNeighbor(unsigned char* _P1, unsigned char* _P2, unsigned char* Ppub, unsigned char* _Da);
void readParamNeighbor();
void saveParamNeighbor(unsigned char* data, int len);

void readParamCon();
void saveParamCona(unsigned char* P1, int P1Len, unsigned char* P2, int P2Len, unsigned char* s, int sLen);


extern pairing_t pairing;
extern SKMIB_t skmib;

extern CONFIG_t cfg;
extern CHECK_t auth[8];
extern AUTH_t auth2;
