#include "main.h"

uint32_t service_uuid_int[] = { 0, 0, 0, 0xABCD };

SKMIB_t skmib;
CHECK_t auth[8];
AUTH_t auth2;

unsigned char* enc_auth_to_main(int* len){
	unsigned char* data = NULL;

	int i = 0, j = 0;
	//int dataLen = 0 + authNeighborLen;
	int dataLen = 0;
	int headerTailerLen = 5;

	printf("Enc Auth to Main\n");

	data = (unsigned char *)malloc(dataLen + headerTailerLen);

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x03;

	/*
	data[i++] = authNeighborLen;	


	for(j = 0; j < authNeighborLen; j++){
		data[i++] = neighborNum[j];
	}
	*/

	data[i++] = 0x03;

	*len = dataLen + headerTailerLen;

	//printf_byte(data, dataLen + headerTailerLen);

	return data;
}

/*
unsigned char* enc_auth_to_main(int authNeighborLen, int* neighborNum){
	unsigned char* data = NULL;

	int i = 0, j = 0;
	int dataLen = 1 + authNeighborLen;
	int headerTailerLen = 5;

	printf("Enc Auth to Main\n");

	data = (unsigned char *)malloc(dataLen + headerTailerLen);

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x03;

	data[i++] = authNeighborLen;	

	for(j = 0; j < authNeighborLen; j++){
		data[i++] = neighborNum[j];
	}

	data[i++] = 0x03;

	printf_byte(data, dataLen + headerTailerLen);

	return data;
}
*/


void enc_auth_result(int result){
	unsigned char* data = NULL;

	int i = 0;
	int dataLen = 0;
	int HTLen = 5;

	dataLen = 1;
	data = (unsigned char*)malloc(dataLen + HTLen);

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x08;

	data[i++] = result;

	data[i++] = 0x03;

        server_tcpsend(data, dataLen + HTLen);
}

void enc_setup_key_gen(int dev_num, unsigned char* mac){
	unsigned char* data = NULL;
	unsigned char* _Da = NULL;
	unsigned char* param = NULL;

	int i = 0;
	int dataLen = 0;
	int HTLen = 6;
	int DaLen = 0;
	int paramLen = 0;

	//while(1){
		_Da = _sk_gen_key(mac);
		DaLen = strlen(_Da);
		printf("Da:%d \n",DaLen);
		//if(DaLen == 128) break;
	//}

	param = getPublicParam(&paramLen);

	dataLen = DaLen + paramLen;
	data = (unsigned char*)malloc(dataLen + HTLen);

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x05;

	memcpy(&data[i], param, paramLen);
	i+= paramLen;

	data[i++] = DaLen;
	memcpy(&data[i], _Da, DaLen);
	i+= DaLen;

	data[i++] = 0x03;

	printf_byte(data, dataLen + HTLen);

	insert_Da(dev_num, _Da);

        server_tcpsend(data, dataLen + HTLen);
}

unsigned char* enc_setup_neighbor(int *len){
	unsigned char* data = NULL;
	char* mac = get_bt_addr();
	char* uuid = get_bt_uuid();
	int i = 0;
	int macLen = strlen(mac);
	int uuidLen = strlen(uuid);
	int dataLen = 3 + macLen + uuidLen;
	int headerTailLen = 5;

	printf("Enc Setup Neighbor\n");

	data = (unsigned char *)malloc(dataLen + headerTailLen);

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x04;
	data[i++] = DEV_ID; //0x05; //Rasp-5
	data[i++] = macLen;
	//MAC
	memcpy(&data[i], mac, macLen);
	i += macLen;

	data[i++] = uuidLen;
	//UUID
	memcpy(&data[i], uuid, uuidLen);
	i += uuidLen;
	data[i++] = 0x03;

	*len = i;

	printf_byte(data, dataLen + headerTailLen);

	return data;

}


unsigned char* enc_setup_neighborList(int row, int col, char** result, int *len){
	unsigned char* data = NULL;
	unsigned char* param = NULL;
	int i = 0, j = 0;
	int macLen = 0;
	int uuidLen = 0;
	int nameLen = 0;
	int DaLen = 0;
	int dataLen = 0;
	int paramLen = 0;
	int headerTailLen = 6;

	printf("Enc Setup Neighbor List\n");

	for(j = 1; j <= row; j++){
		macLen = strlen(result[j * col + 1]);
		uuidLen = strlen(result[j * col + 2]);
		nameLen = strlen(result[j * col + 3]);
		DaLen = strlen(result[j * col + 4]);
	}

	param = getPublicParam(&paramLen);

	dataLen = row * (macLen + uuidLen + nameLen + DaLen + 5);
	dataLen += paramLen;
	data = (unsigned char *)malloc(dataLen + headerTailLen);
	
	*len = dataLen + headerTailLen;

	data[i++] = 0x02;
	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;
	data[i++] = 0x02;

	data[i++] = paramLen >> 8;
	data[i++] = paramLen >> 0;
	memcpy(&data[i], param, paramLen);
	i += paramLen;

	data[i++] = row;

	for(j = 1; j <= row; j++){
		data[i++] = atoi(result[j*col]); //dev_num

		//mac
		macLen = strlen(result[j * col + 1]);
		data[i++] = macLen;
		memcpy(&data[i], result[j*col + 1], macLen);
		i += macLen;

		//uuid
		uuidLen = strlen(result[j * col + 2]);
		data[i++] = uuidLen;
		memcpy(&data[i], result[j*col + 2], uuidLen);
		i += uuidLen;

		//name
		nameLen = strlen(result[j * col + 3]);
		data[i++] = nameLen;
		memcpy(&data[i], result[j*col + 3], nameLen);
		i += nameLen;

		//Da
		DaLen = strlen(result[j * col + 4]);
		data[i++] = DaLen;
		memcpy(&data[i], result[j*col + 4], DaLen);
		i += DaLen;
	}

	/*
	for(j = 0; j < neighborLen; j++){
		data[i++] = dev_num[j];
		data[i++] = macLen;
		//MAC
		memcpy(&data[i], mac, macLen);
		i += macLen;

		data[i++] = uuidLen;
		//UUID
		memcpy(&data[i], uuid, uuidLen);
		i += uuidLen;
	}
	*/
	data[i++] = 0x03;
	
	printf_byte(data, dataLen + headerTailLen);

	return data;
}


void parse_neighborList(unsigned char* data){

	int i = 0, j = 0;
	int neighborLen = -1;

	int dev_num = 0;
	int macLen = 0;
	int uuidLen = 0;
	int nameLen = 0;
	int DaLen = 0;
	int paramLen = -1;

	unsigned char* param = NULL;
	unsigned char* _mac = NULL;
	unsigned char* _uuid = NULL;
	unsigned char* _name = NULL;
	unsigned char* _Da = NULL;

	printf("Parse neighbor List\n");

	paramLen = data[i++] << 8;
	paramLen |= data[i++] << 0;
	param = (unsigned char*) malloc(paramLen);
	memcpy(param, &data[i], paramLen);
	param[paramLen] = '\0';
	i += paramLen;

	setPublicParam(param, paramLen);

	//printf_byte(param, paramLen);

	neighborLen = data[i++];
	if(neighborLen < 0) printf("Parse List NeighborLen Error!!!\n");
	
	printf("neighborLen: %d \n", neighborLen);
	
	auth2.cnt_neighbor = neighborLen;
	//auth2.cnt_auth = neighborLen;
	auth2.cnt_auth = 1;

	for(j = 0; j < neighborLen; j++){
		dev_num = data[i++];
		printf("dev_num:%d \n",dev_num);
		auth[j].devId = dev_num;

		macLen = data[i++];
		printf("macLen:%d \n",macLen);
		_mac = (unsigned char*)malloc(macLen);
		memset(_mac, 0, macLen);
		memcpy(_mac, &data[i], macLen);
		//_mac[macLen] = '\0';
		//memcpy(auth[j].MAC, &data[i], macLen);
		memcpy(auth[j].MAC, _mac, macLen);
		i += macLen;
	
		uuidLen = data[i++];
		printf("uuidLen:%d \n",uuidLen);
		_uuid = (unsigned char*) malloc (uuidLen);
		memset(_uuid, 0, uuidLen);
		memcpy(_uuid, &data[i], uuidLen);
		//_uuid[uuidLen] = '\0';
		//memcpy(auth[j].UUID, &data[i], uuidLen);
		memcpy(auth[j].UUID, _uuid, uuidLen);
		i+= uuidLen;
/*
		nameLen = data[i++];
		printf("nameLen:%d \n",nameLen);
		if(nameLen >0){
			_name = (unsigned char*)malloc(nameLen);
			memset(_name, 0, nameLen);
			memcpy(_name, &data[i], nameLen);
			//_name[nameLen] = '\0';
			i+= nameLen;
		}

		DaLen = data[i++];
		printf("DaLen:%d \n",DaLen);
		_Da = (unsigned char*)malloc(DaLen);
		memset(_Da, 0, DaLen);
		memcpy(_Da, &data[i], DaLen);
		//_Da[DaLen] = '\0';
		i+= DaLen;
*/
		//printf_byte(mac, macLen);
		//printf_byte(uuid, uuidLen);
		//printf_byte(name, nameLen);
		//printf_byte(_Da, DaLen);

		//printf("NList dev:%02d mac[%d]: %s, uuid[%d]: %s, name[%d]:%s, Da[%d]: %s\n",dev_num, macLen,  mac,uuidLen, uuid, nameLen, name, DaLen, _Da);

		//insert_neighbor(dev_num, _mac, _uuid, _name);
		//insert_neighbor(dev_num, mac, uuid, uuid);
		
		printf("Neighbor get Dev:%02d mac[%d]:%s uuid[%d]:%s name[%d] Da[%d]\n", dev_num, macLen,_mac, uuidLen,_uuid, nameLen, DaLen);

		free(_mac);
		free(_uuid);
		free(_name);
		free(_Da);

		macLen = 0;
		uuidLen = 0;
		nameLen = 0;
		DaLen = 0;

		_mac = NULL;
		_uuid = NULL;
		_name = NULL;
		_Da = NULL;
		
	}
	
}

void parse_key(unsigned char* data){

	int i = 0;
	int P1Len = 0;
	int P2Len = 0;
	int PpubLen = 0;
	int keyLen = 0;
	int len =0;

	char* _Da;
	char* _P1;
	char* _P2;
	char* _Ppub;

	printf("Parse Key: \n");

	P1Len = data[i++];
	_P1 = (unsigned char*)malloc(P1Len);
	memcpy(_P1, &data[i], P1Len);
	_P1[P1Len] = '\0';
	i += P1Len;
	
	P2Len = data[i++];
	_P2 = (unsigned char*)malloc(P2Len);
	memcpy(_P2, &data[i], P2Len);
	i += P2Len;
	_P2[P2Len] = '\0';

	PpubLen = data[i++];
	_Ppub = (unsigned char*)malloc(PpubLen);
	memcpy(_Ppub, &data[i], PpubLen);
	i += PpubLen;
	_Ppub[PpubLen] = '\0';

	keyLen = data[i++];
	_Da = (unsigned char*)malloc(keyLen);
	memcpy(_Da, &data[i], keyLen);
	i += keyLen;
	_Da[keyLen] = '\0';

	//printf("get _Da: ");
	//printf_byte(_Da, keyLen);

	_sk_setup_param(_P1, _P2, _Ppub);
	_sk_setup_key(_Da);

	//insert_param_neighbor(1, _P1, _P2, _Ppub, _Da);

	len = P1Len + P2Len + PpubLen + keyLen + 4;
	saveParamNeighbor(data, len);
	//saveParamNeighbor(_P1, _P2, _Ppub, _Da);

	printf_byte(_Da, keyLen);
}

void parse_neighbor(unsigned char* data){

	int i = 0;
	int dev_num = -1;
	int macLen = -1;
	int uuidLen = -1;

	char *mac;
	char *uuid;

	printf("Parse neighbor: ");
	dev_num = data[i++];
	macLen = data[i++];
	mac = (char *)malloc(macLen);
	memcpy(mac, &data[i], macLen);
	i += macLen;

	uuidLen = data[i++];
	uuid = (char *)malloc(uuidLen);
	memcpy(uuid, &data[i], uuidLen);
	i+= uuidLen;

	printf("[%02d] mac[%d]: %s, uuid[%d]: %s \n",dev_num, macLen,  mac,uuidLen, uuid);
	
	insert_neighbor(dev_num, mac, uuid, uuid);

	enc_setup_key_gen(dev_num, mac);
}

void parse_auth_dev(unsigned char* data){

	int i = 0, j = 0;
	int authNeighborLen = -1;
	int* dev_num;
	
	int row = 0, col = 0;
	char** result = NULL;

	printf("Parse Auth Dev\n");
/*
	authNeighborLen = data[i++];

	dev_num = (int *)malloc(authNeighborLen);

	for(j = 0; j < authNeighborLen; j++){
		dev_num[j] = data[i++];
	}
*/
/*
	result = select_neighborLista(&row, &col);

	printf("NeighborLista Result Row:%d, Col:%d\n",row,col);

	for(i = 1; i <= row; i++){

		auth[i-1].devId = atoi(result[i*col]);
		memcpy(auth[i-1].MAC, result[i*col +1], strlen(result[i*col +1]));

		memcpy(auth[i-1].UUID, result[i*col +2], strlen(result[i*col +2]));
		printf("MAC[%d], uuid[%d]\n",strlen(result[i*col+1]), strlen(result[i*col+2]));
	}
	*/
	//SEARCH
	
	//search_sdp_r();

	register_service();
}

void parse_role_socket(unsigned char* data, int socket){
	int i = 0;
	int dataLen = -1;
	unsigned char* tagData = NULL;

	printf("Parse MD Role Socket Init \n");

	if(data[i++] != 0x02) printf("Parse MD Header Error!!!\n");
	dataLen = data[i++] << 8;
	dataLen |= data[i++] << 0;
	
	if(dataLen < 0) printf("Parse MD DataLen Error!!!\n");

	if(data[i] == 0x07){
		//tag
		i++;
		tagData = (unsigned char*) malloc(dataLen);
		memcpy(tagData, &data[i], dataLen);
		checkTag(tagData, dataLen, socket);

		printf("Result Time: %d \n",clock());
	}
}

void parse_role(unsigned char* data){

	int i = 0, j = 0;
	int dataLen = -1;
	int neighborLen = -1;
	int num = -1;
	unsigned char* neighbor = NULL;
	unsigned char* neighborList = NULL;
	unsigned char* auth = NULL;
	unsigned char* keyData = NULL;
	unsigned char* encData = NULL;
	unsigned char* tagData = NULL;

	printf("Parse MD Role Init \n");

	if(data[i++] != 0x02) printf("Parse MD Header Error!!!\n");
	dataLen = data[i++] << 8;
	dataLen |= data[i++] << 0;
	
	if(dataLen < 0) printf("Parse MD DataLen Error!!!\n");
	if(data[i] == 0x02){
		//Setup
		i++;
	
		neighborList = (unsigned char*)malloc(dataLen +1);
		memcpy(neighborList, &data[i], dataLen +1);
		
		parse_neighborList(neighborList);

		printf_byte(neighborList, dataLen + 1);
		
	}else if(data[i] == 0x03){
		//Authenticate
		i++;

		auth = (unsigned char*)malloc(dataLen);
		memcpy(auth, &data[i], dataLen);

		parse_auth_dev(auth);

	}else if(data[i] == 0x04){
		//neighbor Reigster
		i++;
		neighbor = (unsigned char*)malloc(dataLen);
		memcpy(neighbor, &data[i], dataLen);

		parse_neighbor(neighbor);
	}else if(data[i] == 0x05){
		//Key
		i++;
		keyData = (unsigned char*)malloc(dataLen + 1);
		memcpy(keyData, &data[i], dataLen + 1);

		parse_key(keyData);
	}else if(data[i] == 0x06){
		//encryption
		i++;
		encData = (unsigned char*) malloc(dataLen);
		memcpy(encData, &data[i], dataLen);
		
		sendTag(encData);

	}else if(data[i] == 0x07){
		//tag
		i++;
		tagData = (unsigned char*) malloc(dataLen);
		memcpy(tagData, &data[i], dataLen);
		checkTag(tagData, dataLen, 0);

		printf("Result Time: %d \n",clock());
	}else if(data[i] == 0x08){
		//Auth2
		printf("Result Time: %d \n",clock());
	}

	//free(neighbor);

}


void* network_thread(void *arg){
	pthread_t serverid;
	pthread_t clientid;

	int ret = 0;
	int err = 0;

	//parse_role(enc_setup_neighbor());

	if(skmib._main == 1 || skmib._userSetup == 1){
		err = pthread_create(&serverid,NULL,tcp_server_thread,NULL);
		if(err!=0) printf("Create Server Thread Error[%d]\n",err);
		
		err = pthread_join(serverid,(void**)&ret);
		if(err!=0) printf("Server Return[%d][%d]\n",err,ret);
	}
	if(skmib._neighbor == 1 || skmib._userAuth == 1 || skmib._userAuthReq == 1){
		err = pthread_create(&clientid,NULL,tcp_client_thread,NULL);
		if(err!=0) printf("Create Client Thread Error[%d]\n",err);
		err = pthread_join(clientid,(void**)&ret);
		if(err!=0) printf("Client Return[%d][%d]\n",err,ret);
	}

}
