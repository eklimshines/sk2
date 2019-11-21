#include "main.h"

static element_t Ppub,P1,P2,s,g,Da;
pairing_t pairing;
CHECK_t auth[8];
AUTH_t auth2;

unsigned char* getPpub(int *len);

void checkTag(unsigned char* data, int len, int index){
	int i = 0, j = 0, cnt = 0;
	int tagLen = 0;
	int tagDataLen = 0;
	int myTagLen = 0;
	int myMacLen = 0;
	int result = -1;

	unsigned char* _tag = NULL;
	unsigned char* _tagData = NULL;
	unsigned char* myTag = NULL;
	unsigned char* myMac = NULL;

	tagLen = data[i++];
	_tag = (unsigned char*)malloc(tagLen);
	memcpy(_tag, &data[i], tagLen);
	i += tagLen;

	printf("_tag[%d]: ", tagLen);
	printf_byte(_tag, tagLen);

	myMacLen = strlen(auth[index].MAC);

	tagDataLen = myMacLen + 260;	
	_tagData = (unsigned char*)malloc(tagDataLen);

	i = 0;
	memcpy(&_tagData[i], auth[index].MAC, myMacLen);
	i += myMacLen;
	memcpy(&_tagData[i], auth[index].CIPHER, 260);

	//myTag = HMAC_SHA512(auth[index].KEY, 128, _tagData, &myTagLen);
	myTag = HMAC_SHA1(auth[index].KEY, _tagData, &len);
	
	if(memcmp(_tag, myTag, myTagLen) != 0){
		printf("Auth Failed\n");
		auth[index].result = 1;
	}
	else {
		printf("Auth Success\n");
		auth[index].result = 2;
		auth2.cnt_authed++;
	}
	
	if(auth2.cnt_authed == auth2.cnt_auth){
		enc_auth_result(1);
	}else{
		for(j = 0; j < auth2.cnt_neighbor; j++){
			if(auth[j].result > 0) cnt++;
		}
		if(cnt == auth2.cnt_neighbor)
			enc_auth_result(0);
	}
	printf("NOW CHECK[%d] Authed:%d, Auth:%d, Cnt:%d\n",index, auth2.cnt_authed, auth2.cnt_auth, auth2.cnt_neighbor);

	//myTag = HMAC_SHA512(_key, keyLen, data, &myTaglen);	
}

void sendTaga(unsigned char* _tag, int tagLen){
	int i = 0;
	int dataLen = 0;

	unsigned char* data;

	dataLen = 6 + tagLen;
	data = (unsigned char*) malloc(dataLen);
	
	data[i++] = 0x02;

	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;

	data[i++] = 0x07;

	data[i++] = tagLen;
	memcpy(&data[i], _tag, tagLen);
	i += tagLen;
	
	data[i++] = 0x03;

	l2cap_send(data, dataLen);
	//blue_send(data, dataLen);
}

void sendTag(unsigned char* data){
	int i = 0;
	int macLen = 0;
	int paramLen = 0;
	int encLen = 0;
	int len = 0;
	int keyLen = 0;
	int pubLen = 0;
	int myMacLen = 0;
	int tagDataLen = 0;

	unsigned char* _enc = NULL;
	unsigned char* _param = NULL;
	unsigned char* _MAC = NULL;
	unsigned char* _key = NULL;
	unsigned char* _tag = NULL;
	unsigned char* _dec = NULL;
	unsigned char* _tagData = NULL;

	unsigned char* myPub = NULL;
	unsigned char* myMac = NULL;

	macLen = data[i++];
	_MAC = (unsigned char*) malloc(macLen);
	memcpy(_MAC, &data[i], macLen);
	i += macLen;

	myMac = get_bt_addr();
	myMacLen = strlen(myMac);

	if(myMacLen != macLen){
		printf("Mac Len failed\n");
	}else {
		printf("Mac len Correct\n");
		if(memcmp(myMac, _MAC, myMacLen) != 0){
			printf("MAC cmp failed\n");
		}else printf("MAC cmp correct\n");
	}

	paramLen = data[i++] << 8;
	paramLen |= data[i++] << 0;
	_param = (unsigned char*) malloc(paramLen);
	memcpy(_param, &data[i], paramLen);
	i += paramLen;

	myPub = getPpub(&pubLen);
		
	if(pubLen != paramLen){
		printf("Pub Len failed\n");
	}else {
		printf("Pub len Correct\n");
		if(memcmp(myPub, _param, pubLen) != 0){
			printf("Pub cmp failed\n");
		}else printf("pub cmp correct\n");
	}

	encLen = data[i++] << 8;
	encLen |= data[i++] << 0;
	_enc = (unsigned char*) malloc(encLen);
	memcpy(_enc, &data[i], encLen);
	i += encLen;

	//printf("recv enc[%d]:  ",encLen);
	//printf_byte(_enc, encLen);

	_key = _sk_kem_dec(_enc, &keyLen);

	tagDataLen = myMacLen + encLen;	
	_tagData = (unsigned char*)malloc(tagDataLen);

	i = 0;
	memcpy(&_tagData[i], myMac, myMacLen);
	i += myMacLen;
	memcpy(&_tagData[i], _enc, encLen);
	
	//_tag = HMAC_SHA512(_key, keyLen, _tagData, &len);
	_tag = HMAC_SHA1(_key, _tagData, &len);

	printf("_tag[%d]: ", len);
	printf_byte(_tag, len);

	sendTaga(_tag, len);

	//_tag = HMAC_SHA1(_key, data, &len);
}

void sendEnc(char* ID, int index){
	unsigned char* _enc = NULL;
	unsigned char* _param = NULL;
	unsigned char* data = NULL;
	
	int i = 0;
	int checkMac = -1;
	int encLen = -1;
	int paramLen = -1;
	int macLen = strlen(ID);
	int dataLen = -1;
	clock_t start, end;

	start = clock();
	checkMac = select_neighborByMAC(ID);
	
	if(checkMac <= 0){
		printf("No MAC \n");
		//return NULL;
	}else printf("MainDevice Send Enc Func\n");

	//_param = getPublicParam(&paramLen);
	_param = getPpub(&paramLen);
	_enc = _sk_kem_enc(ID, &encLen, index);

	memcpy(auth[index].CIPHER, _enc, encLen);

	dataLen = 10 + encLen + macLen + paramLen;
	data = (unsigned char*) malloc(dataLen);
	
	data[i++] = 0x02;

	data[i++] = dataLen >> 8;
	data[i++] = dataLen >> 0;

	data[i++] = 0x06;

	data[i++] = macLen;
	memcpy(&data[i], ID, macLen);
	i += macLen;

	data[i++] = paramLen >> 8;
	data[i++] = paramLen >> 0;

	memcpy(&data[i], _param, paramLen);
	i += paramLen;

	data[i++] = encLen >> 8;
	data[i++] = encLen >> 0;

	memcpy(&data[i], _enc, encLen);
	i += encLen;

	data[i++] = 0x03;

	//blue_send(data, dataLen);
	blue_send_sock(data, dataLen,auth[index].socket);

	//l2cap_send_sock(data, dataLen, auth[index].socket);
	end = clock();
	printf("The elapse time : %fs\n", (double) (end - start)/CLOCKS_PER_SEC);

}

unsigned char* getPpub(int *len){
	unsigned char* data;
	int PpubLen;

	PpubLen = element_length_in_bytes(Ppub);

	data = (unsigned char*) malloc(PpubLen);
	data = pbc_malloc(PpubLen);

	element_to_bytes(data, Ppub);
	*len = PpubLen;

	return data;

}

void setPublicParam(unsigned char* data, int len){
	unsigned char* _P1 = NULL;
	unsigned char* _P2 = NULL;
	unsigned char* _Ppub = NULL;

	int i =0;
	int P1Len = 0, P2Len = 0, PpubLen = 0;

	printf("SetPublicParam \n");

	printf_byte(data, len);

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_GT(g, pairing);
	element_init_Zr(s, pairing);

	//P1Len = data[i++] << 8;
	//P1Len |= data[i++] << 0;

	P1Len = data[i++];
	_P1 = (unsigned char*) malloc(P1Len);
	memcpy(_P1, &data[i], P1Len);
	i += P1Len;

	P2Len = data[i++];
	_P2 = (unsigned char*) malloc(P2Len);
	memcpy(_P2, &data[i], P2Len);
	i += P2Len;

	PpubLen = data[i++];
	_Ppub = (unsigned char*) malloc(PpubLen);
	memcpy(_Ppub, &data[i], PpubLen);
	i += PpubLen;

	element_from_bytes(P1, _P1);
	element_from_bytes(P2, _P2);
	element_from_bytes(Ppub, _Ppub);

	//element_printf("P1 =%B\n", P1);
	//element_printf("P2 =%B\n", P2);
	element_printf("Ppub =%B\n", Ppub);
	
    	element_pairing(g, P1, P2);
    	//element_printf("g =%B\n",g);

}

unsigned char* getPublicParam(int *len){
	unsigned char* data;
	unsigned char *_p1, *_p2, *_pPub;
	int i = 0;
	int p1Len, p2Len, PpubLen, dataLen;

	printf("GetPublicParam\n");

	//element_printf("P1 =%B\n", P1);
	//element_printf("P2 =%B\n", P2);
	element_printf("Ppub =%B\n", Ppub);


	p1Len = element_length_in_bytes(P1);
	p2Len = element_length_in_bytes(P2);
	PpubLen = element_length_in_bytes(Ppub);

	dataLen = p1Len + p2Len + PpubLen + 3;

	printf("GetPublicParam :%d\n",dataLen);

	data = (unsigned char*)malloc(dataLen);
	_p1 = pbc_malloc(p1Len);
	_p2 = pbc_malloc(p2Len);
	_pPub = pbc_malloc(PpubLen);

	element_to_bytes(_p1, P1);
	element_to_bytes(_p2, P2);
	element_to_bytes(_pPub, Ppub);

	data[i++] = p1Len;
	memcpy(&data[i], _p1, p1Len);
	i+= p1Len;

	data[i++] = p2Len;
	memcpy(&data[i], _p2, p2Len);
	i+= p2Len;

	data[i++] = PpubLen;
	memcpy(&data[i], _pPub, PpubLen);
	i+= PpubLen;

	*len = dataLen;

	//printf("getPublicParam i:%d, datalen:%d, len:%d\n",i,dataLen,len);

	return data;
}

void _sk_close(){
	element_clear(Ppub);
    	element_clear(P1);
    	element_clear(P2);
    	element_clear(s);
    	element_clear(g);
	element_clear(Da);

    	pairing_clear(pairing);
}

void _sk_setup_load_neighbor(int row, int col, char** result){
	int j = 0;

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_G2(Da, pairing);
	element_init_GT(g, pairing);

	printf("Setup Load Neighbor.\n");

	for(j = 1; j <= row; j++){
		printf("sk setup neighbor load: %d \n", result[j*col]);

		printf_byte(result[j*col+1], strlen(result[j*col+1]));

		element_from_bytes(P1, result[j * col + 1]);
		element_printf("P1 =%B\n",P1);
	
		element_from_bytes(P2, result[j * col + 2]);
		element_printf("P2 =%B\n",P2);
		
		element_from_bytes(Ppub, result[j * col + 3]);
		element_printf("Ppub =%B\n",s);

		element_from_bytes(Da, result[j * col + 4]);
		element_printf("Da =%B\n",s);
	}
    	element_pairing(g, P1, P2);
    	element_printf("g =%B\n",g);
}

void _sk_setup_load(int row, int col, char** result){
	int j = 0;

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_GT(g, pairing);
	element_init_Zr(s, pairing);

	printf("Setup.\n");

	for(j = 1; j <= row; j++){
		printf("sk setup load: %d \n", result[j*col]);

		printf_byte(result[j*col+1], strlen(result[j*col+1]));

		element_from_bytes(P1, result[j * col + 1]);
		element_printf("P1 =%B\n",P1);
	
		element_from_bytes(P2, result[j * col + 2]);
		element_printf("P2 =%B\n",P2);
		
		element_from_bytes(s, result[j * col + 3]);
		element_printf("s =%B\n",s);
	}


    	element_pairing(g, P1, P2);
    	element_printf("g =%B\n",g);
    	element_mul_zn(Ppub,P1,s);
    	element_printf("Ppub =%B \n",Ppub);
}

void _sk_setup(){

	unsigned char* _P1 = NULL;
	unsigned char* _P2 = NULL;
	unsigned char* _s = NULL;

	int P1Len;
	int P2Len;
	int sLen;

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_GT(g, pairing);
	element_init_Zr(s, pairing);

	printf("Setup.\n");
    	element_random(P1);
    	element_random(P2);
    	element_random(s);

    	element_printf("P1 =%B\n",P1);
    	element_printf("P2 =%B\n",P2);
    	element_printf("s =%B\n",s);

    	element_pairing(g, P1, P2);
    	element_printf("g =%B\n",g);
    	element_mul_zn(Ppub,P1,s);
    	element_printf("Ppub =%B \n",Ppub);
	
	P1Len = element_length_in_bytes(P1);
	P2Len = element_length_in_bytes(P2);
	sLen = element_length_in_bytes(s);
	
	_P1 = pbc_malloc(P1Len);
	_P2 = pbc_malloc(P2Len);
	_s = pbc_malloc(sLen);

	element_to_bytes(_P1, P1);
	element_to_bytes(_P2, P2);
	element_to_bytes(_s, s);

	//printf("%d %d %d Len\n", P1Len, P2Len, sLen);

	//printf("%s %s %s \n", _P1, _P2, _s);

	//insert_param(1, _P1, _P2, _s);
	saveParamCona(_P1, P1Len,  _P2, P2Len, _s, sLen);
}

void _sk_setup_key(unsigned char* _Da){

	element_init_G2(Da, pairing);
	element_from_bytes(Da, _Da);

	element_printf("Da =%B\n",Da);

}
void _sk_setup_param(unsigned char* _P1, unsigned char* _P2, unsigned char* _Ppub){
	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);

	element_from_bytes(P1, _P1);
	element_from_bytes(P2, _P2);
	element_from_bytes(Ppub, _Ppub);
	
	element_printf("P1 =%B\n",P1);
	element_printf("P2 =%B\n",P2);
	element_printf("Ppub =%B\n",Ppub);
}


void setPublicParamController(unsigned char* data, int len){
	unsigned char* _P1 = NULL;
	unsigned char* _P2 = NULL;
	unsigned char* _s = NULL;

	int i =0;
	int P1Len = 0, P2Len = 0, sLen = 0;

	printf("SetPublicParamController \n");

	//printf_byte(data, len);

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_GT(g, pairing);
	element_init_Zr(s, pairing);

	//element_init_Zr(s, pairing);

	//P1Len = data[i++] << 8;
	//P1Len |= data[i++] << 0;

	P1Len = data[i++];
	_P1 = (unsigned char*) malloc(P1Len);
	memcpy(_P1, &data[i], P1Len);
	i += P1Len;

	P2Len = data[i++];
	_P2 = (unsigned char*) malloc(P2Len);
	memcpy(_P2, &data[i], P2Len);
	i += P2Len;

	sLen = data[i++];
	_s = (unsigned char*) malloc(sLen);
	memcpy(_s, &data[i], sLen);
	i += sLen;

	element_from_bytes(P1, _P1);
	element_from_bytes(P2, _P2);
	element_from_bytes(s, _s);

	//element_printf("P1 =%B\n", P1);
	//element_printf("P2 =%B\n", P2);

    	element_mul_zn(Ppub,P1,s);
	element_printf("Ppub =%B\n", Ppub);
	
    	element_pairing(g, P1, P2);
    	element_printf("g =%B\n",g);
}

void setPublicParamNeighbor(unsigned char* data, int len){
	unsigned char* _P1 = NULL;
	unsigned char* _P2 = NULL;
	unsigned char* _Ppub = NULL;
	unsigned char* _Da = NULL;

	int i =0;
	int P1Len = 0, P2Len = 0, PpubLen = 0, DaLen = 0;

	printf("SetPublicParamNeighbor \n");

	//printf_byte(data, len);

	element_init_G1(Ppub, pairing);
	element_init_G1(P1, pairing);
	element_init_G2(P2, pairing);
	element_init_GT(g, pairing);
	//element_init_Zr(s, pairing);
	element_init_G2(Da, pairing);

	//P1Len = data[i++] << 8;
	//P1Len |= data[i++] << 0;

	P1Len = data[i++];
	_P1 = (unsigned char*) malloc(P1Len);
	memcpy(_P1, &data[i], P1Len);
	i += P1Len;

	P2Len = data[i++];
	_P2 = (unsigned char*) malloc(P2Len);
	memcpy(_P2, &data[i], P2Len);
	i += P2Len;

	PpubLen = data[i++];
	_Ppub = (unsigned char*) malloc(PpubLen);
	memcpy(_Ppub, &data[i], PpubLen);
	i += PpubLen;

	DaLen = data[i++];
	_Da = (unsigned char*) malloc(DaLen);
	memcpy(_Da, &data[i], DaLen);
	i += DaLen;

	element_from_bytes(P1, _P1);
	element_from_bytes(P2, _P2);
	element_from_bytes(Ppub, _Ppub);
	element_from_bytes(Da, _Da);

	element_printf("P1 =%B\n", P1);
	element_printf("P2 =%B\n", P2);
	element_printf("Ppub =%B\n", Ppub);
	element_printf("Da =%B\n", Da);
	
    	element_pairing(g, P1, P2);
    	element_printf("g =%B\n",g);

}

unsigned char* _sk_kem_enc(unsigned char* _ID, int* len, int index){
	int keylength = 128;
	int uLen, vLen, dataLen, grLen, mLen;
	unsigned char* data = NULL;
	unsigned char* _U;
	unsigned char* _V;
	unsigned char* _gr;
	unsigned char* _m;
	unsigned char aes_key[keylength];
	int i = 0 ;

	element_t r, Q, U, V, gr, m;
	element_t IDa, P1_ID, H2_gr;

	mpz_t mpz_gr, mpz_m, mpz_V;

    	memset(aes_key, 0, sizeof(aes_key));
    	
	//m <- {0,1]^n
	if (!RAND_bytes(aes_key, keylength)){
        	exit(-1);
	}
	aes_key[keylength-1] = '\0';

	//printf_byte(aes_key, keylength);

	mpz_init(mpz_gr);
	mpz_init(mpz_m);
	mpz_init(mpz_V);

	element_init_G1(P1_ID, pairing);
	element_init_G1(Q, pairing);
	element_init_G1(U, pairing);

	element_init_GT(gr, pairing);

	element_init_Zr(m, pairing);
	element_init_Zr(IDa, pairing);
	element_init_Zr(V, pairing);

	element_from_bytes(m, aes_key);
	
	memcpy(auth[index].KEY, aes_key, keylength);
	//r <- H3(m)

	element_printf("m = %B\n",m);

	printf("KEM-Enc ID[%d]:%s\n",strlen(_ID),_ID);
	element_from_hash(IDa, _ID, strlen(_ID)); //H1(ID)
	element_pow_zn(P1_ID, P1, IDa); //p1^H1(ID)
	element_mul(Q,Ppub,P1_ID); //Q <- R*P1^H1(ID) R=Ppub

	//element_printf("IDa = %B\n",IDa);
	//element_printf("P1_ID = %B\n",P1_ID);
	//element_printf("P1 = %B\n",P1);
	//element_printf("Q = %B\n",Q);

	element_pow_zn(U, Q, m); //U <- Q^r
	element_pow_zn(gr,g,m); // e(P1, P2)^r

	//element_printf("gr =%B\n",gr);

	element_to_mpz(mpz_gr,gr);
	element_to_mpz(mpz_m,m);

	//gmp_printf("mpz_m = %Zd\n", mpz_m);
	//gmp_printf("mpz_gr = %Zd\n", mpz_gr);


	grLen = element_length_in_bytes(gr);
	_gr = pbc_malloc(grLen);
	element_to_bytes(_gr, gr);

	//printf("gr : %d, key :%d\n", grLen, keylength);
	//printf("gr : ");
	//printf_byte(gr, grLen);

	_V = (unsigned char*) malloc(128);

	for(i = 0; i < 128; i++)
		_V[i] = _gr[i] ^ aes_key[i];
	
	//mpz_xor(mpz_V,mpz_m,mpz_gr); //V <- m xor gr
	//printf_byte(_V, 128);
	//element_from_bytes(V, _V);
	
	//element_set_mpz(V, mpz_V);

	//gmp_printf("mpz_v = %Zd\n", mpz_V);

	//element_printf("U = %B\n", U);
	//element_printf("V = %B\n", V);

	uLen = element_length_in_bytes(U);
	//vLen = element_length_in_bytes(V);
	
	_U = pbc_malloc(uLen);
	//_V = pbc_malloc(vLen);
	
	element_to_bytes(_U, U);
	//element_to_bytes(_V, V);
	vLen = 128;
	//printf("ulen:%d\n", uLen);
	
	dataLen = uLen + vLen + 4;
	data = (unsigned char*)malloc(dataLen);
	i = 0;
	
	data[i++] = uLen << 8;
	data[i++] = uLen << 0;
	memcpy(&data[i], _U, uLen);
	i += uLen;
	
	data[i++] = vLen << 8;
	data[i++] = vLen << 0;
	memcpy(&data[i], _V, vLen);
	i += vLen;

	//printf_byte(_V, vLen);
	//printf_byte(data, dataLen);
	//printf("kem enc dataLen: %d\n", dataLen);
	*len = dataLen;

	element_clear(P1_ID);
	element_clear(Q);
	element_clear(U);
	element_clear(gr);
	element_clear(m);
	element_clear(IDa);
	element_clear(V);

	return data;
}

unsigned char* _sk_kem_dec(unsigned char* _enc, int* keyLen){
	int uLen = 0, vLen = 0, mLen = 0, aLen = 0;
	unsigned char* _U = NULL;
	unsigned char* _V = NULL;
	unsigned char* _m = NULL;
	unsigned char* _a = NULL;
	int i = 0;

	element_t U, V, m, a;
	mpz_t mpz_gp, mpz_V, mpz_W, mpz_M, mpz_a;

	printf("_SK_KEM_DEC \n");

	element_init_G1(U, pairing);
	//element_init_GT(gp, pairing);

	element_init_GT(a, pairing);

	element_init_Zr(V, pairing);
	element_init_Zr(m, pairing);

	mpz_init(mpz_gp);
	mpz_init(mpz_V);
	mpz_init(mpz_W);
	mpz_init(mpz_M);	
	mpz_init(mpz_a);

	uLen = _enc[i++] >> 8;
	uLen |= _enc[i++] >> 0;
	_U = (unsigned char*) malloc(uLen);
	memcpy(_U, &_enc[i], uLen);
	_U[uLen] = '\0';
	i += uLen;
	element_from_bytes(U,_U);

	//printf("uLen[%d]: ", uLen);
	//printf_byte(_U, uLen);

	vLen = _enc[i++] >> 8;
	vLen |= _enc[i++] >> 0;
	_V = (unsigned char*) malloc(vLen);
	memcpy(_V, &_enc[i], vLen);
	i += vLen;
	//element_from_bytes(V,_V);

	//printf("vLen[%d]: ", vLen);
	//printf_byte(_V, vLen);

	//element_printf("U = %B\n", U);
	//element_printf("V = %B\n", V);

	element_pairing(a, U, Da); //a <- e(U, IDa)
	
	//element_printf("a = %B\n",a);

	//element_to_mpz(mpz_V, V);
	element_to_mpz(mpz_a, a);

	//gmp_printf("mpz_v = %Zd\n", mpz_V);
	//gmp_printf("mpz_a = %Zd\n", mpz_a);

	//mpz_xor(mpz_M, mpz_a, mpz_V); //m <- v xor a
	//element_set_mpz(m, mpz_M);
	
	//gmp_printf("mpz_M = %Zd\n", mpz_M);

	aLen = element_length_in_bytes(a);
	_a = (unsigned char*) malloc(aLen);
	element_to_bytes(_a, a);

	//printf("aLen:%d, vLen:%d\n", aLen, vLen);
	//printf("_a : ");
	//printf_byte(_a, aLen);
	//printf("_V : ");
	//printf_byte(_V, vLen);

	_m = (unsigned char*) malloc(128);
	for(i = 0; i < 128; i++)
		_m[i] = _V[i] ^ _a[i];
	//for(i = vLen; i < 128; i++)
//		_m[i] = _a[i] ^ 0x0;

	element_from_bytes(m,_m);

	element_printf("m = %B\n",m);

	//mLen = element_length_in_bytes(m);
	//_m = (unsigned char*) malloc(mLen);
	//element_to_bytes(_m, m);

	*keyLen = 128;

	element_clear(U);
	element_clear(a);
	element_clear(V);
	element_clear(m);

	return _m;
}

unsigned char* _sk_gen_key(unsigned char *ID){
	element_t IDa;
	element_t Da;
	element_t temp1;

	unsigned char *_Da;
	int DaLen = 0;

	element_init_G2(Da, pairing);
	element_init_Zr(IDa, pairing);
	element_init_Zr(temp1, pairing);

	printf("Extract. [%d]%s\n",strlen(ID), ID);
	element_from_hash(IDa,ID,strlen(ID)); //H1(IDa)
	element_printf("IDa =%B \n",IDa);
	element_add(temp1, s, IDa);
	element_invert(temp1, temp1);
	//element_div(Da, P2, temp1);
	element_mul_zn(Da,P2, temp1);
	element_printf("Da =%B \n", Da);

	DaLen = element_length_in_bytes(Da);
	_Da = pbc_malloc(DaLen);
	element_to_bytes(_Da, Da);

	printf("GenKeyDaLen : %d\n", DaLen);

	element_clear(IDa);
	element_clear(Da);
	element_clear(temp1);

	return _Da;
}

unsigned char* extractDa(pairing_t pairing, unsigned char *ID, element_t s, element_t P2){
	element_t IDa;
	element_t Da;
	element_t temp1;

	unsigned char *_Da;
	int DaLen = 0;

	element_init_G2(Da, pairing);
	element_init_Zr(IDa, pairing);
	element_init_Zr(temp1, pairing);

	printf("Extract. [%d]%s\n",strlen(ID), ID);
	element_from_hash(IDa,ID,strlen(ID)); //H1(IDa)
	element_printf("IDa =%B \n",IDa);
	element_add(temp1, s, IDa);
	element_invert(temp1, temp1);
	//element_div(Da, P2, temp1);
	element_mul_zn(Da,P2, temp1);
	element_printf("Da =%B \n", Da);

	DaLen = element_length_in_bytes(Da);
	_Da = pbc_malloc(DaLen);
	element_to_bytes(_Da, Da);

	printf("extract Da Len: %d\n", DaLen);

	element_clear(IDa);
	element_clear(Da);
	element_clear(temp1);

	return _Da;
}
