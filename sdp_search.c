#include "main.h"

CONFIG_t cfg;
CHECK_t auth[8];

void* t_sdp_search(void *arg){
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0xAB, 0xCD };
    uuid_t svc_uuid;
    int err;
    int i = *(int *)arg;
    int* result = 1;

    bdaddr_t target;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    sdp_session_t *session = 0;

    printf("search SDP protocol[%s][%s]\n", auth[i].MAC, auth[i].UUID);

    //str2ba( "B8:27:EB:BB:62:35", &target );
    str2ba( auth[i].MAC, &target);

    // connect to the SDP server running on the remote machine
    session = sdp_connect( BDADDR_ANY, &target, SDP_RETRY_IF_BUSY );

    if(session == NULL) {
	    printf("NULL\n");
	    *result  = -1;
	    return (void*)result;
    }
    // specify the UUID of the application we're searching for
    
    //_str2uuid("00001101-0000-1000-8000-00805F9B34FB",&svc_uuid);
    _str2uuid(auth[i].UUID, &svc_uuid);

    //sdp_uuid128_create( &svc_uuid, &svc_uuid_int );
    search_list = sdp_list_append( NULL, &svc_uuid );

    // specify that we want a list of all the matching applications' attributes
    uint32_t range = 0x0000ffff;
    attrid_list = sdp_list_append( NULL, &range );

    // get a list of service records that have UUID 0xabcd
    err = sdp_service_search_attr_req( session, search_list, \
            SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
    sdp_list_t *r = response_list;

    if(response_list == NULL) {
	    printf("NULL\n");
	    *result  = -1;
	    return (void*)result;
    }
    printf("err: %d\n",err);
    // go through each of the service records
    for (; r; r = r->next ) {
        sdp_record_t *rec = (sdp_record_t*) r->data;
        sdp_list_t *proto_list;
        
	// get a list of the protocol sequences
        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
        sdp_list_t *p = proto_list;

        // go through each protocol sequence
        for( ; p ; p = p->next ) {
            sdp_list_t *pds = (sdp_list_t*)p->data;

            // go through each protocol list of the protocol sequence
            for( ; pds ; pds = pds->next ) {

                // check the protocol attributes
                sdp_data_t *d = (sdp_data_t*)pds->data;
                int proto = 0;
                for( ; d; d = d->next ) {
                    switch( d->dtd ) {
			    
                        case SDP_UUID16:
                        case SDP_UUID32:
                        case SDP_UUID128:
                            proto = sdp_uuid_to_proto( &d->val.uuid );
			    
                            break;
			case SDP_UINT16:
                            if( proto == L2CAP_UUID ) {
                                printf("uint16 l2cap port: %ld\n",d->val.uint16);
				//Connect to Main Device
				//*psm = d->val.uint16;
				auth[i].psm = d->val.uint16;
                            }
			    break;
			    /*
                        case SDP_UINT8:
                            if( proto == RFCOMM_UUID ) {
                                printf("rfcomm channel: %d\n",d->val.int8);
                            }
			    
                            if( proto == L2CAP_UUID ) {
                                printf("l2cap port: %d\n",d->val.int8);
                            }
                            break;
			    */
                    }
                }
            }
            sdp_list_free( (sdp_list_t*)p->data, 0 );
        }
        sdp_list_free( proto_list, 0 );

        }

        printf("found service record 0x%x\n", rec->handle);

        sdp_record_free( rec );
    }

    printf("finish sdp search \n");
    sdp_close(session);

    *result = 1;
    return (void*)result;
}

int _sdp_search(char* mac, char* uuid, int* psm){
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0xAB, 0xCD };
    uuid_t svc_uuid;
    int err;
    bdaddr_t target;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    sdp_session_t *session = 0;
    clock_t start, end;
    char __mac[17];

    start = clock();

    printf("search SDP protocol[%s][%s]\n", mac, uuid);

    //str2ba( "B8:27:EB:BB:62:35", &target );
    //
    //

    //memcpy(__mac, mac, 17);
    str2ba(mac, &target);
    // connect to the SDP server running on the remote machine
    //session = sdp_connect( BDADDR_ANY, &target, SDP_RETRY_IF_BUSY );
    session = sdp_connect( BDADDR_ANY, &target, 0);

    if(session == NULL) {
	    printf("session NULL\n");
    		sdp_close(session);
	    return -1;
    }
    // specify the UUID of the application we're searching for
    
    //_str2uuid("00001101-0000-1000-8000-00805F9B34FB",&svc_uuid);
    //_str2uuid(uuid, &svc_uuid);

    //_str2uuid("0000110c-0000-1000-8000-00805f9b34fb", &svc_uuid);
    _str2uuid("0000111f-0000-1000-8000-00805f9b34fb", &svc_uuid);
    //sdp_uuid128_create( &svc_uuid, &svc_uuid_int );
    search_list = sdp_list_append( NULL, &svc_uuid );

    // specify that we want a list of all the matching applications' attributes
    uint32_t range = 0x0000ffff;
    attrid_list = sdp_list_append( NULL, &range );

    // get a list of service records that have UUID 0xabcd
    err = sdp_service_search_attr_req( session, search_list, \
            SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
    sdp_list_t *r = response_list;

    if(response_list == NULL) {
	    printf("[%d]response NULL\n",err);
    	    sdp_close(session);
	    return -1;
    }
    printf("err: %d\n",err);
    // go through each of the service records
    for (; r; r = r->next ) {
        sdp_record_t *rec = (sdp_record_t*) r->data;
        sdp_list_t *proto_list;
        
	// get a list of the protocol sequences
        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
        sdp_list_t *p = proto_list;

        // go through each protocol sequence
        for( ; p ; p = p->next ) {
            sdp_list_t *pds = (sdp_list_t*)p->data;

            // go through each protocol list of the protocol sequence
            for( ; pds ; pds = pds->next ) {

                // check the protocol attributes
                sdp_data_t *d = (sdp_data_t*)pds->data;
                int proto = 0;
                for( ; d; d = d->next ) {
                    switch( d->dtd ) {
			    
                        case SDP_UUID16:
                        case SDP_UUID32:
                        case SDP_UUID128:
                            proto = sdp_uuid_to_proto( &d->val.uuid );
			    
                            break;
			case SDP_UINT16:
                            if( proto == L2CAP_UUID ) {
                                printf("uint16 l2cap port: %ld\n",d->val.uint16);
				//Connect to Main Device
				*psm = d->val.uint16;
                            }
			    break;
			    /*
                        case SDP_UINT8:
                            if( proto == RFCOMM_UUID ) {
                                printf("rfcomm channel: %d\n",d->val.int8);
                            }
			    
                            if( proto == L2CAP_UUID ) {
                                printf("l2cap port: %d\n",d->val.int8);
                            }
                            break;
			    */
                    }
                }
            }
            sdp_list_free( (sdp_list_t*)p->data, 0 );
        }
        sdp_list_free( proto_list, 0 );

        }

        printf("found service record 0x%x\n", rec->handle);

        sdp_record_free( rec );
    }

    end = clock();

    printf("The SDP Search elapse time : %fs\n",(double) (end - start)/CLOCKS_PER_SEC);

    printf("finish sdp search \n");
    sdp_close(session);
    session = NULL;
	
    return 1;
}

int sdp_search(int* psm){
    uint8_t svc_uuid_int[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
        0, 0, 0xAB, 0xCD };
    uuid_t svc_uuid;
    int err;
    bdaddr_t target;
    sdp_list_t *response_list = NULL, *search_list, *attrid_list;
    sdp_session_t *session = 0;

    printf("search SDP protocol\n");

    //str2ba( "B8:27:EB:BB:62:35", &target );
    str2ba( cfg.maindevicemac, &target);

    // connect to the SDP server running on the remote machine
    session = sdp_connect( BDADDR_ANY, &target, SDP_RETRY_IF_BUSY );

    if(session == NULL) {
	    printf("NULL\n");
	    return -1;
    }
    // specify the UUID of the application we're searching for
    
    //_str2uuid("00001101-0000-1000-8000-00805F9B34FB",&svc_uuid);
    _str2uuid(cfg.maindeviceuuid, &svc_uuid);
    //_str2uuid("0000110c-0000-1000-8000-00805f9b34fb", &svc_uuid);
    
    //sdp_uuid128_create( &svc_uuid, &svc_uuid_int );
    search_list = sdp_list_append( NULL, &svc_uuid );

    // specify that we want a list of all the matching applications' attributes
    uint32_t range = 0x0000ffff;
    attrid_list = sdp_list_append( NULL, &range );

    // get a list of service records that have UUID 0xabcd
    err = sdp_service_search_attr_req( session, search_list, \
            SDP_ATTR_REQ_RANGE, attrid_list, &response_list);
    sdp_list_t *r = response_list;

    if(response_list == NULL) {
	    printf("NULL\n");
	    return -1;
    }
    printf("err: %d\n",err);
    // go through each of the service records
    for (; r; r = r->next ) {
        sdp_record_t *rec = (sdp_record_t*) r->data;
        sdp_list_t *proto_list;
        
	// get a list of the protocol sequences
        if( sdp_get_access_protos( rec, &proto_list ) == 0 ) {
        sdp_list_t *p = proto_list;

        // go through each protocol sequence
        for( ; p ; p = p->next ) {
            sdp_list_t *pds = (sdp_list_t*)p->data;

            // go through each protocol list of the protocol sequence
            for( ; pds ; pds = pds->next ) {

                // check the protocol attributes
                sdp_data_t *d = (sdp_data_t*)pds->data;
                int proto = 0;
                for( ; d; d = d->next ) {
                    switch( d->dtd ) {
                        case SDP_UUID16:
                        case SDP_UUID32:
                        case SDP_UUID128:
                            proto = sdp_uuid_to_proto( &d->val.uuid );
			    
                            break;
			case SDP_UINT16:
                            if( proto == L2CAP_UUID ) {
                                printf("uint16 l2cap port: %ld\n",d->val.uint16);
				//Connect to Main Device
				*psm = d->val.uint16;
                            }
			    break;
                        case SDP_UINT8:
                            if( proto == RFCOMM_UUID ) {
                                printf("rfcomm channel: %d\n",d->val.int8);
                            }
			    
                            if( proto == L2CAP_UUID ) {
                                printf("l2cap port: %d\n",d->val.int8);
                            }
                            break;
                    }
                }
            }
            sdp_list_free( (sdp_list_t*)p->data, 0 );
        }
        sdp_list_free( proto_list, 0 );

        }

        printf("found service record 0x%x\n", rec->handle);

        sdp_record_free( rec );
    }

	sdp_list_free( response_list, 0 );
	sdp_list_free( search_list, 0 );
	sdp_list_free( attrid_list, 0 );

    printf("finish sdp search \n");
    sdp_close(session);

    return 1;
}

