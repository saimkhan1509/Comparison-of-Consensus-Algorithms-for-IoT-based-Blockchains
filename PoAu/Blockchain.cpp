#include<iostream>
#include<vector>
#include<string>
#include<pthread.h>
#include<random>
#include<cstring>   //memset()
#include <map>      //map
#include <netdb.h>  //IP retreival

#include <openssl/sha.h> //SHA256()

#include <stdio.h>

#include "cryptohelper.h"
#include "talktobeacon.h"
//#include "sendreceivetx.h"

#include <unistd.h>  //usleep()
#include <chrono>


#define NO_OF_TRANSACTIONS 10  // Upperlimit on no of transactions in a block
#define KEYLENGTH 512
#define DATESIZE 20
#define MYPORTNO 6000
#define MYBLOCKPORTNO 12000


using namespace std;



void settransactionzero(struct tx& trnsc);
int generatemykeypair(unsigned char* mypublickey, unsigned char* myprivatekey);

class transactionpool;
class block;
class blockchain;


/* The strncpy() function is similar to strcpy() function, except that at most n bytes of src are copied.
 If there is no NULL character among the first n character of src, the string placed in dest will not be NULL-terminated.
 If the length of src is less than n, strncpy() writes additional NULL character to dest to ensure that a total of n character are written. */

/* Second argument of strcpy() needs to be nul terminated, and the first needs to fit the number of characters in source + the nul terminator.*/

/* Assumption: SHA256(), publicdecrypt(), privateencrypt() are not affected by '\0' in the string*/



struct tx{
    uint16_t meterreading;
    uint16_t keyindex;
    unsigned char datetime[DATESIZE];  //DDMMYYHHMMSSMMM
    unsigned char signature[66];
};

struct txwithptr{
    struct txwithptr* prev;
    struct txwithptr* next;
    struct tx transaction;

};

struct sendparam{
    class transactionpool* tp;
    int mykeyindex;
    unsigned char* myprivatekey;
    int MAXNOOFNODES;
    char* MYIP;
    double blockrate;
    int transactionrate;
};

struct sendrecvblockparam{
    class blockchain* bc;
    class transactionpool* tp;
    int mykeyindex;
    unsigned char* myprivatekey;
    int MAXNOOFNODES;
    char* MYIP;
    double blockrate;
};

struct messagefrombeacon* ipandkeys;
int mykeyindex;



class transactionpool{

public:

    struct txwithptr* unconfirmedtxfirst;
    struct txwithptr* unconfirmedtxlast;
    uint16_t counter;
    pthread_mutex_t tp_mutex;


    transactionpool(){
        unconfirmedtxfirst = nullptr;       // Pointers not nullptr by default
        unconfirmedtxlast = nullptr;        // Pointers not nullptr by default
        counter=0;
        tp_mutex = PTHREAD_MUTEX_INITIALIZER;
    }


    void addreceivedtx(struct tx& received){
        // ADD Signature verification
        unsigned char plaintext[KEYLENGTH/8+1];
        memset(plaintext, 0, KEYLENGTH/8+1);
        unsigned char decrypted[KEYLENGTH/8+1];
        memset(decrypted, 0, KEYLENGTH/8+1);

//        memcpy(&plaintext[0], &(received.meterreading), sizeof(received.meterreading));
//        memcpy(&plaintext[sizeof(received.meterreading)], &(received.keyindex), sizeof(received.keyindex));
//        memcpy(&plaintext[sizeof(received.meterreading)+sizeof(received.keyindex)], received.datetime, DATESIZE);
//        memset(&plaintext[sizeof(received.meterreading)+sizeof(received.keyindex)+DATESIZE],'0',(KEYLENGTH/8)-DATESIZE-sizeof(received.keyindex)-sizeof(received.meterreading));


        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE-sizeof(received.keyindex)-sizeof(received.meterreading)], &(received.meterreading), sizeof(received.meterreading));
        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE-sizeof(received.keyindex)], &(received.keyindex), sizeof(received.keyindex));
        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE], received.datetime, DATESIZE);
        memset(plaintext,'0',(KEYLENGTH/8)-DATESIZE-sizeof(received.keyindex)-sizeof(received.meterreading));


        int decrypted_length = public_decrypt(received.signature, KEYLENGTH/8, ipandkeys->entries[received.keyindex].publickey, decrypted);
        
        //cout<<"decrypted: "<<decrypted<<endl;
        //cout<<"plaintext: "<<plaintext<<endl;
        
        if(decrypted_length == -1)
        {
            cout<<"Public Decrypt failed";
        }

        if(strcmp((char*)decrypted, (char*)plaintext)!=0){
            cout<<"Signature does not match\n";
            return ;
        };



        struct txwithptr* mycopy = (struct txwithptr*)malloc(sizeof(struct txwithptr)+1);
        memset(mycopy,0,sizeof(struct txwithptr)+1);        // Null termination
        memcpy(&(mycopy->transaction), &received, sizeof(struct tx));


        pthread_mutex_lock(&tp_mutex);           // Taking LOCK
        if(!unconfirmedtxfirst)
            unconfirmedtxfirst = mycopy;
        mycopy->prev = unconfirmedtxlast;
        if(unconfirmedtxlast)
            unconfirmedtxlast->next = mycopy;
        unconfirmedtxlast = mycopy;
        mycopy->next=nullptr;
        pthread_mutex_unlock(&tp_mutex);           // Releasing LOCK

        counter = counter+1;
        
        //printf("Counter: \n%hu\n",counter);
        
        //cout<<"Added received transaction\n";

    }


    int retreivetransactions(struct tx* ret){
        while (counter<NO_OF_TRANSACTIONS){
            cout<<"Transaction pool has only "<<counter<<" transactions"<<endl;
            usleep(100000);
        }
        struct txwithptr* ptr = unconfirmedtxfirst;
        for(int i=0;i<NO_OF_TRANSACTIONS;i++){
            memset(&ret[i],0, sizeof(struct tx));
            memcpy(&ret[i], &(ptr->transaction), sizeof(struct tx));

            ptr=ptr->next;
        }
        return 0;
    }


//    int free100transactions(){
//        for(int i=0;i<NO_OF_TRANSACTIONS;i++){
//            free(unconfirmedtxfirst);
//            unconfirmedtxfirst = unconfirmedtxfirst->next;
//        }
//        unconfirmedtxfirst->prev = nullptr;
//        counter = counter-NO_OF_TRANSACTIONS;
//        return 0;
//    };


    struct tx* addtransaction(uint16_t meterreading, uint16_t keyindex, unsigned char* datetime, unsigned char* myprivatekey){
        struct txwithptr* newtxwithptr = (struct txwithptr*)malloc(sizeof(struct txwithptr));
        newtxwithptr->transaction.meterreading = meterreading;
        newtxwithptr->transaction.keyindex = keyindex;
        memset(newtxwithptr->transaction.datetime, 0, DATESIZE);
        strncpy((char*)newtxwithptr->transaction.datetime, (const char*)datetime, DATESIZE-1);


        unsigned char plaintext[KEYLENGTH/8+1];
        memset(plaintext, 0, KEYLENGTH/8+1);
        memset(newtxwithptr->transaction.signature, 0, 66);


//        memcpy(&plaintext[0], &meterreading, sizeof(meterreading));
//        memcpy(&plaintext[sizeof(meterreading)], &keyindex, sizeof(keyindex));
//        memcpy(&plaintext[sizeof(meterreading)+sizeof(keyindex)], &newtxwithptr->transaction.datetime, DATESIZE);
//        memset(&plaintext[sizeof(meterreading)+sizeof(keyindex)+DATESIZE],'0',(KEYLENGTH/8)-DATESIZE-sizeof(keyindex)-sizeof(meterreading));

        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE-sizeof(keyindex)-sizeof(meterreading)], &meterreading, sizeof(meterreading));
        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE-sizeof(keyindex)], &keyindex, sizeof(keyindex));
        memcpy(&plaintext[(KEYLENGTH/8)-DATESIZE], &newtxwithptr->transaction.datetime, DATESIZE);
        memset(&plaintext[0],'0',(KEYLENGTH/8)-DATESIZE-sizeof(keyindex)-sizeof(meterreading));
        

//        std::cout<<std::endl;
//        for(int i=0;i<64;i++){
//            printf("%02x",plaintext[i]);
//        }
//        std::cout<<std::endl;

        int encrypted_length;
        do {
            encrypted_length= private_encrypt(plaintext, KEYLENGTH/8, myprivatekey, newtxwithptr->transaction.signature);
            if(encrypted_length == -1)
            {
                cout<<"Private Encrypt failed";
                usleep(100000);
            }
        }
        while(encrypted_length == -1);


//        for(int i=0;i<64;i++){
//            printf("%02x",newtxwithptr->transaction.signature[i]);
//        }

        pthread_mutex_lock(&tp_mutex);           // Taking LOCK
        if(unconfirmedtxfirst==nullptr)
            unconfirmedtxfirst = newtxwithptr;
        newtxwithptr->prev = unconfirmedtxlast;
        if(unconfirmedtxlast)
            unconfirmedtxlast->next = newtxwithptr;
        unconfirmedtxlast = newtxwithptr;
        newtxwithptr->next=nullptr;
        pthread_mutex_unlock(&tp_mutex);        // Releasing LOCK

        counter+=1;
        //printf("Counter: \n%hu\n",counter);

        return &(newtxwithptr->transaction);
    }
    
    int removetxs(block blk);

};



class block{

    public:

    block* prev; // 8

    unsigned char previousblockhash[33];
    unsigned char transactionhash[33];  //Hash of contained transaction data SHA256
    uint32_t blockno;  // 4

    uint32_t numberoftransactions; // 4       Padding creates issue
    block* next; // 8
    struct tx transactions[NO_OF_TRANSACTIONS]; // 86*100



    void retreivetxs(transactionpool& tp){
        tp.retreivetransactions(transactions);
    };

    void calculatetxhash(){
        unsigned char ibuf[NO_OF_TRANSACTIONS*sizeof(struct tx)+1];
        memset(ibuf,0,NO_OF_TRANSACTIONS*sizeof(struct tx)+1);
        for(int i=0;i<NO_OF_TRANSACTIONS;i++){
            memcpy(&ibuf[i*sizeof(struct tx)], &transactions[i], sizeof(struct tx));
        }
        SHA256(ibuf, NO_OF_TRANSACTIONS*sizeof(struct tx), transactionhash);
    }


    void setuptheblock(blockchain* bc, transactionpool* tp);


    bool verifytransactions(){
        unsigned char decrypted[KEYLENGTH/8+1];  // keysize = 512 bits
        unsigned char encrypted[KEYLENGTH/8+1];
        unsigned char plaintext[KEYLENGTH/8+1];
        memset(encrypted, 0, KEYLENGTH/8 +1);
        memset(plaintext, 0, KEYLENGTH/8+1);

        for(int i=0;i<NO_OF_TRANSACTIONS;i++){
            //unsigned char publickey[64] = keymap[i];
            memcpy(encrypted, transactions[i].signature, KEYLENGTH/8);
            memset(decrypted, 0, KEYLENGTH/8 +1);
            int decrypted_length= public_decrypt(encrypted, KEYLENGTH/8, ipandkeys->entries[transactions[i].keyindex].publickey, decrypted);
            if(decrypted_length == -1){
                cout<<"Public Decrypt failed\n";
                return false;
            }
            //printf("Decrypted length =%d\n",decrypted_length);
            memset(plaintext, '0', KEYLENGTH/8 - sizeof(transactions[i].meterreading)-sizeof(transactions[i].keyindex)-DATESIZE);  // Padding '0'
            memcpy(&plaintext[KEYLENGTH/8 - sizeof(transactions[i].meterreading)-sizeof(transactions[i].keyindex)-DATESIZE]
                   , (unsigned char*)&(transactions[i].meterreading), sizeof(transactions[i].meterreading));
            memcpy(&plaintext[KEYLENGTH/8 -sizeof(transactions[i].keyindex)-DATESIZE]
                   , (unsigned char*)&(transactions[i].keyindex), sizeof(transactions[i].keyindex));
            memcpy(&plaintext[KEYLENGTH/8 -DATESIZE]
                   , (unsigned char*)&(transactions[i].datetime), DATESIZE);
                   
			
            if(strcmp((char*)decrypted, (char*)plaintext)!=0){
            	cout<<decrypted<<endl;
            	cout<<plaintext<<endl;
                cout<<"Signature does not match\n";
                return false;
            };
        }
        cout<<"Transaction verification successful\n";
        return true;
    }


    unsigned char* blockheaderhash(unsigned char* obuf){
        unsigned char ibuf[32+32+4+1];
        memset(ibuf,0, 32+32+4+1);
        memcpy(&ibuf[0], previousblockhash, 32);
        memcpy(&ibuf[32], transactionhash, 32);
        memcpy(&ibuf[64], &blockno, 4);
        SHA256(ibuf, 68, obuf);
        return obuf;
    }


    void printblock(){
        printf("previousblockhash= ");
        for(int j=0;j<32;j++){
                    printf("%02x",previousblockhash[j]);
            }
        cout<<endl;
        printf("transactionhash= ");
        for(int j=0;j<32;j++){
                    printf("%02x",transactionhash[j]);
            }
        cout<<endl;
        for(int i =0; i<NO_OF_TRANSACTIONS;i++){
            cout<<transactions[i].meterreading<<endl;
            cout<<transactions[i].keyindex<<endl;
            cout<<transactions[i].datetime<<endl;
            printf("signature= ");
            for(int j=0;j<KEYLENGTH/8;j++){
                    printf("%02x",transactions[i].signature[j]);
            }
            cout<<endl;
        }

    }

};


int transactionpool::removetxs(block blk){
    struct txwithptr* ptr;
    //cout<<"Counter: "<<counter<<endl;
    pthread_mutex_lock(&tp_mutex);           // Taking LOCK
    for(int i=0;i<NO_OF_TRANSACTIONS;i++){
    	ptr = unconfirmedtxfirst;
        while(ptr!=nullptr && strncmp((const char*)ptr->transaction.signature, (const char*)blk.transactions[i].signature, 64)){
            ptr=ptr->next;
        }
        if(ptr!=nullptr){
            if(ptr->prev!=nullptr)
                ptr->prev->next=ptr->next;
            if(ptr->next!=nullptr)
                ptr->next->prev=ptr->prev;
            if(ptr==unconfirmedtxfirst)
                unconfirmedtxfirst=unconfirmedtxfirst->next;
            if(ptr==unconfirmedtxlast)
                unconfirmedtxlast=unconfirmedtxlast->prev;
            counter--;
        }
        free(ptr);
    }
    //cout<<"Counter: "<<counter<<endl;
    pthread_mutex_unlock(&tp_mutex);           // Taking LOCK

    return 0;
};



class blockchain{

    public:
    
    int maxlatency;
    int totallatency;

    block genesisblock;
    block* lastblockptr;

    block* orphanblockptrfirst;
    block* orphanblockptrlast;

    int noofblocks;


    blockchain(){
    	maxlatency=0;
    	totallatency=0;
        orphanblockptrfirst = nullptr;
        orphanblockptrlast = nullptr;

        genesisblock.prev=nullptr;
        memset(genesisblock.previousblockhash, 0, 33);
        memset(genesisblock.previousblockhash, '0', 32);
        genesisblock.numberoftransactions = NO_OF_TRANSACTIONS;
        for (int i=0;i<NO_OF_TRANSACTIONS;i++){
            memset(&genesisblock.transactions[i],'2',sizeof(struct tx));
        }
        memset(genesisblock.transactionhash, 0, 33);
        genesisblock.calculatetxhash();
        genesisblock.blockno = 0;
        genesisblock.next=nullptr;

        lastblockptr = &genesisblock;
        noofblocks = 1;
    }



    block* lookinorphanblocks(unsigned char* previousblockhash){
        block* ptr = orphanblockptrlast;
        unsigned char blckhdrhash[33];
        memset(blckhdrhash, 0, 33);
        cout<<"0\n";
        while(ptr!=nullptr && strncmp((const char*)ptr->blockheaderhash(blckhdrhash), (const char*)previousblockhash, 32)){
            cout<<"a\n";
            ptr=ptr->prev;
        }
        cout<<"1\n";
        if(ptr==nullptr)
           return 0;
        else{
            if(ptr->prev!=nullptr){
                if(ptr->next!=nullptr){
                    ptr->prev->next=ptr->next;
                    ptr->next->prev=ptr->prev;
                }
                else ptr->prev->next=nullptr;
            }
            else{
                if(ptr->next!=nullptr){
                    orphanblockptrlast=ptr->next;
                    ptr->next->prev=nullptr;
                }
                else orphanblockptrlast=nullptr;
            }
            return ptr;
        }
    }

    void appendorphanblock(block& newblock){
        block* newblockcopy = (block*)malloc(sizeof(block));
        memcpy(newblockcopy, &newblock, sizeof(block));

        newblockcopy->next = nullptr;
        newblockcopy->prev = orphanblockptrlast;
        if(orphanblockptrlast!=nullptr)
            orphanblockptrlast->next = newblockcopy;
        orphanblockptrlast = newblockcopy;
    }


    int appendnewblock(transactionpool* tp, block& newblock, struct messagefrombeacon* ipandkeys){
        if (!newblock.verifytransactions()){
            cout<<"transaction verification failed\n";
            return 0;
        }
        tp->removetxs(newblock);

        block* ptr = lastblockptr;
        unsigned char blckhdrhash[33];
        memset(blckhdrhash, 0, 33);
        while(ptr!=nullptr && strncmp((const char*)ptr->blockheaderhash(blckhdrhash), (const char*)newblock.previousblockhash, 32)){
            ptr=ptr->prev;
        }
        if(ptr==nullptr){
            cout<<"Parent not found\n";
            block* adjustedblock;
            if ((adjustedblock = lookinorphanblocks(newblock.previousblockhash))==0){
                appendorphanblock(newblock);       ///////////////////////////////////////
                cout<<"Block moved to orphaned pool\n";
                return 0;
            }
            else{
                cout<<"old block recovered\n";

                adjustedblock->next = nullptr;
                adjustedblock->prev = lastblockptr;     // Take orphan tx and append to the blockchain
                if(lastblockptr!=nullptr)
                    lastblockptr->next = adjustedblock;
                lastblockptr = adjustedblock;
            }
        }
        

        block* newblockcopy = (block*)malloc(sizeof(block));
        memcpy(newblockcopy, &newblock, sizeof(block));

        newblockcopy->next = nullptr;
        newblockcopy->prev = lastblockptr;
        lastblockptr->next = newblockcopy;
        lastblockptr = newblockcopy;

        cout<<"Block No "<<newblockcopy->blockno<<" added"<<endl;
        //cout<<newblock.numberoftransactions<<" "<<newblockcopy->numberoftransactions<<endl;
        cout<<newblock.previousblockhash<<"--"<<newblockcopy->previousblockhash<<endl;

        unsigned long long reqtime10 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        reqtime10 = ( reqtime10 + 19800000)%86400000;
        
        char buffer[10];
        unsigned long long ai=0;
        unsigned long long reqtime11;
        
        
        for(int i=0;i<NO_OF_TRANSACTIONS;i++){
        	memset(buffer,0,10);
        	strcpy(buffer,(const char*)newblock.transactions[i].datetime+10);
        	if(strlen(buffer)==7){
        		buffer[8]=buffer[6];
        		buffer[7]='0';
        		buffer[6]='0';
        	}
        	else if(strlen(buffer)==8){
        		buffer[8]=buffer[7];
        		buffer[7]=buffer[6];
        		buffer[6]='0';
        	}
        	ai=atoi(buffer);
        	//cout<<ai<<endl;
        	reqtime11=(ai%100000+((ai/100000)%100)*60000+((ai/10000000)%100)*3600000);
        	ai=reqtime10-reqtime11;
        	
        	maxlatency = maxlatency>ai?maxlatency:ai;
        	totallatency=totallatency+ai;
        }
        
       	cout<<"Block No "<<newblockcopy->blockno<<" added\n\n\n"<<endl;

        noofblocks++;

        return 0;
    }

    void printblockchain(){
        int counter=0;
        block* ptr = &genesisblock;
        while(ptr!=nullptr){
            cout<<"BlockNo: "<<counter<<endl;
            cout<<ptr->previousblockhash<<endl;
            //cout<<ptr->transactionhash<<endl;
            //for(int i=0;i<NO_OF_TRANSACTIONS;i++){
                //cout<<ptr->transactions[i].meterreading<<endl;
                //cout<<ptr->transactions[i].keyindex<<endl;
                //cout<<ptr->transactions[i].datetime<<endl;
                //cout<<ptr->transactions[i].signature<<endl;
            //}
            cout<<endl;
            counter++;
            ptr=ptr->next;
        }
    }
};



void block::setuptheblock(blockchain* bc, transactionpool* tp){

    memset(previousblockhash, 0, 33);
    (*bc).lastblockptr->blockheaderhash(previousblockhash);

    numberoftransactions = NO_OF_TRANSACTIONS;

    (*tp).retreivetransactions(transactions);
    memset(transactionhash, 0, 33);

    blockno = (*bc).noofblocks;

    calculatetxhash();
}



void* sendfunc (void* arg){
    class transactionpool* tp = ((struct sendparam*)arg)->tp;
    int mykeyindex = ((struct sendparam*)arg)->mykeyindex;
    unsigned char* myprivatekey = ((struct sendparam*)arg)->myprivatekey;
    int MAXNOOFNODES = ((struct sendparam*)arg)->MAXNOOFNODES;
    double blockrate = ((struct sendparam*)arg)->blockrate;
    int transactionrate = ((struct sendparam*)arg)->transactionrate;

    int status;

    int clientsockid;
    int sockarr[MAXNOOFNODES];
    
    struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 500000;

	
	int j;

    for(int i=mykeyindex+1;i<mykeyindex+MAXNOOFNODES;i++){

		j=i%MAXNOOFNODES;
		
        clientsockid = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);

        sockarr[j]=clientsockid;

        if(clientsockid==-1)
        {
            std::cerr<<"Could not create the server"<<std::endl;
            return nullptr;
        }

        struct sockaddr_in portaddr;
        portaddr.sin_family=AF_INET;
        portaddr.sin_port = htons(MYPORTNO);        // Destination Port No+

        inet_pton(AF_INET, ipandkeys->entries[j].ipaddr, &portaddr.sin_addr.s_addr);

        status=connect(clientsockid, (struct sockaddr *) &portaddr,sizeof(portaddr));
        if(status==-1)
        {
            std::cerr<<"Could not connect to the server"<<std::endl;
            cout<<ipandkeys->entries[j].ipaddr<<endl;
            return nullptr;
        }
    }

    uint16_t meterreading = 100*mykeyindex;

    unsigned long long int reqtime;
    time_t rawtime;
    struct tm* timeinfo;
    char buffer[80];
    srand(time(0));

    struct tx* txptr;
    char buf[sizeof(struct tx)+1];
    memset(buf,0,sizeof(struct tx)+1);

	
	
    while(true){

        time (&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer,80,"%d%m%Y--%H%M%S",timeinfo);

        reqtime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        reqtime = (reqtime + 19800000)%86400000;                   //A day consists of 86400000 milliseconds. 19800000 added to adjust international time delay.
        string s(buffer);
        s = s+to_string(reqtime%1000);


        txptr = tp->addtransaction(meterreading, mykeyindex, (unsigned char*)s.c_str(), myprivatekey);



        memcpy(buf, txptr, sizeof(struct tx));

        for(int i=mykeyindex+1;i<mykeyindex+MAXNOOFNODES;i++){
        
        	j=i%MAXNOOFNODES;

            status = send(sockarr[j], buf, sizeof(struct tx), 0);       // Don't send a struct. Instead copy struct to char[] and send the char[].
            if(status!=sizeof(struct tx)){
                std::cerr<<"Could not send the complete message"<<std::endl;
            }
            else
                //cout<<"Sent a transaction\n\n";
				;
        }

        meterreading++;
        usleep(rand()%(1000000/transactionrate));
    }

}




void* recvfunc(void* arg){

    class transactionpool* tp = ((struct sendparam*)arg)->tp;
    int mykeyindex = ((struct sendparam*)arg)->mykeyindex;
    unsigned char* myprivatekey = ((struct sendparam*)arg)->myprivatekey;
    int MAXNOOFNODES = ((struct sendparam*)arg)->MAXNOOFNODES;
    char* MYIP = ((struct sendparam*)arg)->MYIP;
    

    int main_socketid = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(main_socketid==-1)
    {
        std::cerr<<"Could not create the main receiving socket"<<std::endl;
        return nullptr;
    }


    struct sockaddr_in main_portaddr;
    main_portaddr.sin_family=AF_INET;
    main_portaddr.sin_port = htons(MYPORTNO);
    main_portaddr.sin_addr.s_addr = inet_addr(MYIP);

    int status = bind(main_socketid, (struct sockaddr*)&main_portaddr, sizeof(main_portaddr));
    if (status==-1)
    {
        std::cerr<<"Could not bind the socket"<<std::endl;
        return nullptr;
    }

    status = listen(main_socketid, 100);
    if (status==-1)
    {
        std::cerr<<"Could not start listening"<<std::endl;
        return nullptr;
    }

    int newsocketid[MAXNOOFNODES];

    struct sockaddr_in clientportaddr;
    socklen_t clntLen = sizeof(clientportaddr);

    for (int j=0;j<MAXNOOFNODES;j++){
        if (j==mykeyindex) continue;

        std::cout<<"server running"<<std::endl;

        newsocketid[j]=accept(main_socketid,(struct sockaddr *)&clientportaddr,&clntLen);
        if (newsocketid[j] == -1){
            std::cerr<<"Could not accept the request"<<std::endl;
            exit(0);
        }
    }

    fd_set currentsockets, readysockets;                    // Creating fd sets for select() function
    int maxfd=0;
    FD_ZERO (&currentsockets);
    for(int k=0;k<MAXNOOFNODES;k++){
        if (k==mykeyindex) continue;
        FD_SET(newsocketid[k],&currentsockets);
        maxfd=maxfd>newsocketid[k]?maxfd:newsocketid[k];
    }
    struct timeval tv;                                      // Setting waiting time for select() function
    tv.tv_sec=0;
    tv.tv_usec = 100;


    struct tx receivedtx;

    while(true){
        readysockets=currentsockets;
        select(maxfd+1,&readysockets,NULL,NULL,&tv);
        for(int i=0;i<MAXNOOFNODES;i++){                  // RECEIVE EVENTS
        	if (i==mykeyindex) continue;
            memset(&receivedtx, 0, sizeof(struct tx));
            if(FD_ISSET(newsocketid[i], &readysockets)){
                status = recv(newsocketid[i], &receivedtx, sizeof(struct tx), 0);
                if(status!=sizeof(struct tx)){
                    std::cerr<<"Could not receive the complete message"<<std::endl;
                }
                else{
                    tp->addreceivedtx(receivedtx);
                }
            }


        }
    }
}




void* sendrecvblockfunc(void* arg){
    class blockchain* bc = ((struct sendrecvblockparam*)arg)->bc;
    class transactionpool* tp = ((struct sendrecvblockparam*)arg)->tp;
    int mykeyindex = ((struct sendrecvblockparam*)arg)->mykeyindex;
    unsigned char* myprivatekey = ((struct sendrecvblockparam*)arg)->myprivatekey;
    int MAXNOOFNODES = ((struct sendrecvblockparam*)arg)->MAXNOOFNODES;
    char* MYIP = ((struct sendrecvblockparam*)arg)->MYIP;
    double blockrate = ((struct sendrecvblockparam*)arg)->blockrate;
    


    int mysocketid = socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(mysocketid==-1)
    {
        std::cerr<<"Could not create the sending socket"<<std::endl;
        return nullptr;
    }

    struct sockaddr_in myportaddr;
    myportaddr.sin_family=AF_INET;
    myportaddr.sin_port = htons(MYBLOCKPORTNO);
    myportaddr.sin_addr.s_addr = inet_addr(MYIP);

    int status = bind(mysocketid, (struct sockaddr*)&myportaddr, sizeof(myportaddr));
    if (status==-1)
    {
        std::cerr<<"Could not bind the socket"<<std::endl;
        return nullptr;
    }

    struct sockaddr_in destportaddr[MAXNOOFNODES];
    for(int i =0; i<MAXNOOFNODES;i++){
        destportaddr[i].sin_family=AF_INET;
        destportaddr[i].sin_port = htons(MYBLOCKPORTNO);
        inet_pton(AF_INET, ipandkeys->entries[i].ipaddr, &destportaddr[i].sin_addr.s_addr);
    }



    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    if (setsockopt(mysocketid, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("Error");
    }


    int leader=0;
    int agreement=1,received=0;
    block blk;
    block recvblk;
    block recvblk2;
    int counter;
    int nummessage=0;


    int blksize = sizeof(block);
    char sendbuffer[sizeof(block)+1];
    char sendbuffer2[sizeof(block)+1];
    memset(sendbuffer, 0, sizeof(block)+1);
    memset(sendbuffer2, 0, sizeof(block)+1);


    int sendmsgsize, recvmsgsize;
    socklen_t clntLen = sizeof(destportaddr[0]);


    unsigned long long int reqtime, reqtime2, reqtime3, reqtime4, reqtime5, reqtime6, reqtime00;
    reqtime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    usleep((4000-reqtime%4000+50)*1000);
    cout<<"Time's up. Let's make some blocks\n";


	int cycletime = 1000.0/blockrate;		// in milli sec
	
	reqtime00 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    while(bc->noofblocks<201){
        reqtime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        usleep((cycletime-reqtime%cycletime)*1000);
        cout<<(reqtime%cycletime)<<endl;

        if(leader==mykeyindex){
            cout<<"I am leader\n";
            blk.setuptheblock(bc, tp);
            memset(sendbuffer, 0, blksize+1);
            memcpy(sendbuffer,(void*)&blk, blksize);
            for(int j=0;j<MAXNOOFNODES;j++){
                if (j==mykeyindex) continue;
                sendmsgsize = sendto(mysocketid, sendbuffer, blksize, 0, (struct sockaddr *)&destportaddr[j], clntLen);
                if (sendmsgsize != blksize)
                    std::cerr<<"send() failed"<<std::endl;
            }
            nummessage=nummessage-1+MAXNOOFNODES;
        }
        else{
            received=0;
            reqtime2 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            reqtime3 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            while((reqtime3-reqtime2 < 3*cycletime/10) && received<1){
		    recvmsgsize = recvfrom(mysocketid, &recvblk, blksize, 0, NULL, &clntLen);
		    if(recvmsgsize!=blksize){
		        std::cerr<<"Could not receive the complete message88888"<<std::endl;
		    }
		    else received++;
		    reqtime3 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();

            }
        }

        reqtime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        usleep((2*cycletime/5-reqtime%(2*cycletime/5))*1000);
        cout<<reqtime%(2*cycletime/5)<<endl;
        cout<<2*cycletime/5-reqtime%(2*cycletime/5)<<endl;
        


        if(leader!=mykeyindex){
            memset(sendbuffer2, 0, blksize+1);
            memcpy(sendbuffer2,(void*)&recvblk, blksize);
            for(int j=0;j<MAXNOOFNODES;j++){
                if (j==mykeyindex) continue;
                sendmsgsize = sendto(mysocketid, sendbuffer2, blksize, 0, (struct sockaddr *)&destportaddr[j], clntLen);
                if (sendmsgsize != blksize)
                    std::cerr<<"sendto() failed"<<std::endl;
            }
            nummessage=nummessage-1+MAXNOOFNODES;
            agreement = 1;
            reqtime4 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            reqtime5 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            while((reqtime5-reqtime4 < cycletime/4) && agreement<MAXNOOFNODES){
                recvmsgsize = recvfrom(mysocketid, &recvblk2, blksize, 0, NULL, &clntLen);
                if (recvmsgsize!= blksize) ///////////////////////////////////////////////////////////////////
                    std::cerr<<"recvfrom() failed2222"<<std::endl;
                if(!strcmp((const char*)recvblk.transactionhash, (const char*)recvblk2.transactionhash)){
                    agreement++;
                }
                reqtime5 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            }
            cout<<"agreement: "<<agreement<<endl;
            if(agreement>(MAXNOOFNODES/2)){
                bc->appendnewblock(tp, recvblk, ipandkeys);
            }

        }

        else{
            cout<<"I am leader\n";
            agreement = 1;
            reqtime4 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            reqtime5 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            while((reqtime5-reqtime4 < 9*cycletime/20) && agreement<MAXNOOFNODES){
            	recvmsgsize = recvfrom(mysocketid, &recvblk2, blksize, 0, NULL, &clntLen);
                if (recvmsgsize!= blksize)
                    std::cerr<<"recvfrom() failed"<<std::endl;
                if(!strcmp((const char*)blk.transactionhash, (const char*)recvblk2.transactionhash))
                    agreement++;
                reqtime5 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            }

            cout<<"agreement: "<<agreement<<endl;
            if(agreement>(MAXNOOFNODES/2)){
                bc->appendnewblock(tp, blk,ipandkeys);
            }
        }
		leader=(leader+1)%MAXNOOFNODES;
		
    }
    reqtime6 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    
    bc->printblockchain();
        
    cout<<"Throughput:"<<200.0*1000/(reqtime6-reqtime00)<<" blocks per sec\n";
    cout<<"MaxLatency:"<<bc->maxlatency<<" millisec\n";
    cout<<"Avglatency:"<<bc->totallatency/2000<<" millisec\n";
    cout<<"No of messages sent for block exchange:"<<nummessage<<"\n";

    return nullptr;
}





int main(int argc, char* argv[]){

	cout<<"here"<<endl;
    cout<<"here"<<endl;
    cout<<"here"<<endl;

	int MAXNOOFNODES = atoi(argv[1]);
	double blockrate = atof(argv[3]);
	double transactionrate = 0;
	
	if(argc>4){
		transactionrate = atof(argv[4]);
	}
	else{
		transactionrate = (double)(NO_OF_TRANSACTIONS*blockrate/MAXNOOFNODES);
	}
	
	
	cout<<MAXNOOFNODES<<endl;
	
	char MYIP[16];
	memset(MYIP,0,16);
	
	if(argc>5){
		strcpy(MYIP,argv[5]);
	}
	else{
		memcpy(MYIP,"127.0.0.",8);
		strcpy(&MYIP[8],argv[2]);
	}
	
	cout<<"My IP: "<<MYIP<<endl;
	


    ERR_load_crypto_strings();
    SSL_load_error_strings();

    unsigned char mypublickey[158+1];
    memset(mypublickey,0,158+1);
    unsigned char myprivatekey[497+1];
    memset(myprivatekey,0,497+1);
    if(generatemykeypair(mypublickey,myprivatekey)){
        cout<<"Couldn't create keypair\n";
    }

    struct messagefrombeacon ipandkeys2(MAXNOOFNODES);
    ipandkeys2 = talktobeacon(mypublickey, MAXNOOFNODES, MYIP);
    ipandkeys = &ipandkeys2;
    

    int i=0;
    while(strcmp((const char*)mypublickey, (const char*)ipandkeys->entries[i].publickey)){
        i++;
    }
    mykeyindex=i;
    
    cout<<"I am node no "<<i<<endl;


    blockchain bc;
    transactionpool tp;
    block blk1;


    struct sendparam param;
    param.tp = &tp;
    param.mykeyindex=mykeyindex;
    param.myprivatekey = myprivatekey;
    param.MAXNOOFNODES = MAXNOOFNODES;
    param.MYIP= MYIP;
    param.blockrate = blockrate;
    param.transactionrate = transactionrate;
    

    pthread_t sendtx, recvtx, sendrecvblock;
    pthread_create(&recvtx, NULL, recvfunc, (void*)&param);
    sleep(2);
    pthread_create(&sendtx, NULL, sendfunc, (void*)&param);




    struct sendrecvblockparam bparam;
    bparam.bc = &bc;
    bparam.tp = &tp;
    bparam.mykeyindex=mykeyindex;
    bparam.myprivatekey = myprivatekey;
    bparam.MAXNOOFNODES = MAXNOOFNODES;
    bparam.MYIP = MYIP;
    bparam.blockrate = blockrate;

	unsigned long long int reqtime0 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    usleep((5000-reqtime0%5000)*1000);
	
    pthread_create(&sendrecvblock, NULL, sendrecvblockfunc, (void*)&bparam);



    pthread_join(sendrecvblock, NULL);
    pthread_join(sendtx, NULL);                                                   // Joining threads
    pthread_join(recvtx, NULL);                                                   // Joining threads

}




