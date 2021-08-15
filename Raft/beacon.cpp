#include<iostream>
#include<chrono>

#include<sys/socket.h>      //PF_INET
#include<arpa/inet.h>       //IPPROTO_TCP


#define BEACONIP "127.0.0.5"
#define BEACONPORT 8000

using namespace std;


struct messagetobeacon{
    char ipaddr[16];
    unsigned char publickey[158+2];
};

struct messagefrombeacon{
    struct messagetobeacon* entries;
    uint8_t noofentries;
    
    messagefrombeacon(int MAXNOOFNODES){
    	entries = new struct messagetobeacon[MAXNOOFNODES];
    }
    
//    ~messagefrombeacon(){
//    	delete[] entries;
//    }

};


int main(int argc, char* argv[]){

	int MAXNOOFNODES = atoi(argv[1]);

    int main_socketid = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(main_socketid==-1){
        std::cerr<<"Could not create the server"<<std::endl;
        return 1;
    }

    struct sockaddr_in main_portaddr;
    main_portaddr.sin_family=AF_INET;
    main_portaddr.sin_port = htons(BEACONPORT);
    main_portaddr.sin_addr.s_addr = inet_addr(BEACONIP);

    int status = bind(main_socketid, (struct sockaddr*)&main_portaddr, sizeof(main_portaddr));
    if (status==-1){
        std::cerr<<"Could not bind the socket"<<std::endl;
        return 1;
    }

    status = listen(main_socketid, 3);
    if (status==-1){
        std::cerr<<"Could not start listening"<<std::endl;
        return 1;
    }

    struct messagefrombeacon msgfrmbcn(MAXNOOFNODES);

    int newsocketid[MAXNOOFNODES];
    int counter=0;

    struct sockaddr_in clientportaddr;
    socklen_t clntLen = sizeof(clientportaddr);

    for (int j=0;j<MAXNOOFNODES;j++){

        std::cout<<"server running"<<std::endl;

        newsocketid[counter]=accept(main_socketid,(struct sockaddr *)&clientportaddr,&clntLen);
        if (newsocketid[counter] == -1){
            std::cerr<<"Could not accept the request"<<std::endl;
            exit(0);
        }
        status=recv(newsocketid[counter], &msgfrmbcn.entries[counter], sizeof(struct messagetobeacon),0);
        if(status!=sizeof(struct messagetobeacon)){
		    std::cerr<<"Could not receive the complete message"<<std::endl;
		}
        counter++;
    }
    cout<<msgfrmbcn.entries[3].ipaddr<<endl;
    

    msgfrmbcn.noofentries=counter;
    cout<<counter<<endl;

    for(int i=0;i<counter;i++){
        status = send(newsocketid[i], &msgfrmbcn.entries[0], sizeof(struct messagetobeacon)*MAXNOOFNODES, 0);
        if(status!=sizeof(struct messagetobeacon)*MAXNOOFNODES){
            std::cerr<<"Could not send the complete message"<<std::endl;
        }
    }

    printf("Exiting");
}
