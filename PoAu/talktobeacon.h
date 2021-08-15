#include<arpa/inet.h>




#define BEACONIP "127.0.0.5"
#define BEACONPORT 8000
#define MYPORTNOFORBEACON 8000

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
    	noofentries = MAXNOOFNODES;
    }
    
/*    ~messagefrombeacon(){*/
/*    	delete[] entries;*/
/*    }*/

};



struct messagefrombeacon talktobeacon(unsigned char* mypublickey, int MAXNOOFNODES, const char* MYIP){
    std::string IPaddress=BEACONIP;

    int clientsockid = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(clientsockid==-1)
    {
        std::cerr<<"Could not create the server"<<std::endl;
        exit(0);
    }

    struct sockaddr_in localaddr;
    localaddr.sin_family=AF_INET;
    localaddr.sin_port = htons(MYPORTNOFORBEACON);
    localaddr.sin_addr.s_addr = inet_addr(MYIP);

    int status = bind(clientsockid, (struct sockaddr*)&localaddr, sizeof(localaddr));
    if (status==-1)
        {
            std::cerr<<"Could not bind the socket"<<std::endl;
            exit(0);
        }


    struct sockaddr_in portaddr;
    portaddr.sin_family=AF_INET;
    portaddr.sin_port = htons(BEACONPORT);            //converts the unsigned short integer from host byte order to network byte order.

    inet_pton(AF_INET,IPaddress.c_str(),&portaddr.sin_addr.s_addr);

    status=connect(clientsockid, (struct sockaddr *) &portaddr,sizeof(portaddr));
    if(status==-1)
    {
        std::cerr<<"Could not connect to the server"<<std::endl;
        exit(0);
    }

    struct messagetobeacon msg;
    memcpy(msg.publickey, mypublickey, 159);
    memset(msg.ipaddr,0,16);
    memcpy(msg.ipaddr,MYIP, 15);

    status = send(clientsockid, &msg, sizeof(struct messagetobeacon), 0);
    if(status!=sizeof(struct messagetobeacon))
    {
        std::cerr<<"Could not send the complete message"<<std::endl;
    }

    struct messagefrombeacon msgfrmbeacon(MAXNOOFNODES);
    status = recv(clientsockid, &msgfrmbeacon.entries[0], sizeof(struct messagetobeacon)*MAXNOOFNODES, 0);
    if(status!=sizeof(struct messagetobeacon)*MAXNOOFNODES){
        std::cerr<<"Could not receive the complete message"<<std::endl;
    }
/*    printf("%hu\n",msgfrmbeacon.noofentries);*/
/*    cout<<msgfrmbeacon.entries[0].ipaddr<<endl;*/
/*    cout<<msgfrmbeacon.entries[0].publickey<<endl;*/
/*    cout<<msgfrmbeacon.entries[1].ipaddr<<endl;*/
/*    cout<<msgfrmbeacon.entries[1].publickey<<endl;*/
/*    cout<<msgfrmbeacon.entries[2].ipaddr<<endl;*/
/*    cout<<msgfrmbeacon.entries[2].publickey<<endl;*/
/*    cout<<msgfrmbeacon.entries[3].ipaddr<<endl;*/
/*    cout<<msgfrmbeacon.entries[3].publickey<<endl;*/
    printf("received a reply from beacon node\n");
    //cout<<msgfrmbeacon.entries[0].ipaddr<<endl;
    //cout<<msgfrmbeacon.entries[1].ipaddr<<endl;

    return msgfrmbeacon;

}


