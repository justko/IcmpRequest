#include <string.h>  
#include <unistd.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include"IcmpManager.h"
#include<iostream>
#include<iomanip>

int main(){
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s < 0)
    {
        std::cout << errno << std::endl;
        exit(0);
    }
    struct timeval timeout;  
    timeout.tv_sec = 3;  
    timeout.tv_usec = 0;
    setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    sockaddr_in ad;
    ad.sin_family = AF_INET;
    ad.sin_port = 0;
    ad.sin_addr.s_addr = inet_addr("202.112.10.36");
    /*--------------------------------发送Echo请求----------------------------------------*/
    /*
    //构造ICMP数据包
    IcmpManager::Icmp req;
    bzero(&req,sizeof(req));
    req.type=static_cast<unsigned char>(IcmpManager::Type::Echo);
    req.code=0;
    req.id=getpid();
    req.sequence=0;
    strncpy(req.data,"xixi",56);
    req.checksum=IcmpManager::checksumX((unsigned short*)&req,sizeof(IcmpManager::Icmp));
    //发送ICMP
    sendto(s,&req,sizeof(IcmpManager::Icmp),0,(sockaddr*)&ad,sizeof(sockaddr));
    //接收
    IcmpManager::Ip header;
    bzero(&header,sizeof(header));
    socklen_t len;
    recvfrom(s,&header,sizeof(IcmpManager::Ip),0,(sockaddr*)&ad,&len);
    IcmpManager::ipShow(header);
    */
    /*------------------------------------发送时间戳请求------------------------------------*/
    //某些主机不会回应
    IcmpManager::Icmp req;
    bzero(&req,sizeof(req));
    req.type=static_cast<unsigned char>(IcmpManager::Type::Timestamp);
    req.code=0;
    req.origTimestamp=htonl(time(nullptr)%86400*1000);
    req.id=getpid();
    req.sequence=0;
    strncpy(req.tsData,"我想要时间戳",sizeof(req.tsData));
    req.checksum=IcmpManager::checksumX((unsigned short*)&req,sizeof(IcmpManager::Icmp));
    //发送
    sendto(s,&req,sizeof(IcmpManager::Icmp),0,(sockaddr*)&ad,sizeof(sockaddr));
    //接收
    IcmpManager::Ip header;
    socklen_t len;
    bzero(&header,sizeof(header));
    recvfrom(s,&header,sizeof(IcmpManager::Ip),0,(sockaddr*)&ad,&len);
    IcmpManager::ipShow(header);

    close(s);
    return 0;
    
}