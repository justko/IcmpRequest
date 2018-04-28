#include "IcmpManager.h"
#include <netinet/in.h>
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>
void IcmpManager::ipShow(const Ip &ip)
{
    std::cout << "--------------------IP Header(20 Bytes)--------------------" << std::endl;
    std::cout << "version:" << static_cast<unsigned>(ip.version)
              << "\theadLen:" << static_cast<unsigned>(ip.headLen) << "(×4 Bytes)"
              << "\ttype:" << static_cast<unsigned>(ip.type)
              << "\tlength:" << ntohs(ip.length) << std::endl;
    std::cout << "id:" << ntohs(ip.id)
              << "\tflag:" << static_cast<unsigned>(ip.flag)
              << "\toffset:" << ntohs(ip.offset) << std::endl;
    std::cout << "timeToLive:" << static_cast<unsigned>(ip.live)
              << "\tprotocal:" << static_cast<unsigned>(ip.protocal) << "("
              << ((ip.protocal == 1) ? "ICMP" : (ip.protocal == 2) ? "IGMP" : "Other") << ")"
              << "\tchecksum:" << ntohs(ip.checksum) << std::endl;
    std::cout << std::hex << "src IP:" << inet_ntoa(in_addr{ip.src}) << std::endl;
    std::cout << std::hex << "des IP:" << inet_ntoa(in_addr{ip.des}) << std::endl;
    icmpShow(ip.icmp);
    std::cout << "--------------------END IP--------------------" << std::endl;
}

void IcmpManager::icmpShow(const Icmp &icmp)
{
    std::cout << "--------------------ICMP Header(64 Bytes)--------------------" << std::endl;
    std::cout << std::dec << std::ends;
    std::cout << "type:" << static_cast<unsigned>(icmp.type)
              << "\tcode:" << static_cast<unsigned>(icmp.code)
              << "\tchecksum:" << ntohs(icmp.checksum) << std::endl;
    switch (icmp.type)
    {
    case static_cast<unsigned>(Type::TimestampReply):
        std::cout << "id:" << ntohs(icmp.id)
                  << "\tsequence:" << ntohs(icmp.sequence) << std::endl;
        std::cout << "origTimestamp:" << ntohl(icmp.origTimestamp) << std::endl;
        std::cout << "recvTimestamp:" << ntohl(icmp.recvTimestamp) << std::endl;
        std::cout << "transTimestamp:" << ntohl(icmp.transTimestamp) << std::endl;
        std::cout << "data:" << std::ends;
        for (char i : icmp.tsData)
        {
            std::cout << i << std::ends;
        }
        std::cout << std::endl;
        break;
    default:
        std::cout << "id:" << ntohs(icmp.id)
                  << "\tsequence:" << ntohs(icmp.sequence) << std::endl;
        std::cout << "data:" << std::ends;
        for (char i : icmp.data)
        {
            std::cout << i << std::ends;
        }
        std::cout << std::endl;
        break;
    }

    std::cout << "--------------------END ICMP--------------------" << std::endl;
}
unsigned short IcmpManager::checksumX(unsigned short *buff, int size)
{
    unsigned int cksum = 0;
    while (size >= 2)
    {
        cksum += *buff++;
        size -= sizeof(unsigned short);
    }
    if (size != 0)
        cksum += *(unsigned char *)buff;
    cksum = (cksum >> 16) + (cksum & 0xFFFF);
    cksum = (cksum >> 16) + (cksum & 0xFFFF);
    return ~cksum;
}