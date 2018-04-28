#pragma once
//https://www.rfc-editor.org/rfc/rfc792.txt
class IcmpManager
{
public:
  enum class Type : unsigned char
  {
    EchoReply = 0,
    DestinationUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    Echo = 8,
    TimeExceeded = 11,
    ParameterProblem = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16
  };
  /*
    ICMP:
     +----+----+--------+
     |type|code|checksum|
     +---------+--------+
     |    id   |  seq   |
     +------------------+
     |      data        |
     |       ...        |
     +------------------+ 
    */
  struct Icmp
  {
    //4B
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    //4B
    union {
      struct
      {
        unsigned short id;
        unsigned short sequence;
      };
      unsigned int gatewayInternetAddr;
      unsigned char pointer;
    };
    //56B
    union {
      struct
      {
        unsigned origTimestamp;
        unsigned recvTimestamp;
        unsigned transTimestamp;
        char tsData[44];
      };
      char data[56];
    };
  };

/*
  典型20 Bytes IP头结构体
  IP:
  +----+----+--------+----------------+
  |ver | len|   type |    length      |
  +----+----+---+----+----------------+
  |   id    |flg|       offset        |
  +---------+---+----+----------------+
  |  ttl    | proto  |    checksum    |
  +---------+--------+----------------+
  |             src                   |
  +-----------------------------------+
  |             des                   |
  +-----------------------------------+

*/
  struct Ip
  {
    unsigned char headLen : 4;
    unsigned char version : 4;
    unsigned char type;
    unsigned short length;

    unsigned short id;
    unsigned short offset:13;
    unsigned char flag:3;

    unsigned char live;
    unsigned char protocal;
    unsigned short checksum;

    unsigned int src;
    unsigned int des;

    Icmp icmp;
  };
  //计算校验和函数
  static unsigned short checksumX(unsigned short *buff, int size);
  //打印ICMP包函数
  static void icmpShow(const Icmp &icmp);
  //打印IP包函数
  static void ipShow(const Ip &ip);
};