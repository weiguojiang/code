

#ifndef OVS_NET_COMMON_H
#define OVS_NET_COMMON_H 1

typedef unsigned short int uint16;
typedef unsigned long int uint32;
 //may be can be replaced by FP defined api
#define BigLittleSwap16(A)  ((((uint16)(A) & 0xff00) >> 8) | \
                            (((uint16)(A) & 0x00ff) << 8))
 
#define BigLittleSwap32(A)  ((((uint32)(A) & 0xff000000) >> 24) | \
                            (((uint32)(A) & 0x00ff0000) >> 8) | \
                            (((uint32)(A) & 0x0000ff00) << 8) | \
                            (((uint32)(A) & 0x000000ff) << 24))

static inline int  checkCPUendian(void)
{
       union{
              unsigned long int i;
              unsigned char s[4];
       }c;
 
       c.i = 0x12345678;
       return (0x12 == c.s[0]);
}
/* 
static inline unsigned long  int  htonl(unsigned long int h)
{
       return checkCPUendian() ? h : BigLittleSwap32(h);
}
 
static inline unsigned long int  ntohl(unsigned long int n)
{
       return checkCPUendian() ? n : BigLittleSwap32(n);
}
 
static inline unsigned short int  htons(unsigned short int h)
{
       return checkCPUendian() ? h : BigLittleSwap16(h);
}
 
static inline unsigned short int  ntohs(unsigned short int n)
{
       return checkCPUendian() ? n : BigLittleSwap16(n);
}
*/
#define OVS_NET_COMMON_H 1

#endif /* OVS_NET_COMMON_H */
