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


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct MyAddr final{
  Ip ip_;
  Mac mac_;
};




void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

MyAddr getMyAddr(char *dev);
void print_result(int return_value);

int main(int argc, char* argv[]) {

    if( argc < 4 || argc % 2 !=0 )
    {
        usage();
        return -1;
    }

    int i;
    int attackCase = 0;

    attackCase = (argc-2) / 2 ;

    MyAddr myAddr = getMyAddr(argv[1]);
    printf("getMyAddr Done\n");

}

MyAddr getMyAddr(char *dev)
{
    FILE *fp = NULL;

    MyAddr myaddr;

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
    regmatch_t matchIP[20],matchMAC[20];
    int len=0;
    char mIP[MAX_STR_SIZE], mMAC[MAX_STR_SIZE];
    int flag=0;

    if(regcomp(&regexComIP,regexIP,REG_EXTENDED) || regcomp(&regexComMac,regexMAC,REG_EXTENDED))
    {
        fprintf(stderr,"Could not compile regular Expresion.\n");
        exit(1);
    }

    while(fgets(line,MAX_STR_SIZE,fp)!=NULL)
    {
        //printf("%s",line);

        if(regexec(&regexComIP,line,MAX_STR_SIZE,matchIP,REG_EXTENDED)==0)
        {
            len = matchIP[0].rm_eo-matchIP[0].rm_so;
            strncpy(mIP, line+matchIP[0].rm_so, len);
            myaddr.ip_=Ip(mIP+strlen("inet "));
            //printf("%s\n",mIP);
            flag++;
        }

        if(regexec(&regexComMac,line,MAX_STR_SIZE,matchMAC,REG_EXTENDED)==0)
        {
            len = matchMAC[0].rm_eo - matchMAC[0].rm_so;
            strncpy(mMAC, line+matchMAC[0].rm_so,len);
            myaddr.mac_=Mac(mMAC+strlen("ether "));
            //printf("%s\n",mMAC);
            flag++;
        }

        if(flag==2)
        {
            //printf("regfree\n");
            regfree(&regexComIP);
            regfree(&regexComMac);
            //printf("return\n");
            return myaddr;
        }


    }

    regfree(&regexComIP);
    regfree(&regexComMac);

    fprintf(stderr,"We can't find MY Address");
    exit(1);



}
