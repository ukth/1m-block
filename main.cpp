#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <netinet/in.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_HOSTNAME 128

char sites[800000][100];
int SITE_N;

void usage() {
	printf("syntax :\n");
	printf("python3 sort.py\n");
	printf("Enter file name:\n");
	printf("<filename>\n");
	printf("./1m-block\n");
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}

int ban_pkt(struct nfq_data *tb, u_int32_t* id){
	unsigned char* host_loc = NULL;
	char host[MAX_HOSTNAME];
	int host_len = 0;

	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;

	int ret;
	unsigned char *data;
	unsigned char *ptr;
	int i, j, p;


	ph = nfq_get_msg_packet_hdr(tb);

	if (ph) {
		*id = ntohl(ph->packet_id);
	}


	ret = nfq_get_payload(tb, &data);
	if (ret == 0){
		return 0;
	}

	ptr = data;
	ptr += sizeof(libnet_ipv4_hdr);
	ptr += sizeof(libnet_tcp_hdr);

	for(i = 0; i < 128; i++){
		if(ptr[i] == 'H' && ptr[i+1] == 'o' && ptr[i+2] == 's' && ptr[i+3] == 't'){
			host_loc = ptr + (i + 6);
		}

	}
	if(host_loc == NULL){
		return 0;
	}

	for(i = 0; i < MAX_HOSTNAME; i++){
		if(host_loc[i] == '\r'){
			host_len = i;
			break;
		}
	}

	if(host_len == 0){
		printf("Blank Host!");
		return 0;
	}

	memcpy(host, host_loc, host_len);

	i = 0;
    j = SITE_N - 1;
    p = (i+j)/2;

    printf("Host:%s \n",host);

    while(i <= j){
	    if(strcmp(sites[p],host) == 0){
	    	printf("\n### Not allowed website!! ###\n");
			return 1;
	    }
	    if(strcmp(sites[p],host) > 0){
	    	j = p-1;
	    	p = (i+j)/2;
	    }else if(strcmp(sites[p],host) < 0){
	    	i = p+1;
	    	p = (i+j)/2;
	    }
	}
	printf("Allowed website\n");
	return 0;

}



static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;
	printf("entering callback\n");


	if(ban_pkt(nfa, &id)){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

int main(int argc, char **argv)
{
	if (argc != 1) {
		usage();
		return -1;
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	int l;
	FILE* fp;
	char s[100];

	printf("1");


	fp = fopen("sorted.csv", "r");

	

	l = 0;
    while (feof(fp) == 0){
    	fgets(s, 100, fp);
    	s[strlen(s) - 1] = '\0';
    	memcpy(sites[l],s,strlen(s));
    	l++;
    }

    SITE_N = l;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
