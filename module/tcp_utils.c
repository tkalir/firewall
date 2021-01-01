#include "tcp_utils.h"

int is_hdr_fin(tcphdr* hdr)
{
	return hdr->fin;
}
//---------------------------------------------------------
int is_hdr_synack(tcphdr* hdr)
{
	return (hdr->ack == 1) && (hdr->syn == 1);
}
//---------------------------------------------------------
int is_hdr_syn(tcphdr* hdr)
{
	return hdr->ack == 0 && hdr->syn == 1;
}
//---------------------------------------------------------
int is_hdr_ack(tcphdr* hdr)
{
	return hdr->ack == 1 && hdr->syn == 0;
}
//---------------------------------------------------------
int is_hdr_established(tcphdr* hdr)
{
	return hdr->ack == 1 && hdr->fin == 0;
}

