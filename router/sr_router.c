/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define ECHO_REQUEST 8
#define ECHO_REPLY 0
#define REDIRECT 5
#define IPv4 4
#define TTL 64
#define IP_ADDR_LEN 4

#define UNREACHABLE_TYPE 3
#define TIME_EXCEEDED 11
#define TIME_EXCEEDED_CODE 0
#define ICMP_HOST_CODE 1
#define ICMP_NET_CODE 0
#define ICMP_PORT_CODE 3


void handle_IP(struct sr_instance* sr, uint8_t * packet, 
  unsigned int len, char* interface);
void forward_IP(struct sr_instance* sr, uint8_t * packet,
  unsigned int len, char* interface);
void handle_Icmp(struct sr_instance* sr,  uint8_t * packet,
  unsigned int len, char* interface);

void send_icmp_echo(struct sr_instance* sr, uint8_t * packet,
  unsigned int len);
void send_icmp_error(struct sr_instance* sr, uint8_t * packet,
  unsigned int len, uint8_t type, uint8_t code);
void check_and_send(struct sr_instance *sr, uint8_t *packet, unsigned int len,
  enum sr_ethertype type, uint32_t dst_ip);
struct sr_rt *match_longest_prefix(struct sr_instance* sr, uint32_t ip);

void handle_ARP(struct sr_instance* sr, uint8_t * packet,
  unsigned int len, char* interface);
int check_dst(struct sr_instance* sr, uint32_t dst_ip);
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  fprintf(stderr, "*******************\n");
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /* sanity check */
  if (len < sizeof(sr_ethernet_hdr_t)){
    fprintf(stderr, "Packet length too short\n");
    return;
  }

  /* get type of packet */
  if (ethertype(packet) == ethertype_ip) {
    handle_IP(sr, packet, len, interface);
  } else if (ethertype(packet) == ethertype_arp){
    handle_ARP(sr, packet, len, interface);
  } else {
    fprintf(stderr, "Wrong packet protocol type\n");
  }


}/* end sr_ForwardPacket */


void handle_IP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* printf("handling ip packet\n");*/
  /* sanity check */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){
    fprintf(stderr, "Ip Packet too short");
    return;
  }

  /* cast to ip content */
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* print_addr_ip_int(ip_packet->ip_src); */
  /* calculate checksum*/
  uint16_t received = ip_packet->ip_sum;
  ip_packet->ip_sum = 0;
  uint16_t calculated =  cksum(ip_packet, ip_packet->ip_hl * 4);
  if (received != calculated){
    fprintf(stderr, "Ip checksum doesn't match\n");
    return;
  }
  /*set checksum back*/
  ip_packet->ip_sum = received;
		
  /*sanity check*/ 
  if (ip_packet->ip_hl < 5){
    fprintf(stderr, "Invalid IP packet size\n");
    return;
  }
  /*sanity check*/ 
  if (ip_packet->ip_v != IPv4){
    fprintf(stderr, "Invalid IP version\n");
    return;
  }

  /* check if the destination of the ip packet is us*/
  if(check_dst(sr, ip_packet->ip_dst)){
    /*check type is icmp, otherwise unsupported in this assignment*/
    if(ip_packet->ip_p == (uint8_t)ip_protocol_icmp){
      handle_Icmp(sr, packet, len, interface);
    }else{
      send_icmp_error(sr, packet, len, UNREACHABLE_TYPE, ICMP_PORT_CODE);
    }
  }else{
    /*if not for us, forward it*/
    forward_IP(sr, packet, len, interface);
  }

  return;
}

void forward_IP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  /*time limit check*/
  if(ip_packet->ip_ttl == 1){
    send_icmp_error(sr, packet, len, TIME_EXCEEDED, TIME_EXCEEDED_CODE);
    return;
  }
  /*get lpm, check it
  struct sr_rt *router = match_longest_prefix(sr, ip_packet->ip_dst);
  if(!router){
    return;
  }*/

  /*create new packet*/
  uint8_t* new_packet = malloc(len);
  sr_ip_hdr_t* new_ip = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));  
  memcpy(new_ip, ip_packet,len - sizeof(sr_ethernet_hdr_t));
  new_ip->ip_ttl--;

  /*since content change, need to recalculate checksum*/
  new_ip->ip_sum = 0;
  new_ip->ip_sum = cksum(new_ip, new_ip->ip_hl * 4);
    
  check_and_send(sr, new_packet, len, ethertype_ip, new_ip->ip_dst);
  free(new_packet);
}

/*check if the destination of a packet is us*/
int check_dst(struct sr_instance* sr, uint32_t dst_ip){
  struct sr_if *temp = sr->if_list;
  while(temp){
    if(dst_ip == temp->ip){
      return 1;
    }
    temp = temp->next;
  }
  return 0;
}


void handle_Icmp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* sanity check */
  if (len < sizeof(sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_hdr_t) + (ip_packet->ip_hl * 4))){
    fprintf(stderr, "Icmp Packet too short");
    return;
  }
    
  sr_icmp_hdr_t* icmp_packet = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  /* checksum */
  uint16_t received = icmp_packet->icmp_sum;
  icmp_packet->icmp_sum = 0;
  uint16_t calculated =  cksum(icmp_packet, ntohs(ip_packet->ip_len) - ip_packet->ip_hl * 4);
  if (received != calculated){
    fprintf(stderr, "Icmp checksum doesn't match\n");
    return;
  }
  icmp_packet->icmp_sum = received;

  /*echo-reply it only if it is a request*/
  if(icmp_packet->icmp_type == ECHO_REQUEST){
    send_icmp_echo(sr, packet, len);
  }
}

void send_icmp_echo(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len)
{
  /*create a new packet*/
  uint8_t* new_packet = malloc(len);
  sr_ip_hdr_t* new_ip = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t* new_icmp = (sr_icmp_hdr_t*) ((uint8_t*)new_ip + sizeof(sr_ip_hdr_t));

  /* switch the dst and the src to echo*/
  /*load in the copy of the packet*/
  sr_ip_hdr_t *src_ip = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *src_ip_copy = malloc(len - sizeof(sr_ethernet_hdr_t));
  memcpy(src_ip_copy, src_ip, len - sizeof(sr_ethernet_hdr_t));
  uint32_t dst = src_ip_copy->ip_dst;
  src_ip_copy->ip_dst = src_ip_copy->ip_src;
  src_ip_copy->ip_src = dst;

  sr_icmp_hdr_t *src_icmp = (sr_icmp_hdr_t*) ((uint8_t*)src_ip_copy + sizeof(sr_ip_hdr_t));

  src_icmp->icmp_sum = 0;
  src_icmp->icmp_code = ECHO_REPLY;
  src_icmp->icmp_type = 0;

  /*load in the new packet*/
  memcpy(new_ip, src_ip_copy, len - sizeof(sr_ethernet_hdr_t));
  new_icmp->icmp_sum = cksum(new_icmp, len - sizeof(sr_ethernet_hdr_t) - new_ip->ip_hl * 4);
  check_and_send(sr, new_packet, len, ethertype_ip, new_ip->ip_dst);
  free(new_packet);
  free(src_ip_copy);
}

void send_icmp_error(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        uint8_t type,
        uint8_t code)
{
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /*create a new packet*/
  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  uint8_t* new_packet = malloc(new_len);
  sr_ip_hdr_t* new_ip = (sr_ip_hdr_t*) (new_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t* new_icmp = (sr_icmp_t3_hdr_t*) ((uint8_t*)new_ip + sizeof(sr_ip_hdr_t));

  /*initialize the ip header*/
  new_ip->ip_hl = sizeof(sr_ip_hdr_t) >> 2;
  new_ip->ip_v = IPv4;
  new_ip->ip_tos = 0;
  new_ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  new_ip->ip_id = htons(0);
  new_ip->ip_off = htons(IP_DF);
  new_ip->ip_ttl = TTL;
  new_ip->ip_p = ip_protocol_icmp;
  new_ip->ip_sum = 0;
  new_ip->ip_dst = ip_packet->ip_src;

  /*get lpm and check it*/
  struct sr_rt* router = match_longest_prefix(sr, ip_packet->ip_src);
  if(!router){
    return;
  }
  struct sr_if *interface = sr_get_interface(sr, router->interface);

  new_ip->ip_src = interface->ip;
  new_ip->ip_sum = cksum(new_ip, new_ip->ip_hl * 4);

  /*initialize the icmp header*/
  new_icmp->icmp_type = type;
  new_icmp->icmp_code = code;
  new_icmp->icmp_sum = 0;
  new_icmp->unused = 0;
  new_icmp->next_mtu = 0;

  /*load in the data of the icmp type3 header*/
  memcpy(new_icmp->data, ip_packet, ICMP_DATA_SIZE);
  new_icmp->icmp_sum = cksum(new_icmp, sizeof(sr_icmp_t3_hdr_t));

  check_and_send(sr, new_packet, new_len, ethertype_ip, new_ip->ip_dst);
  free(new_packet);
}

/*wrap in ethernet header, do some check and send*/
void check_and_send(struct sr_instance *sr,
        uint8_t *packet,
        unsigned int len,
        enum sr_ethertype type,
        uint32_t dst_ip)
{
  /*find the longest matched entry of routing table*/
  struct sr_rt* router = match_longest_prefix(sr, dst_ip);

  if(!router){
    send_icmp_error(sr, packet, len, UNREACHABLE_TYPE, ICMP_NET_CODE);
    return;
  }
  
  struct sr_if *interface = sr_get_interface(sr, router->interface);

  /*check wheter the destination ip is in the arp queue*/
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, router->gw.s_addr);

  /*update the ethernet header's source host, type*/
  sr_ethernet_hdr_t *ether_packet = (sr_ethernet_hdr_t*)packet;
  memcpy(ether_packet->ether_shost, interface->addr, ETHER_ADDR_LEN);
  ether_packet->ether_type = htons(type);
  if(arp_entry){
    /*if it is already in the arp queue, just send it*/
    memcpy(ether_packet->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, router->interface);
    free(arp_entry);
  }else{
    /*if not, need to add it in the queue, prepare to send arp request*/
    struct sr_arpreq *arp_reqs = sr_arpcache_queuereq(&sr->cache, router->gw.s_addr, packet, len, router->interface);
    /*if this request haven't been sent yet, send it at once*/
    if(arp_reqs->times_sent == 0){
        handle_arpreq(sr, arp_reqs);
        arp_reqs->sent = time(NULL);
    }
  }

}

/*get lpm*/
struct sr_rt *match_longest_prefix(struct sr_instance* sr, uint32_t ip){
  struct sr_rt* longest = NULL;
  uint32_t length = 0;
  struct sr_rt* curr;
  for(curr = sr->routing_table; curr; curr = curr->next){
    /* if the destination match*/
    if((curr->dest.s_addr & curr->mask.s_addr) == (ip & curr->mask.s_addr)
    /*if it is the longest till now*/
      && (length <= curr->mask.s_addr)){
        longest = curr;
        length = curr->mask.s_addr;
    }
  }
  return longest;
}

void handle_ARP(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* sanity check */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) ){
    fprintf(stderr, "ARP Packet too short");
    return;
  }

  /* cast to arp content */
  sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /*check hardware*/
  if(ntohs(arp_packet->ar_hrd) != arp_hrd_ethernet){
    fprintf(stderr, "Packet hardware type not ethernet\n");
    return;
  }
  /*check protocol*/
  if(ntohs(arp_packet->ar_pro) != ethertype_ip){
    fprintf(stderr, "Packet protocol type not IP\n");
    return;
  }
  /*check destination*/
  if(!check_dst(sr, arp_packet->ar_tip)){
    fprintf(stderr, "Request destination IP is not on this router.\n");
    return;
  }

  /*if it is a arp request*/
  if(ntohs(arp_packet->ar_op) == arp_op_request){
    /*create new packet*/
    uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    sr_ethernet_hdr_t *new_ether = (sr_ethernet_hdr_t*) new_packet;
    sr_arp_hdr_t *new_arp = (sr_arp_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));

    /*initialize ethernet header*/
    memcpy(new_packet, packet, len);
    struct sr_if* rec_interface = sr_get_interface(sr, interface);
    memcpy(new_ether->ether_dhost, new_ether->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_ether->ether_shost, rec_interface->addr, ETHER_ADDR_LEN);

    /*initialize arp header*/
    new_arp->ar_hrd = htons(arp_hrd_ethernet);
    new_arp->ar_pro = htons(ethertype_ip);
    new_arp->ar_hln = ETHER_ADDR_LEN;
    new_arp->ar_pln = IP_ADDR_LEN;
    new_arp->ar_op = htons(arp_op_reply);

    /*load in the reply to the request and send*/
    memcpy(new_arp->ar_sha, rec_interface->addr, ETHER_ADDR_LEN);
    new_arp->ar_sip = rec_interface->ip;
    memcpy(new_arp->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN);
    new_arp->ar_tip = arp_packet->ar_sip;

    sr_send_packet(sr, new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), rec_interface->name);
    free(new_packet);
  }else if(ntohs(arp_packet->ar_op) == arp_op_reply){
    /*if it is a arp reply*/
    struct sr_arpreq* req = 
      sr_arpcache_insert(&sr->cache, arp_packet->ar_sha, arp_packet->ar_sip);
    if(req){
      /*we got an reply for our previous request, need to send all packet waiting in the queue*/
      while(req->packets){
	      struct sr_packet *packet = req->packets;
        sr_ethernet_hdr_t *ether_packet = (sr_ethernet_hdr_t*)(packet->buf);
        /*load in the MAC we get from the reply*/
        memcpy(ether_packet->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
          
        sr_send_packet(sr, packet->buf, packet->len, packet->iface);
	      req->packets = req->packets->next;
      }
    }
    /*this request is done, destroy it.*/
    sr_arpreq_destroy(&sr->cache, req);
  }
}

