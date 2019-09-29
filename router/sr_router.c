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


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

    if (len < sizeof(sr_ethernet_hdr_t)) {
        fprintf(stderr, "sr_handlepacket: Ethernet packet doesn't meet minimum length.\n");
        return;
    }

    /* It's an ARP Packet type*/
    if (ethertype(packet) == ethertype_arp) {
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
            fprintf(stderr, "sr_handlepacket: ARP packet doesn't meet minimum length.\n");
            return;
        }

        /* ARP header is after the Ethernet header */
        sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

        /* Check hardware format code */
        if(ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) {
            fprintf(stderr, "sr_handlepacket: unknown hardware address format.\n");
            return;
        }

        /* Check if protocol type is valid */
        if(ntohs(arp_hdr->ar_pro) != ethertype_ip) {
            fprintf(stderr, "sr_handlepacket: invalid protocol type.\n");
            return;
        }

        /*
         * For ARP Requests: Send an ARP reply if the target IP address is one of your router’s IP addresses.
         * For ARP Replies: Cache the entry if the target IP address is one of your router’s IP addresses.
         * Check if target IP is one of router's IP addresses.
         * */
        struct sr_if* if_walker = sr->if_list;
        while(if_walker->next) {
            if (if_walker->ip == arp_hdr->ar_tip) {
                handle_arp(sr, arp_hdr, if_walker);
                return;
            }
            if_walker = if_walker->next;
        }
        fprintf(stderr, "sr_handlepacket: target IP cannot be found.\n");
    }
    /* It's a IP Packet type*/
    else if (ethertype(packet) == ethertype_ip) {
        /* Handle IP Packet */

    }
    else {
        /* Drop the packet */
        printf("Drop the packet.\n")
    }

}/* end sr_ForwardPacket */

void handle_arp(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* inf) {
    switch(ntohs(arp_hdr->ar_op)) {
        case arp_op_request: {
            printf("Received an ARP request\n");

            /* Construct ARP reply */
            unsigned int len = sizeof(sr_ethernet_hdr_t);
            uint8_t* arp_reply = malloc(len);

            /* Set Ethernet Header */
            sr_ethernet_hdr_t* reply_eth_hdr = (sr_ethernet_hdr_t*)arp_reply;
            /* set destination MAC to be source MAC */
            memcpy(reply_eth_hdr->ether_dhost, reply_eth_hdr->ether_shost, ETHER_ADDR_LEN);
            /* set source MAC to be interface's MAC */
            memcpy(reply_eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);

            /* Set ARP Header */
            sr_arp_hdr_t* reply_arp_hdr = (sr_arp_hdr_t*)(arp_reply + sizeof(sr_ethernet_hdr_t));
            reply_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
            reply_arp_hdr->ar_pro = arp_hdr->ar_pro;
            reply_arp_hdr->ar_hln = arp_hdr->ar_hln;
            reply_arp_hdr->ar_pln = arp_hdr->ar_pln;
            reply_arp_hdr->ar_op = htons(arp_op_reply);
            /* set sender MAC to be interface's MAC */
            memcpy(reply_arp_hdr->ar_sha, inf->addr, ETHER_ADDR_LEN);
            /* set sender IP to be interface's IP */
            reply_arp_hdr->ar_sip = inf->ip;
            /* set target MAC to be the packet's sender MAC */
            memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            /* set target IP to be the packet's sender IP */
            reply_arp_hdr->ar_tip = arp_hdr->ar_sip;

            printf("Send ARP reply.\n");
            sr_send_packet(sr, arp_reply, len, inf->name);
            free(arp_reply);
            break;
        }
        case arp_op_reply: {
            printf("Received an ARP reply.\n");
            /* Look up request queue */
            struct sr_arpreq* queued = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            if(queued) {
                struct sr_packet* queued_pkts = cached->packets;
                /* Send outstanding packets */
                while(queued_pkts) {
                    struct sr_if* inf = sr_get_interface(sr, queued_pkts->iface);
                    if(inf) {
                        sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)(queued_pkts->buf);
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                        memcpy(eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
                        sr_send_packet(sr, queued_pkts->buf, queued_pkts->len, queued_pkts->iface);
                    }
                    queued_pkts = queued_pkts->next;
                }
                sr_arpreq_destroy(&sr->cache, cached);
            }
            break;
        }
    }
}

