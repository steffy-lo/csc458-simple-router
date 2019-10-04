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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    if (len < sizeof(sr_ethernet_hdr_t))
    {
        fprintf(stderr, "sr_handlepacket: Ethernet packet doesn't meet minimum length.\n");
        return;
    }

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

    /* It's an ARP Packet type*/
    if (ethertype(packet) == ethertype_arp)
    {
        if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
        {
            fprintf(stderr, "sr_handlepacket: ARP packet doesn't meet minimum length.\n");
            return;
        }

        /* ARP header is after the Ethernet header */
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        /* Check hardware format code */
        if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet)
        {
            fprintf(stderr, "sr_handlepacket: unknown hardware address format.\n");
            return;
        }

        /* Check if protocol type is valid */
        if (ntohs(arp_hdr->ar_pro) != ethertype_ip)
        {
            fprintf(stderr, "sr_handlepacket: invalid protocol type.\n");
            return;
        }

        /*
         * For ARP Requests: Send an ARP reply if the target IP address is one of your router’s IP addresses.
         * For ARP Replies: Cache the entry if the target IP address is one of your router’s IP addresses.
         * Check if target IP is one of router's IP addresses.
         * */
        struct sr_if *if_walker = sr->if_list;
        while (if_walker->next)
        {
            if (if_walker->ip == arp_hdr->ar_tip)
            {
                handle_arp(sr, arp_hdr, if_walker);
                return;
            }
            if_walker = if_walker->next;
        }
        fprintf(stderr, "sr_handlepacket: target IP cannot be found.\n");
    }
    /* It's a IP Packet type*/
    else if (ethertype(packet) == ethertype_ip)
    {
        /* Handle IP Packet */
		if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
        {
            fprintf(stderr, "sr_handlepacket: IP packet doesn't meet minimum length.\n");
            return;
        }

        /* IP header is after the Ethernet header */
        sr_ip_hdr_t *ip_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        /* Verify checksum */
        uint16_t checksum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        if (checksum != cksum(ip_hdr, sizeof(sr_ip_hdr_t)))
        {
            fprintf(stderr, "sr_handlepacket: IP packet has incorrect checksum.\n");
            return;
        }

        /* Check if the IP address matches the current router's IP addresses */
        struct sr_if *if_walker = sr->if_list;
        while (if_walker->next)
        {
            if (if_walker->ip == ip_hdr->ip_dst)
            {
				        handle_ip(sr, ip_hdr, if_walker, packet, len)
                return;
            }
            if_walker = if_walker->next;
        }
        forward_ip(sr, ip_hdr, eth_hdr, packet, len);
    }
    else
    {
        /* Drop the packet */
        printf("Drop the packet.\n");
    }

} /* end sr_ForwardPacket */

void handle_arp(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *inf)
{
    switch (ntohs(arp_hdr->ar_op))
    {
    case arp_op_request:
    {
        printf("Received an ARP request\n");
        /* Construct ARP reply */
        unsigned int len = sizeof(sr_ethernet_hdr_t);
        uint8_t *arp_reply = malloc(len);

        /* Set Ethernet Header */
        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)arp_reply;
        memcpy(reply_eth_hdr->ether_dhost, reply_eth_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);

        /* Set ARP Header */
        sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
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
    case arp_op_reply:
    {
        printf("Received an ARP reply.\n");
        /* Look up request queue */
        struct sr_arpreq *queued = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (queued)
        {
            struct sr_packet *queued_pkts = queued->packets;
            /* Send outstanding packets */
            while (queued_pkts)
            {
                struct sr_if *inf = sr_get_interface(sr, queued_pkts->iface);
                if (inf)
                {
                    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(queued_pkts->buf);
                    memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    memcpy(eth_hdr->ether_shost, inf->addr, ETHER_ADDR_LEN);
                    sr_send_packet(sr, queued_pkts->buf, queued_pkts->len, queued_pkts->iface);
                }
                queued_pkts = queued_pkts->next;
            }
            sr_arpreq_destroy(&sr->cache, queued);
        }
        break;
    }
    }
}
void handle_ip(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr, struct sr_if *inf, uint8_t *packet, unsigned int len)
{
    /* Verify checksum here*/

    if (ip_hdr->ip_p == ip_protocol_icmp)
    {
        printf("An ICMP message.\n");

		if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
			fprintf(stderr, "handle_ip: ICMP header doesn't meet minimum length.\n");
            return;
		}

		/* ICMP header is after the IP header */
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(ip_hdr + sizeof(sr_ip_hdr_t));

        /* if it's an ICMP echo request, send echo reply */
        if(icmp_hdr->icmp_type == 0) {
			/* Construct ICMP echo reply */
			send_icmp_message(sr, packet, inf, 0, 0);
        }
    }
    else
    {
        printf("A TCP/UDP message.\n");
        /* Send ICMP type 3 code 3: Port Unreachable */
        send_icmp_message(sr, packet, inf, 3, 3);
    }
}

void send_icmp_message(struct sr_instance *sr, uint8_t *packet, struct sr_if *inf, uint8_t icmp_type, uint8_t icmp_code)
{
    /* Construct ICMP Message */
    int len = sizeof(sr_ethernet_hdr_t);
    uint8_t *icmp_packet = malloc(len);
    memcpy(icmp_packet, packet, len);

    /* Modify Ethernet and IP header */
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, inf->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);

    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;
    memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Modify ICMP header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmp_hdr->icmp_type = icmp_type;
    icmp_hdr->icmp_code = icmp_code;
    memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
    if (icmp_type == 0)
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
    else if (icmp_type == 3)
        icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, icmp_packet, len, inf->name);
    free(icmp_packet);
}

void forward_ip(struct sr_instance *sr, sr_ip_hdr_t *ip_hdr, sr_ethernet_hdr_t *eth_hdr, uint8_t *packet, unsigned int len)
{
    /* Sanity Check: Minimum Length & Checksum*/

    /* Decrement TTL by 1 */
    ip_hdr->ip_ttl--;
    if (ip_hdr->ip_ttl == 0)
    {
        /* Send ICMP Message Time Exceeded */
		send_icmp_message(sr, packet, inf, 11, 0);
        return;
    }

    /* Recompute checksum and add back in */
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /* Check the routing table and compare the values to the destination IP address */
    struct sr_rt *cur_node = sr->routing_table;
    uint32_t matching_mask = 0;
    uint32_t matching_address;
    char inf[sr_IFACE_NAMELEN];

    while (cur_node->next)
    {
        /* Compare the packet destination and the destination in the routing table node, record how many bits match */
        check_longest_prefix(cur_node, ip_hdr->ip_dst, &matching_mask, &matching_address, inf);
    }
    if (matching_address)
    {
        /*
		* Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP
		* If it's there, send it
		* Otherwise, send an ARP request for the next-hop IP (if one hasn’t been sent within the last second), and add the packet to the queue of packets waiting on this ARP request.
		*/
        struct sr_arpentry *matching_entry = sr_arpcache_lookup(&sr->cache, matching_address);
        /* Update the destination and source information for this package */
        if (matching_entry)
        {
            memcpy(eth_hdr->ether_dhost, matching_entry->mac, ETHER_ADDR_LEN);
            memcpy(eth_hdr->ether_shost, sr_get_interface(sr, inf)->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, inf);
            free(matching_entry);
        }
        else
        {
            /* There was no entry in the ARP cache */
            struct arp_req *req = sr_arpcache_queuereq(&sr->cache, matching_address, packet, len, inf);
            handle_arpreq(req, sr);
        }
    }
    else
    {

    } else {
		send_icmp_message(sr, packet, inf, 3, 0);
		/* Send ICMP Net unreachable */

	}
    /* If we get here, then matching_address was null, then we drop the packet and send an error */
}

void check_longest_prefix(struct sr_rt *cur_node, uint32_t packet_dest, uint32_t *matching_mask, uint32_t *matching_address, char *inf)
{
    /* Mask the packet's destination address to get the prefix */
    int masked_dest = packet_dest & cur_node->mask.s_addr;
    /* If the prefix matches the entry's destination as well, it's a match */
    /* If doesn't work try: if (masked_dest == cur_node->dest.s_addr & cur_node->mask.s_addr) instead */
    if (masked_dest == cur_node->dest.s_addr & cur_node->mask.s_addr)
    {
        /* If this is true then we know that this match is our best match (since the number of bits compared was higher)
         Save the data for comparison later */
        if (cur_node->mask.s_addr > *matching_mask)
        {
            *matching_mask = cur_node->mask.s_addr;
            *matching_address = cur_node->gw.s_addr;
            strncpy(inf, cur_node->interface, sr_IFACE_NAMELEN);
        }
        /* If it's false then it's not our best match, just ignore it */
    }
    /* If the prefix doesn't match then we do nothing */
}

/* If the destinatino IP address doesn't match the router, then forward it
 Take the destination IP address, compare it to the routing table (longest prefix matching)
 If it matches some pair in the routing table
 Use the ARP cache to see if we can find the MAC address of the target IP
 If we can, we send out the packet using the target MAC address
 If we can't then we broadcast an ARP request, and do the steps above after receiving a reply (or an error if no replies after 5 attempts)
 If it doesn't match some pair in the routing table
 Send an error back to the client */
