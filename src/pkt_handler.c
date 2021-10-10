/*
 * pkt_handler.c
 * This file is part of the LaBrea package
 *
 * Copyright (C) 2001, 2002 Tom Liston <tliston@premmag.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id: pkt_handler.c,v 1.2 2003/09/12 21:23:39 lorgor Exp $ */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <X11/Xlib.h>
#include <gtk/gtk.h>

#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <assert.h>
#include <dnet.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ether.h>


#ifdef HAVE_ERR_H
#include <err.h>
#else
#include "err.h"
#endif

#include "labrea.h"
#include "pkt.h"
#include "bget.h"
#include "ctl.h"
#include "lbio.h"
#include "utils.h"
#include "pkt_handler.h"
#include "demonstration.h"

uint16_t tlength; /* Total length of pkt */
int headersize; /* Size of packet header */
bool input_new_data; /* 1 - если были записаны новые данные в массив, иначе 0 */


/*
 * Check if (IP) addr a is in (IP) subnet b
 */
static int
addr_in_subnet(const ip_addr_t a, const struct addr *b)
{
  struct addr atmp;

  if (b->addr_type != ADDR_TYPE_IP)
    return(FALSE);
  
  addr_pack(&atmp, ADDR_TYPE_IP, b->addr_bits, &a, IP_ADDR_LEN);
  return( (addr_cmp(&atmp, b) == 0) );
}

void error(const char *msg)
{
	perror(msg);
	exit(0);
}

//Отправка UDP пакета DHCP серверу
void subnet_move_initiator(pkt_t *pkt)
{
	// Генерация UDP пакета
	int sockfd;
	struct sockaddr_in serv_addr;

	// Создаем сокет
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		error("Ошибка открытия сокета");

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(20000);
	serv_addr.sin_addr.s_addr = gethostbyname("dhcp");
	//inet_addr("192.168.0.2");

	char buffer[45] = "intruder\n";
	strcat(buffer, ip_ntoa(&pkt->pkt_ip->ip_src));
	strcat(buffer, "\n");
	strcat(buffer, ether_ntoa(&pkt->pkt_eth->eth_src));

	//Отправляем данные
	sendto(sockfd, buffer, strlen(buffer), 0, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	printf("%s\n", "UDP отправлен");

	close(sockfd);
}

static bool 
first_check_syn_or_ack(uint8_t th_flag, struct tcp_opt * input_pkt_opts) 
{ 
    if(th_flag == TH_SYN) { 
        if(input_pkt_opts->opt_type == (TCP_OPT_NOP | TCP_OPT_EOL)) 
            return 1; 
    } 
    else if(th_flag == TH_ACK) 
        if(input_pkt_opts->opt_type == TCP_OPT_NOP) 
            return 1; 
    return 0; 
} 
 
/*********************************************************/ 
/* Option MSS is only in SYN packets - RFC 793           */ 
/* Skip SACK option (better sent ACK to every packet)    */ 
/* WindowsScale option is only in SYN packets - RFC 7323 */ //- [Windows Full] 
/*********************************************************/ 
static bool 
second_check_syn_or_ack(uint8_t th_flag, struct tcp_opt * input_pkt_opts) 
{ 
    if(th_flag == TH_SYN) { 
        if(input_pkt_opts->opt_type == (TCP_OPT_SACKOK | TCP_OPT_SACK)) 
            return 1; 
    } 
    else if(th_flag == TH_ACK) 
        if(input_pkt_opts->opt_type == (TCP_OPT_MSS | TCP_OPT_SACKOK | TCP_OPT_SACK | TCP_OPT_WSCALE)) 
            return 1; 
    return 0; 
}

//Производит последнюю генерацию выходного TCP пакета
static void 
generate_output_pkt(struct pkt *pkt, struct pkt *new, uint8_t th_flag, char *msg) 
{
  if (ctl.mode & FL_TCP_OPTS) {
    uint8_t tcp_hdr_len = pkt->pkt_tcp->th_off << 2;
 
    if (tcp_hdr_len > TCP_HDR_LEN) {
      uint8_t tcp_opt_len = tcp_hdr_len - TCP_HDR_LEN;
      DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: there are TCP options (Len %d b)", tcp_opt_len);
 
      uint8_t * input_pkt_ptr = (uint8_t *)pkt->pkt_tcp + TCP_HDR_LEN;
      uint8_t * output_pkt_ptr = (uint8_t *)new->pkt_end;
 
      uint8_t * data_offset_ptr = &new->pkt_tcp->th_flags;
      data_offset_ptr -= 1;
      uint8_t data_offset = *data_offset_ptr >> 2;
 
      struct tcp_opt * input_pkt_opts = (struct tcp_opt *)input_pkt_ptr;
      struct tcp_opt * output_pkt_opts = (struct tcp_opt *)output_pkt_ptr;
 
      while (input_pkt_ptr < (uint8_t *)pkt->pkt_tcp + tcp_hdr_len) {
 
        DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: input type %d", input_pkt_opts->opt_type);
 
        if (first_check_syn_or_ack(th_flag, input_pkt_opts)) {
          memcpy(output_pkt_ptr, input_pkt_ptr, 1);
          input_pkt_ptr += 1;
          output_pkt_ptr += 1;
          data_offset += 1;
 
          input_pkt_opts = (struct tcp_opt *)input_pkt_ptr;
          output_pkt_opts = (struct tcp_opt *)output_pkt_ptr;
        }
        else {
          if (second_check_syn_or_ack(th_flag, input_pkt_opts)) {
            tcp_opt_len -= input_pkt_opts->opt_len;
            input_pkt_ptr += input_pkt_opts->opt_len;
            input_pkt_opts = (struct tcp_opt *)input_pkt_ptr;
            continue;
          }

            memcpy(output_pkt_ptr, input_pkt_ptr, input_pkt_opts->opt_len);
   
            /* Fill timestamps */
            if (input_pkt_opts->opt_type == TCP_OPT_TIMESTAMP) {
              output_pkt_opts->opt_data.timestamp[0] = htonl(get_timestamp());
              output_pkt_opts->opt_data.timestamp[1] = input_pkt_opts->opt_data.timestamp[0];
            }
   
            input_pkt_ptr += input_pkt_opts->opt_len;
            output_pkt_ptr += output_pkt_opts->opt_len;
            data_offset += output_pkt_opts->opt_len;
   
            input_pkt_opts = (struct tcp_opt *)input_pkt_ptr;
            output_pkt_opts = (struct tcp_opt *)output_pkt_ptr;
          }
        }
   
        while ((data_offset & 60) != data_offset) {
            uint8_t tmp = 1;
            memcpy(output_pkt_ptr, &tmp, 1);
            input_pkt_ptr += 1;
            output_pkt_ptr += 1;
            data_offset += 1;
            tcp_opt_len += 1;
          }
   
        new->pkt_end += tcp_opt_len;
        *data_offset_ptr = data_offset << 2;
   
        DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: size %d", IP_HDR_LEN + data_offset);
        lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + data_offset, msg);
      }
      else{
        lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN, msg);
      }
    }
    else {
      lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN, msg);
    }
    ctl.currentbytes += (tlength + ETH_HDR_LEN);
} 

//Режим ответа на ACK, в случае 0-го окна
void 
zero_winprobe(struct pkt *pkt, 
         struct pkt *new, 
         const uint16_t dport, 
         const uint16_t sport, 
         const uint32_t ack, 
         const uint32_t seq) 
{ 
  char *msgptr = NULL; 
  uint32_t ack_out; 
  int boolLinuxWinProbe = 0;  /* True if have received a Linux-style windows probe pkt */ 
  /* 
  * Check for oddball Linux winprobe 
  * 
  * Decode the ack and see if it matches the inbound sequence 
  * number... if it does, then it's a win probe 
  */ 
 
  ack_out = ack; 
  ack_out ^= ntohl(pkt->pkt_ip->ip_src); 
  ack_out ^= ((sport << 16) + dport); 
 
  int i; 
  for(i = 0; i < RANDSIZE2; i++) { 
      if ((ack_out ^ ctl.randqueue2[i]) == seq) 
    boolLinuxWinProbe = 1; 
  } 
 
  DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: check Linux winprobe ack_out %x, Linuxprobe %d", 
    ack_out, boolLinuxWinProbe); 
 
  if ((tlength == (headersize + 1)) || boolLinuxWinProbe) { 
    /* 
    * we'll send back syn = inbound ack and ack = inbound syn... 
    */ 
 
    msgptr = (boolLinuxWinProbe) ? "Linux Persist Activity" : "Persist Activity"; 

    tcp_pack_hdr(new->pkt_tcp, 
        dport,            /* orig dst port becomes src port */ 
        sport, 
        ack,            /* seq # is inbound ack */ 
        seq,            /* ack # is inbound seq */ 
        (TH_ACK), 
        0,            /* windowsize = 0 - they keep waiting */ 
        0);            /* urg */ 
 
    lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN, msgptr);
    return; 
  } else { 
      /* 
      * we ignore everything else, but (optionally) log the fact 
      * that we saw activity... 
      */ 
      util_print(VERBOSE, "Additional Activity %s", lbio_ntoa(ctl.base)); 
      return; 
  } 
} 


//Если количество элементов массива дайтет до его максимума, то значение индекса перерводит в 0
static void
check_array_is_full(int *count, int maximum)
{
	if(count >= maximum)
		count = 0;
}

//Исключает запись дубликаций в массив
static bool 
exclude_duplication(const uint32_t number) 
{ 
  //Проверка предыдущих значений 
  int i; 
  for (i = 0; i < ctl.index_all_seq; ++i) 
    if(ctl.listener[i] == number) 
      return 0; 
  ctl.listener[ctl.index_all_seq++] = number; 
  check_array_is_full(&ctl.index_all_seq, sizeof(ctl.listener));
  return 1; 
} 
 
//Слушатель - записывает все входящие значения от клиента, исключая дубликации 
static void 
listener(const uint32_t seq, uint16_t tlength, int headersize) 
{ 
  int i = 1; 
  //Проверка длинны входящего пакет, если пакет больше окна, разбиваем его 
    while(tlength - headersize >= ctl.throttlesize * i) 
      exclude_duplication(seq + ctl.throttlesize * i++); 
    input_new_data = exclude_duplication(seq + tlength - headersize); 
} 

/* Двойные ACK */
static void
double_ack(struct pkt *pkt,
	struct pkt *new,
	const uint16_t dport,
	const uint16_t sport,
	const uint32_t ack)
{
	int i;
	if(!input_new_data || ctl.index_all_seq == 1) {
		switch(ctl.choice_answer) {
			case 0:
				tcp_pack_hdr(new->pkt_tcp,
					dport,
					sport,
					ack,
					ctl.listener[ctl.index_current_seq++],
					(TH_ACK),
					ctl.throttlesize,
					0);
				ctl.choice_answer = 1;
				generate_output_pkt(pkt, new, TH_ACK, "ACK tarpitting");
			break;
			case 1:
				if(time(NULL) - ctl.last_output_tcp >= rand()%3+3) {
					if(ctl.index_all_seq - ctl.index_current_seq <= 1 && ctl.index_all_seq != 1) {
						ctl.index_current_seq--;
						ctl.choice_answer = 2;
						return;
					}
				for(i = 0; i < 4; ++i) {
					if((new = pkt_new()) == NULL)
						return;
				new->pkt_end = new->pkt_data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
				tcp_pack_hdr(new->pkt_tcp,
					dport,
					sport,
					ack,
					ctl.listener[ctl.index_current_seq],
					(TH_ACK),
					ctl.throttlesize,
					0 );
				generate_output_pkt(pkt, new, TH_ACK, "ACK tarpitting");
				}
				ctl.index_current_seq++;
				check_array_is_full(&ctl.index_current_seq, sizeof(ctl.listener));
				ctl.last_output_tcp = time(NULL);
			}
			break;
			case 2:
				tcp_pack_hdr(new->pkt_tcp,
					dport,
					sport,
					ack,
					ctl.listener[ctl.index_current_seq],
					(TH_ACK),
					0,
					0 );
				lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN, "ACK tarpitting");
				ctl.choice_answer = 3;
			break;
			case 3:
				zero_winprobe(pkt, new, dport, sport, ack, ctl.listener[ctl.index_current_seq]);
			break;
		}
	}
}

/* 
 * Have an established TCP session. Throttle down the data flow as
 * much as possible.

 * pkt		incoming TCP pkt
 * new		our response pkt
 * dport	destination port of incoming TCP pkt
 * sport	source port of incoming TCP pkt
 * ack		incoming ack #
 * seq		incoming seq #
 * offset -> offset in capture subnet for tgt IP addr
 *
 */

/*Наборы открытых портов. Проверка порта.*/
bool check_port(xmlNodePtr node, int dport)
{
  bool check_value = false;

  xmlNodePtr cur_node = node;
    while (cur_node)
    {
      if (cur_node->type == XML_ELEMENT_NODE) //проверяем что попали на узел
      {
        if (!(strcmp(cur_node->name, "Set")))
        {
           check_value = check_port(cur_node->children, dport);
        }
        /*
        if (xmlStrEqual(cur_node->name, "Set"))
        {

            xmlAttrPtr attr1 = cur_node->properties; // берем атрибут
            while(attr1)
            {
                if ((xmlStrEqual(attr1->name, "id")) && (atoi(attr1->children->content) == set_id))
                {
                    check_port(cur_node->children, dport);
                }
                attr1 = attr1->next;//на следующий атрибут
            }
        }*/
      
      if (xmlStrEqual(cur_node->name, "port"))
        {
            //printf("Сравниваем порты: %d и %d \n",atoi(xmlNodeGetContent(cur_node)), dport );
            if (atoi(xmlNodeGetContent(cur_node)) == dport)
                {
                    
                    //port_detector = true;
                    //printf("Порт совпал! Проверка завершена!\n");
                    return true;
                       
                }
        }

      }
      cur_node = cur_node->next;
    }
    return check_value;
}      

static void
throttle_data(struct pkt *pkt,
	      const uint16_t dport,
	      const uint16_t sport,
	      const uint32_t ack,
	      const uint32_t seq,
	      const ip_addr_t offset)
{
  struct pkt *new = NULL;
  int i = 0;

  /* Handle a TCP data packet by attempting to throttle down the data flow */

  DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: dport %d, sport %d, offset %d, ack %x, seq %x",
	    dport, sport, offset, ack, seq);

  if ((new = pkt_new()) == NULL) 
    return; 
  
  new->pkt_end = new->pkt_data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN; 
  /* Add base tcp hdr without options */ 
  
  tlength = ntohs(pkt->pkt_ip->ip_len); /* Total length of pkt */ 
  headersize = IP_HDR_LEN + (pkt->pkt_tcp->th_off << 2); /* TCP + IP hdr size */ 

  /* If persist mode capture only */
  if (ctl.maxbw > 0) {	

    tlength = ntohs(pkt->pkt_ip->ip_len);/* Total length of pkt */
    headersize = IP_HDR_LEN + (pkt->pkt_tcp->th_off << 2); /* TCP + IP hdr size */

    DEBUG_PRT(DEBUG_PKTPROC, "throttle_data: persist mode ctl.maxbw %d, tlength %d, headersize %d, "
	      "newthismin %d",
	      ctl.maxbw, tlength, headersize, ctl.newthisminute);

    /*
     * The 1st data packet.
     *
     * They're sending a packet that is a header plus our throttle
     * size...
     */
    if (tlength == (headersize + ctl.throttlesize)) {
      /*
       * If we've already added all of the connections that we can
       * during this minute, then ignore this packet. This should allow
       * us to ease up toward maximum bw... even when we're being
       * hammered by inbound connects.
       */

      if (ctl.newthisminute <= 0)
	return;

      /* lower b/w due to possible new connects ...                      */
      ctl.newthisminute -= (tlength + ETH_HDR_LEN);

      tcp_pack_hdr( new->pkt_tcp,
		    dport, 			/* orig dst port becomes src port */
		    sport,
		    ack,		   	/* seq # is incoming ack # (ie unchanged) */
		    seq + ctl.throttlesize,     /* ack # is incoming seq # + throttlesize */
		    (TH_ACK),			/* ACK packet */
		    0,				/* throttle down window to 0 ==> persist */
		    0 );			/* urg */

      lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN,
		       "Persist Trapping");
      ctl.currentbytes += (tlength + ETH_HDR_LEN);
      return;
	
    } else {
    	zero_winprobe(pkt, new, dport, sport, ack, seq);
    }
  }

  else if ( (ctl.mode & FL_RAND_WINDOW) &&
          (((pkt->pkt_tcp->th_flags) & (TH_PUSH)) ||
            (pkt->pkt_tcp_data != NULL))) {

  	input_new_data = 0;
  	//Слушатель, записывает все входящие пакеты, и генерирует ответ
  	listener(seq, tlength, headersize); 
  	
  	//Двойные ACK 
  	if(ctl.mode & FL_DOUBLE_ACK)
  	  double_ack(pkt, new, dport, sport, ack);
  	else { 
  	//Правильная работа 
	tcp_pack_hdr( new->pkt_tcp,
	              dport,					/* orig dst port becomes src port */
	              sport,
	              ack,					/* seq # is incoming ack # (ie unchanged) */
	              ctl.listener[ctl.index_current_seq++],	/* ack # is incoming seq # В исходных значениях стоял seq */ 
	              (TH_ACK),					/* ACK packet */
	              ctl.throttlesize,				/* Размер окна, изначально стояла цифра 30 */
	              0 );					/* urg */
  	  generate_output_pkt(pkt, new, TH_ACK, "ACK tarpitting");
  	} 

    ctl.currentbytes += (tlength + ETH_HDR_LEN);
    return;
  }
}

/*
 * Check if IP is on the "IP ignore" list. If so then just ignore this
 * packet.  Check if the IP is on the "New kids" list (ie a machine
 * that recently announced itself via a gratuitous ARP). If so, then
 * just forward the packet on to the existing machine.
 *
 * pkt -> incoming pkt to be examined
 *
 * Returns TRUE if pkt is found on one of the lists (and should be ignored).
 *
 */

static int
check_ip_ignore_or_new_kid( struct pkt *pkt, ip_addr_t offset)
{
  nk_t *nk;
  struct ipig *ipig;
  time_t current = 0;

  /*
   * 
   * First, run the list of source IPs that we are supposed to
   * ignore...
   * 
   * If we find the IP on the list, then just return without
   * doing anything...
   * 
   */

  SLIST_FOREACH(ipig, &ctl.ipig_q, ipig_next){
    if (addr_in_subnet(pkt->pkt_ip->ip_src, &(ipig->ipig_addr))) {
      DEBUG_PRT(DEBUG_PKTPROC, "check_ip_ignore_or_new_kid: ignore ip %d", offset);
      return(TRUE);
    }
  }
 
  /* Next see if this IP is a "new kid" (ie, already belongs to someone) */
  struct addr rand_bogus_mac;
  if (ctl.mode & FL_RAND_MAC)
  {
    addr_pack(&rand_bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
              &ctl.mac_array[offset], ETH_ADDR_LEN);
  }
  if ((nk = ctl.nk_array[offset]) != NULL) {
    if (addr_cmp(&(nk->nk_mac), (ctl.mode & FL_RAND_MAC) ? &rand_bogus_mac : io.bogus_mac) != 0) {
      /* 
       * The incoming IP is already owned by someone.
       *
       * This is a real machine, so just forward the pkt on by
       * stuffing in the "correct" MAC
       * 
       */
      memmove(&(pkt->pkt_eth->eth_dst), &(nk->nk_mac.addr_eth), ETH_ADDR_LEN); 
      lbio_send_pkt(pkt);
      
      /* reset the cull time, because obviously SOMEONE ain't got a clue */
      nk->nk_time = current + CULLTIME;
      
      util_print(VERY_VERBOSE,"Packet forwarded to owner of IP %s (MAC: %s)",
		 lbio_ntoa(ctl.base + offset), addr_ntoa(&(nk->nk_mac)));
    }
    return(TRUE);
  }
  return(FALSE);
}


/*
 * Handle incoming IP pkt: TCP and ICMP ping
 *
 * pkt -> incoming pkt.
 *
 */

static void
ip_handler (struct pkt *pkt)
{
  ip_addr_t offset = 0;		/* Deplacement into array of captured IP addresses */
  uint32_t ack_out;		/* Computed ack # */

  struct pkt *new = NULL;
  static uint16_t currentrand2 = 0;
  /* Index into array of random #'s used for detecting window probes */

  uint16_t dport = 0;		/* Destination port */
  uint16_t sport = 0;		/* Source port */
  uint32_t ack = 0;		/* Incoming ack # */
  uint32_t seq = 0;		/* Incoming seq # */

  static int demo_msg_num;
  if (demo_msg_num == NULL)
    demo_msg_num = 1;

  DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: start");

  /* Calculate offset in subnet to be captured */
  if( lbio_ip_offset(pkt->pkt_ip->ip_dst, &offset) < 0)
    return;

  if (ctl.mode & FL_RAND_MAC)
  {
    struct addr adr_tmp;
    addr_pack(&adr_tmp, ADDR_TYPE_ETH, ETH_ADDR_BITS,
              &(pkt->pkt_eth->eth_dst), ETH_ADDR_LEN);
    struct addr rand_bogus_mac;
    addr_pack(&rand_bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
              &ctl.mac_array[offset], ETH_ADDR_LEN);
    if (addr_cmp(&adr_tmp, &rand_bogus_mac) != 0)
      return;
  }

  /* Check to see that this isn't an excluded address... */
  if (ctl.exclusion[offset] == IP_EXCLUDE)
    return;
  
  if (check_ip_ignore_or_new_kid(pkt, offset))
    return;

  DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: process ip packet - offset %d", offset);

  /* switch on the protocol */
  switch(pkt->pkt_ip->ip_p) {

  case IPPROTO_TCP:

    if (pkt->pkt_tcp == NULL)	/* Ignore malformed pkts */
      return;

    sport = ntohs(pkt->pkt_tcp->th_sport); /* incoming Tcp source port */
    dport = ntohs(pkt->pkt_tcp->th_dport); /* incoming Tcp dest port */
    ack = ntohl(pkt->pkt_tcp->th_ack); /* incoming ack # */
    seq = ntohl(pkt->pkt_tcp->th_seq);

    DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: tcp pkt sport: %d, dport: %d, ack: %x, seq: %x",
	      sport, dport, ack, seq);

    /*
*************************************************
* Special code to handle funky Linux win probes
*************************************************
*
* We're going to "encode" the remote sequence number that we
* should be seeing on the first inbound window probe - we use this
* encoded value as *our* sequence number...
*
* when we get an inbound packet that could be a win probe we'll
* "decode" the ack... if it matches the sequence number, then it's
* a win probe...
*
* This is one of those cool hacks that no one else is ever going
* to understand. Oh Well...
*
*/
    
    ack_out = seq + ctl.throttlesize;
    ack_out ^= ctl.randqueue2[currentrand2];
    ack_out ^= ((sport << 16) + dport);
    ack_out ^= (ntohl(pkt->pkt_ip->ip_src));
    ack_out--;
    currentrand2++;
    if (currentrand2 == RANDSIZE2)
      currentrand2 = 0;
    
    /*Наборы открытых портов. Начало*/

  /*  char *file_name = "test.xml";
  xmldoc = NULL;
  root = NULL;
  bool port_detector = false;

  //LIBXML_TEST_VERSION;
    xmldoc = xmlReadFile(file_name, NULL, 0);
    if(xmldoc == NULL)
        {
        printf("Error parsing file\n");
        exit(1);
        }
    root = xmlDocGetRootElement(xmldoc);
    if (root == NULL) 
    {
        printf("Empty document\n");
        xmlFreeDoc(xmldoc);
        exit(1);
    }
    else
    {
      printf("XML файл успешно прочитан\n");
    }
    */
    
    //short set_id = 1;
    //Наборы открытых портов
    if (ctl.mode & FL_OPEN_PORTS) {
    
    if (check_port(root, dport))
    {
      printf("Порт назначения : %d.  Порт открыт.\n", dport);

      //g_print("\nПорт назначения : %d\n", dport);
      
    }
    else
    {
      printf("Порт назначения : %d.  Порт закрыт. Отправлен RST-пакет.\n", dport);
      goto RST_LABEL;
    }
    //xmlFreeDoc(xmldoc);
  }
    



    /*
     * Now, we want to check our list of port numbers that we're
     * supposed to ignore... if we find it on the list, then return
     * without doing anything...
     *
     */

    if (ctl.mode & FL_RESTRICT_PORTS) {
      int i;
      for (i = 0; i < PORT_USR_AMOUNT; i++) {
        if (ctl.ips_port_array[offset].usr_port[i] == dport)
          goto FL_RESTRICT_PORTS_LABEL;
      }

      for (i = 0; i < PORT_SYS_AMOUNT; i++) {
        if (ctl.ips_port_array[offset].sys_port[i] == dport)
          goto FL_RESTRICT_PORTS_LABEL;
      }

      goto RST_LABEL;
    }
    else {



      if (ctl.port_array[dport] == PORT_IGNORE) {
        if (!(ctl.feature & FL_NO_RST_EXCL_PORT)) {

	  if ((new = pkt_new()) == NULL)
	    return;

	  new->pkt_end = new->pkt_data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
				  /* Add base tcp hdr without options */

	  DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: send RST sport %d dport %d ack %x seq %x",
		    dport, sport, ack_out, seq+1);

    if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "\nАдресу %s отправлен RST-пакет %s\n", ip_ntoa(&pkt->pkt_ip->ip_src));
        g_idle_add(print_demo_message, msg);
      }

	  tcp_pack_hdr( new->pkt_tcp,
		        dport,			/* orig dst port becomes src port */
		        sport,
		        ack_out,			/* seq # = our coded number */
		        seq+1,			/* ack # = (orig seq # + 1) */
		        (TH_RST | TH_ACK),	/* send a Reset */
		        ctl.throttlesize,
		        0 );			/* urg */

	  lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN, NULL);
        }
        return;
      }
    }
FL_RESTRICT_PORTS_LABEL:
    /*
     * If firewalling ports, then don't give a response unless this
     * port has seen sufficient activity. This will slow down nmap
     * scans. But still record that a SYN came in.
     */
    if (ctl.feature & FL_NO_RST_EXCL_PORT) {
      if ((ctl.port_array[dport] < PORT_MAX) &&
	  (pkt->pkt_tcp->th_flags) & TH_SYN)
	ctl.port_array[dport]++;
      if (ctl.port_array[dport] <= PORT_NOISE) {
	DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: SYN so bump cnt port %d = %d but ignore for now",
		  dport, ctl.port_array[dport]);
	return;
      }
    }    
    g_print("\nTCP packet type: %d\n", (pkt->pkt_tcp->th_flags) & (TH_SYN | TH_ACK | TH_FIN | TH_RST));
    /* Switch on type of incoming TCP packet */
    switch((pkt->pkt_tcp->th_flags) & (TH_SYN | TH_ACK | TH_FIN | TH_RST))  {

    case (TH_RST):
      if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Получен RST-пакет. Одностороннее завершение сессии целью.\n \
          \t Источник - %s:%d\n\t Цель - %s:%d\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), sport, ip_ntoa(&pkt->pkt_ip->ip_dst), dport);
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
        g_idle_add(timer_stop, NULL);
      }
    break;

    case (TH_ACK | TH_FIN):
      if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Получен FIN-пакет. Одностороннее завершение сессии целью.\n \
      \t Источник - %s:%d\n\t Цель - %s:%d\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), sport, ip_ntoa(&pkt->pkt_ip->ip_dst), dport);
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
        g_idle_add(timer_stop, NULL);
      }
    break;

    case (TH_SYN):
      /*
       * SYN ==>  reply SYN/ACK
       *
       * If we're persist only, and at bandwidth limit then return
       */
      DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: receive SYN");

      if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Получен SYN-запрос.\n \t Источник - %s:%d\n\t Цель - %s:%d\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), sport, ip_ntoa(&pkt->pkt_ip->ip_dst), dport);
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
      }

      if ((ctl.capture & FL_PERSIST_MODE_ONLY) && (ctl.newthisminute <= 0)) 
	return;

      if ((new = pkt_new()) == NULL)
	return;

	ctl.index_all_seq = 0; 
	ctl.index_current_seq = 0; 
	ctl.choice_answer = 0; 

      new->pkt_end = new->pkt_data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
				/* Add base tcp hdr without options */

      DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: send SYN-ACK sport %d, dport %d, ack %x, seq %x, win %d",
		dport, sport, ack_out, seq+1, ctl.throttlesize);

      ctl.throttlesize = (ctl.mode & FL_RAND_WINDOW) ? rand()%20+10 : ctl.throttlesize;

      if (ctl.mode & FL_DEMOMODE) {
        msg = malloc(256);
        sprintf(msg, "Отправлен SYN-ACK ответ \r\n");
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
      }

      tcp_pack_hdr( new->pkt_tcp,
		    dport,			/* orig dst port becomes src port */
		    sport,
		    ack_out,			/* seq # is our random # */
		    seq+1, 			/* ack # = (inbnd seq + 1) */
		    (TH_SYN | TH_ACK), 		/* Send a SYN/ACK */
		    ctl.throttlesize,
		    0 );			/* urg */

		generate_output_pkt(pkt, new, TH_SYN, "Initial connection - SYN tarpitting");
		subnet_move_initiator(pkt);

     if (ctl.mode & FL_DEMOMODE) {
      /*  Let's make a message to print in demo window  */
      msg = malloc(256);
      sprintf(msg, "TCP-сессия установлена. Захват адреса %s\r\n", ip_ntoa(&pkt->pkt_ip->ip_src));
      demo_msg_num++;
           
     /* ..but before that, let's check the availability of X Window system*/
      // if (XOpenDisplay(NULL) != NULL)
      // {
      //   g_print("I'm under gui mode\n");

      g_idle_add(timer_start, NULL);
      g_idle_add(print_demo_message, msg);

    }
      return;
      /* break; */

    case (TH_SYN | TH_ACK):
      /*
       * SYN/ACK ==> reply RST
       */

      DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: receive SYN-ACK");

      if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Получен SYN-ACK-пакет.\n \t Источник - %s:%d\n\t Цель - %s:%d\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), sport, ip_ntoa(&pkt->pkt_ip->ip_dst), dport);
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
      }
      if (ctl.feature & FL_NO_RESP) 	
	return;
RST_LABEL:

      if ((new = pkt_new()) == NULL)
	return;

      new->pkt_end = new->pkt_data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
				/* Add base tcp hdr without options */

      DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: send ACK sport %d, dport %d, ack %x, seq %x, win %d",
		dport, sport, ack_out, seq+1, ctl.throttlesize);
	  
      tcp_pack_hdr( new->pkt_tcp,
		    dport,			/* orig dst port becomes src port */
		    sport,
		    ack_out,			/* seq # is our random # */
		    seq+1, 			/* ack # = (inbnd seq + 1) */
		    TH_RST, 			/* Send a RST */
		    ctl.throttlesize,
		    0 );			/* urg */

      lbio_send_ip_pkt(new, pkt, IP_HDR_LEN + TCP_HDR_LEN,
		       "Inbound SYN/ACK");
      subnet_move_initiator(pkt);
      // return;
      break;

    case (TH_ACK):
      /* 
       * Ack packet
       */
      DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: receive ACK");
      throttle_data(pkt, dport, sport, ack, seq, offset);

      if (ctl.mode & FL_DEMOMODE){
       
        msg = malloc(256);
        sprintf(msg, "Получен ACK-пакет.\n \t Источник - %s:%d\n\t Цель - %s:%d\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), sport, ip_ntoa(&pkt->pkt_ip->ip_dst), dport);
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
      }
    break;
      
    default:
        break;
    } /* end switch tcp */
    break;

  case IPPROTO_ICMP:
    /*
     * Respond to an incoming ping
     */

    DEBUG_PRT(DEBUG_PKTPROC, "ip_handler: receive Icmp pkt");

     if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Получен ICMP-пакет (Ping-запрос).\n\tИсточник - %s\n\tЦель - %s\r\n", \
          ip_ntoa(&pkt->pkt_ip->ip_src), ip_ntoa(&pkt->pkt_ip->ip_dst));
        demo_msg_num++;
        g_idle_add(print_demo_message, msg);
      }

    if (pkt->pkt_icmp == NULL)	/* Ignore malformed pkts */
      return;
    
    if (!(ctl.feature & FL_NO_RESP)
	     && (pkt->pkt_icmp->icmp_type == ICMP_ECHO)
	     && (pkt->pkt_icmp->icmp_code == ICMP_CODE_NONE)) {

      /* Allocate the new outbound pkt */
      if ((new = pkt_dup(pkt)) == NULL)
        return;
      
      new->pkt_icmp->icmp_type = ICMP_ECHOREPLY; /* Change to a reply */
      lbio_send_ip_pkt(new, pkt, ntohs(new->pkt_ip->ip_len),
		       "Responded to a Ping");

      if (ctl.mode & FL_DEMOMODE){
        msg = malloc(256);
        sprintf(msg, "Ответ на Ping.\n\tИсточник - %s\n\tЦель - %s\r\n", \
          ip_ntoa(&new->pkt_ip->ip_src), ip_ntoa(&new->pkt_ip->ip_dst));
        g_idle_add(print_demo_message, msg);
      }
      subnet_move_initiator(pkt);
    }
    return;
    /* break */

  default:
    break;
  } /* end switch ip */
  return;
}

/*
 *           NEW KIDS ON THE BLOCK
 *               
 * If we see a gratuitous arp, or if someone else replies to an ARP
 * request indicating that an IP address belongs to them (and not
 * us!), then we want to attempt to gracefully step out of the way
 * even if we've "hard" captured this IP.
 *					    
 * We're going to make a list of anyone who pops up new, using an arp
 * to announce their presence.  We hang onto this information for some
 * time, and then route anything that comes through to the correct
 * place.  Hopefully this will help keep us from really screwing
 * things up... 
 */

static void
handle_new_kid_ARP (const ip_addr_t offset, ip_addr_t tpa, const uint8_t *mac)
{
  time_t current = time(NULL);
  nk_t *nk;			/* Ptr to "new kid" element */
  struct addr adr_tmp;

  DEBUG_PRT(DEBUG_PKTPROC, "handle_new_kid_ARP: offset %d, tgt ip %s",
	    offset, ip_ntoa(&tpa));

  /* Check if this arp is from a bogus virtual machine (ie from us) */
  addr_pack(&adr_tmp, ADDR_TYPE_ETH, ETH_ADDR_BITS,
	    mac, ETH_ADDR_LEN);
  if (ctl.mode & FL_RAND_MAC) {
    struct addr rand_bogus_mac;
    addr_pack(&rand_bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
              &ctl.mac_array[offset], ETH_ADDR_LEN);
    if (addr_cmp(&adr_tmp, &rand_bogus_mac) == 0)
      return;
  }
  else {
    if (addr_cmp(&adr_tmp, io.bogus_mac) == 0)
      return;
  }
  
  
  /* reset our arrays */
  ctl.time_array[offset] = 0;
  ctl.addr_array[offset] = 0;

  /*
   * A new kid on the block... check if this IP is marked as belonging
   * to someone else
   */
  if ((nk = ctl.nk_array[offset]) != NULL) {
    /* 
     * If there is already a bogus nk entry (i.e. to force an arp sweep), then
     * free it.
     */
    if (ctl.mode & FL_RAND_MAC) {
      struct addr rand_bogus_mac;
      addr_pack(&rand_bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
                &ctl.mac_array[offset], ETH_ADDR_LEN);
      if (addr_cmp(&(nk->nk_mac), &rand_bogus_mac) == 0)
        util_nk_free(offset);
      else {
        nk->nk_time = current + CULLTIME;
        DEBUG_PRT(DEBUG_PKTPROC, "handle_new_kid_ARP: already tracking IP, bump expiry time");
        return;
      }
    }
    else {
      if (addr_cmp(&(nk->nk_mac), io.bogus_mac) == 0)
        util_nk_free(offset);
      else {
        /* 
         * Otherwise are already tracking this IP so simply bump the
         * expiry time...
         */
        nk->nk_time = current + CULLTIME;
        DEBUG_PRT(DEBUG_PKTPROC, "handle_new_kid_ARP: already tracking IP, bump expiry time");
        return;
      }
    }
  }

  if (ctl.mode & FL_RAND_MAC) {
    /*
     * New MAC must not be the same as
     * any of random MAC in mac_array
     */
    int ip;
    for (ip = 0; ip < ctl.addresses + 2; ip++) {
      struct addr rand_bogus_mac;
      addr_pack(&rand_bogus_mac, ADDR_TYPE_ETH, ETH_ADDR_BITS,
                &ctl.mac_array[ip], ETH_ADDR_LEN);
      if (addr_cmp(&adr_tmp, &rand_bogus_mac) == 0) {
        DEBUG_PRT(DEBUG_PKTPROC, "handle_new_kid_ARP: New MAC is the same as random generated MAC. Change it.");
        while (1) {
          rand_get(ctl.rand, &ctl.mac_array[ip], ETH_ADDR_LEN);
          if (util_check_mac_valid(ip) == 0) break;
        }
      }
    }
  }

  /*
   * The IP/MAC is a new one, so allocate a new element and mark
   * this IP as belonging to the MAC
   */
  util_nk_new(offset, current + CULLTIME, mac);
  DEBUG_PRT(DEBUG_PKTPROC, "handle_new_kid_ARP: mark IP as belonging to Mac");
  return;
}


/*
 * Handle incoming ARP WHO HAS.
 *
 * pkt -> incoming ARP packet
 *
 */
static void
handle_ARP_req (pkt_t *pkt)
{
  nk_t *nk;
  ip_addr_t spa, tpa;		/* Arp source / tgt protocol addr */
  ip_addr_t offset = 0;		/* Deplacement into array of captured IP addresses */

  time_t addrtime=0, current=time(NULL);

  /* calculate our offset from "base" of available local IPs */

#ifdef LB_SYSTEM_IS_SUN
  memmove(&spa, &(pkt->pkt_arp_data->ar_spa), sizeof(ip_addr_t));
  memmove(&tpa, &(pkt->pkt_arp_data->ar_tpa), sizeof(ip_addr_t));
#else
  spa = *( (ip_addr_t *)(pkt->pkt_arp_data->ar_spa)); /* is in netwk byte order */
  tpa = *( (ip_addr_t *)(pkt->pkt_arp_data->ar_tpa));
#endif

  DEBUG_PRT(DEBUG_PKTPROC, "handle_ARP_req: spa %s, tpa %s",
	    ip_ntoa(&spa), ip_ntoa(&tpa));

  if( lbio_ip_offset(tpa, &offset) < 0) {
    /*
     * This is a goofy IP address - don't touch it, and (if we're
     * supposed to) tell someone that we saw it
     * 
     */
    if (ctl.logging & FL_LOG_ODD_ARPS)
      util_print(NORMAL, "IP address not in netblock - ARP WHO-HAS %s TELL %s",
		 ip_ntoa( &tpa ),
		 ip_ntoa( &spa ));
    return;
  }
  
  spa = ntohl(spa);		/* now convert to host byte order */
  tpa = ntohl(tpa);

  /* ignore our own arps */   
  if (io.myip == spa)
    return;

  /* handle excluded IPs */
  if (ctl.exclusion[offset] == IP_EXCLUDE)
    return;

  DEBUG_PRT(DEBUG_PKTPROC, "handle_ARP_req: Check for gratuitous Arp");

  /*
   * Gratuitous ARP
   *
   * Added spa = 0 for the Macs... they do a wacky gratuitous arp:
   *
   * arp who-has 192.168.0.1 tell 0.0.0.0 - Why... why... WHY???
   *  
   */
  if ((spa == tpa) || (spa == 0)) {
    handle_new_kid_ARP(offset, tpa, pkt->pkt_arp_data->ar_sha);
    return;			/* We're done */
  }
  /*
   * If we get here, we know the following:
   *
   * the IP isn't excluded...               
   * this isn't a gratuitous arp...         
   * this isn't a wacky IP...               
   * this isn't one of our own arps...      
   * so...
   *
   * If we've already hard captured it, it's ours...
   *
   * Otherwise, check to see if we should capture this IP address...
   */

  DEBUG_PRT(DEBUG_PKTPROC, "handle_ARP_req: Check if should capture IP"
	    "- offset %d, ctl.addr_array %x, ctl.exclusion %d, ctl.time_array %x",
	    offset, ctl.addr_array[offset], ctl.exclusion[offset], ctl.time_array[offset]);

  if (ctl.exclusion[offset] != IP_HARD_CAPTURED) {
    /* pull the stored time out of the array */
    addrtime = ctl.time_array[offset];

    /*
     * If this arp request came from someone new, or if it's been more
     * than MAXARPTIME, start over
     */
    if ((ctl.addr_array[offset] != spa)
	|| ((addrtime + MAXARPTIME) <= current))
      addrtime = 0;
    /*
     * If the stored time is 0, we're starting fresh...
     *
     * Store the current time so we know when the arp hit.
     *
     * This will happen on the first arp, when we timeout,
     * or when we get another arp request for the same IP 
     * but from a different source...
     */
    if (addrtime == 0) {

      /* store current time and arp source */
      ctl.time_array[offset] = current;
      ctl.addr_array[offset] = spa;

      if (ctl.feature & FL_SAFE_SWITCH)
	lbio_send_ARP_Who_Has(tpa);	/* send our own ARP if on a switch */
      return;
    } else {
      /* there is a time stored, but if we haven't timed out ... */
      if ((addrtime + ctl.rate) > current) {
	
	if (ctl.feature & FL_SAFE_SWITCH) /* and are on a switch */
	  lbio_send_ARP_Who_Has(tpa); /* then send our own ARP */
	return;
      }
    }
  }
  /*
   * If we're here, we've timed out, or we've hard captured this IP
   * already...
   *
   * In either case, we need to send out an arp reply, to route any
   * traffic to this IP address to our bogus ARP address... creating a
   * virtual machine...
   
   * If we're hard capturing, and this address isn't hard excluded, we want to
   * hard capture it...
   */
  if ((ctl.capture & FL_HARD_CAPTURE) && 
      (ctl.exclusion[offset] != IP_HARD_EXCLUDE)) {
    DEBUG_PRT(DEBUG_PKTPROC, "handle_ARP_req: Mark offset %d hard captured", offset);
    ctl.exclusion[offset] = IP_HARD_CAPTURED;
  }

  /*
   * Check if this IP is on our "new kids" list.. if it is, remove
   * it... Why?
   *
   * Well, since we're here, whatever sent out the gratuitous arp that
   * got this IP listed as a "new kid" isn't answering arp requests...
   *
   * So we'll re-take the IP and kick if off the "new kids"
   * list. Whatever wanted this IP, didn't want it very bad... or
   * else, has left the scene...
   */
  if ((nk = ctl.nk_array[offset]) != NULL)
    util_nk_free(offset);
  
  /* back to zero to start over...*/
  ctl.time_array[offset] = 0;
  ctl.addr_array[offset] = 0;

  lbio_send_bogus_ARP(tpa, pkt);	/* Send the bogus ARP to capture the IP addr */
  return;
}


/*
 * Main packet Handler rtn called by pcap rtn
 */

void
pkt_handler (u_char* client_data, const struct pcap_pkthdr* pcpkt, const u_char* pktdata)
{

  /* locals */
  struct pkt *pkt;
  int len = pcpkt->caplen;	/* Length of captured data */
  ip_addr_t offset;		/* Offset into ctl arrays (== ip addr) */
  ip_addr_t spa=0;		/* Arp source protocol addr */

  DEBUG_PRT(DEBUG_PKTIO, "pkt_handler - start");

  if (pktdata == NULL)
    return;

  if (len > PKT_BUF_LEN) {
    warnx("Dropping oversize packet");
    return;
  }

  if ((pkt = pkt_new()) == NULL) {
    warnx("Error allocating new packet");
    return;
  }

  /* Copy received data into a new pkt element */

  memcpy(pkt->pkt_data, pktdata, len);
  pkt->pkt_end = pkt->pkt_data + len;

  pkt_decorate(pkt);		/* Verify that pkt is well-constructed */

  DEBUG_PRT(DEBUG_PKTIO, "pkt_handler - pkt accepted");

  switch (ntohs(pkt->pkt_eth->eth_type)){
  case ETH_TYPE_IP:

    /* Handle incoming IP pkt */
    if (pkt->pkt_ip == NULL)	/* Ignore malformed pkt */
      break;

    ip_handler(pkt); 
    break;
  
  case ETH_TYPE_ARP:
    /* Handle incomping ARP pkt */
    if ((pkt->pkt_arp == NULL) || /* Ignore malformed pkts  */
	(pkt->pkt_arp_data == NULL))
      break;

    if (ctl.capture & FL_CAPTURE) {

      switch(ntohs(pkt->pkt_arp->ar_op)) {

      case ARP_OP_REQUEST:
	handle_ARP_req(pkt);
	break;
	
      case ARP_OP_REPLY:
	
	/* 
	 * Received reply to an ARP "WHO-HAS" pkt
	 */ 

#ifdef LB_SYSTEM_IS_SUN
	memmove(&spa, &(pkt->pkt_arp_data->ar_spa), sizeof(ip_addr_t));
#else
	spa = *( (ip_addr_t *)(pkt->pkt_arp_data->ar_spa)); /* is in netwk byte order */
#endif
	

	/* Check if the incoming IP address interests us */

	if( lbio_ip_offset(spa, &offset) < 0) {
	  if (ctl.logging & FL_LOG_ODD_ARPS) {
	    util_print(NORMAL, "IP address %s not in capture subnet - ARP-REPLY",
		       lbio_ntoa(spa));
	  }
	  break;
	}

	/* 
         * Someone replied to an ARP request ...
	 * 
	 * Set up a "new * kid" element to mark this IP as belonging
	 * to the machine that replied. We want to leave this IP
	 * alone.
	 */
	handle_new_kid_ARP( offset, spa, pkt->pkt_arp_data->ar_sha);
	break;      

      } /* end switch ARP */
    }
    break; /* end arp case */   
  } /* end pkt switch */

  pkt_free(pkt);
  return;
}
