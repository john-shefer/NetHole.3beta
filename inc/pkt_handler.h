/* pkt_handler.h
 * This file is part of the LaBrea package
 *
 * Copyright (C) 2001, 2002 Tom Liston <tliston@premmag.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: pkt_handler.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
*/

#ifndef PKT_HANDLER_H
#define PKT_HANDLER_H

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>




#ifndef DNET_H
#include <dnet.h>
#endif //DNET_H

void	pkt_handler (u_char* client_data, const struct pcap_pkthdr* pcpkt, const u_char* pktdata);

/*наборы открытых портов*/
xmlDocPtr xmldoc;//указатель на документ
xmlNodePtr root;   // Указатель на корневой узел
//short set_id = 1;// ID используемого набора открытых портов

//typedef enum { false, true } bool;
     // bool port_detector = false;


#endif /* PKT_HANDLER_H */
