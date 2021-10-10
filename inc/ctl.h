/*
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * $Id: ctl.h,v 1.2 2003/09/12 21:23:39 lorgor Exp $
 */

#ifndef CTL_H
#define CTL_H

#include <signal.h>
#include <dnet.h>
#include "queue.h"

/*
 * Note that data in these control structures is kept in host byte
 * order.  However, mac addresses are the exception. They are not
 * manipulated by the code, so they are kept in network byte order.
 *
 */

typedef enum 
{
  IDLE,
  IN_PROGRESS,
  CAPTURED

} statuses;

#define FP_NAME_LENGTH 16 /* maximal fake-port name length */
#define FP_SET_NAME_LENGTH 16 /* maximal port-set name length */

struct fake_port_s {
  char      name[FP_NAME_LENGTH];
  uint16_t  port_number;
};
typedef struct fake_port_s fake_port;

/* List of ports for one fake port set */
 
struct fake_port_set_s{
  char                name[FP_SET_NAME_LENGTH];
  struct fake_port_s  *incl_ports;
};
typedef struct fake_port_set_s fake_port_set;


/*! List with fake hosts */

struct fake_host_s {
  ip_addr_t   *fake_host_addr;
  eth_addr_t  *fake_host_mac;
  statuses    *status;
  ip_addr_t   *source_addr;
  fake_port_set  *role;
};

typedef struct fake_host_s fake_host_t;

struct fhosts {
  fake_host_t host;
  LIST_ENTRY(fhosts) host_next;

};

/*! "new kid on the block" list: IPs that have shown life since their capture */

struct nk_s {
  struct addr		nk_mac; 	/*!< corresponding MAC addr (netwk byte order) */
  time_t 		nk_time; 	/*!< Time entry will be culled due to inactivity */
};
typedef struct nk_s nk_t;


/*! IP ignore list */

struct ipig {
  struct addr 		ipig_addr;
  SLIST_ENTRY(ipig)	ipig_next;
};

SLIST_HEAD(ipig_q, ipig);


typedef struct port_restrict_s {
  uint16_t usr_port[PORT_USR_AMOUNT];
  uint16_t sys_port[PORT_SYS_AMOUNT];
} port_restrict_t;

typedef struct 
{ 
  uint8_t data[3]; 
}vendor; 

/* Main control structure */

struct ctl_s {

  /* Controlling arrays and structures */
  uint8_t		*exclusion;		/* 1 byte / addr in subnet */
  ip_addr_t		*addr_array;		/* IP src addr for last WHO-HAS ARP seen */
  time_t		*time_array;		/* Time of last WHO-HAS ARP */
  uint8_t 		*port_array;		/* 1 byte / port to monitor */
  nk_t	*		*nk_array;		/* "new kids on block: gratuitous arps seen */
  eth_addr_t		*mac_array;		/* Mac address array */
  port_restrict_t	*ips_port_array;	/* port_array for every ip, Uses in RESTRICT PORT mode */
  vendor		*oktet_array;		/* Первые 3 октеты из файла */ 
  uint32_t		*listener[BUFSIZE]; 	/* Слушатель, записывает все входящие пакеты */ 


  rand_t		*rand;			/*!< Rand handle */

  uint32_t		randqueue2[RANDSIZE2];	/*!< For linux win probe detection */

  struct ipig_q		ipig_q;			/*!< IP exclude list */


  /* globals */

  char cfg_file_name[BUFSIZE];	/* Configuration file name */
  char *vendor_file;		/* Файл с вендорами */ 
  int  debuglevel;				/* Level of debug output */
  int  index_all_seq;     /* Индекс принятых запросов */ 
  int  index_current_seq; /* Индекс для отслеживания отправленных ответов */ 
  int  choice_answer;     /* Выбор ответа на запрос */ 
  time_t last_output_tcp; /* Time from the last inquiry answer*/ 

  /* capture performance */
  uint32_t throttlesize;	/*!< Window size for incoming tcp sessions */
  uint32_t currentbytes;	/*!< # bytes transmitted this minute */
  uint32_t maxbw;		/*!< User-specified maximum bandwidth - implies persist mode */
  uint32_t newthisminute;	/*!< # bytes due to new connections still allowed this minute */
  uint32_t totalbytes;		/*!< Total bytes transmitted over whole history period */
  uint32_t rate;
  uint32_t past[HIST_MIN+1];	/*!< History array of bandwidth use */
				/*!<   each entry = bytes for the corresponding minute */
  int soft_restart;		/*!< used to delay captures for some minutes   */
				/*!< after startup to avoid having too many    */
				/*!< connections if scanned during this period */

  int	boolThread;		/*!< Win32: signal handling */
  char	syslog_server[MAXHOSTNAMELEN]; /*!< Win32: Remote syslog server */
  int	syslog_port;	/*!< Win32: Port to use for remote syslog */

  /* capture range */
  ip_addr_t base;		/*!< Beginning IP addr of range */
  ip_addr_t topend;		/*!< Ending IP addr of range */
  uint32_t addresses;		/*!< # addr in range */

  /* flags */
  uint16_t 		feature;
#define FL_EXCL_RESOLV_IPS	0x0001 	 /*!< -X */
#define FL_SAFE_SWITCH		0x0002	   /*!< -s */
#define FL_NO_RESP		0x0004	       /*!< -a */
#define FL_NO_RST_EXCL_PORT	0x0008	 /*!< -f */

  uint16_t		logging;
#define FL_LOG_BDWTH_SYSLOG	0x0001	 /*!< -b */
#define FL_LOG_ODD_ARPS		0x0002 	   /*!< -q */

  uint16_t		capture;
#define FL_CAPTURE		0x0001          /*!< -x */
#define FL_HARD_CAPTURE		0x0002	    /*!< -h */
#define FL_AUTO_HARD_CAPTURE	0x0004	/*!< -H */
#define FL_PERSIST_MODE_ONLY	0x0008	/*!< -P */
#define FL_PERSIST		0x0010	        /*!< -p */


  uint16_t		mode;
#define FL_TESTMODE		0x0001	      /*!< -T */
#define FL_DONT_DETACH		0x0002	  /*!< -d */
#define FL_DONT_NAG		0x0004	      /*!< -z */
#define FL_SOFT_RESTART		0x0008	  /*!< -R */
#define FL_NO_ARP_SWEEP		0x0010
#define FL_RAND_MAC		0x0020	/* -M */
#define FL_RAND_WINDOW		0x0040	/* -W */
#define FL_TCP_OPTS		0x0080	/* -C */
#define FL_RESTRICT_PORTS	0x0100	/* -S */
#define FL_RAND_MAC		0x0020	/* -M */
#define FL_RAND_WINDOW		0x0040	/* -W */
#define FL_TCP_OPTS		0x0080	/* -C */
#define FL_RESTRICT_PORTS	0x0100	/* -S */
#define FL_DOUBLE_ACK		0x0200	/* -A */
#define FL_DEMOMODE   0x0400        /*!< -e */

#define FL_OPEN_PORTS   0x0800        /*!< -y */



  volatile sig_atomic_t	signals;
#define SIG_RESTART		0x0001
#define SIG_QUIT		0x0002
#define SIG_TIMER		0x0004
#define SIG_TOGGLE_LOGGING	0x0008
};

typedef struct ctl_s ctl_t;
extern ctl_t ctl;

int 	ctl_init_arrays (int wait);
int	ctl_init();

#endif /* CTL_H */
