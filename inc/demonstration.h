#ifndef DEMONSTRATION_H
#define DEMOSTRATION_H

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>

//#ifndef LIBXML
//#define LIBXML
//#include <libxml/parser.h>
//#include <libxml/tree.h>
//#endif //LIBXML

GtkWidget	*demo_window;
GtkBuilder 	*demo_builder;
GtkWidget 	*buffer_demo;
gchar		*msg;

void*	draw_demo_window ();

gboolean print_demo_message(gpointer data);

gboolean timer_start();

gboolean timer_stop();

void on_demo_window_main_destroy();

enum {
	STOPPED,
	STARTED
};

/*наборы открытых портов*/
/*наборы открытых портов*/
//xmlDocPtr xmldoc;//указатель на документ
//xmlNodePtr root;   // Указатель на корневой узел
//short set_id = 1;// ID используемого набора открытых портов

//typedef enum { false, true } bool;
     // bool port_detector = false;

/*
xmlDocPtr doc = NULL;//указатель на документ
typedef enum { false, true } bool;
      bool port_detector = false;
      */
/*
struct Port
{
  int port_id;
  int port_num;
  char port_description [15];    
};

typedef struct Port_set
{
	int set_id;
	char set_description[15];
	struct Port port[5];
} Port_set;

char* mallocByString(const char *str);
void freeSet(Port_set* port_set);
void util_write_xml_structures(int count_set, Port_set port_set[], char *file_name);
int util_read_xml_structures(Port_set port_set[], char *file_name);
*/

#endif /* DEMOSTRATION_H */