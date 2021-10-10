#include <gtk/gtk.h>
#include "demonstration.h"
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>


// GtkWidget	*demo_window;
// GtkBuilder 	*demo_builder;
// GtkWidget 	*buffer_demo;
pid_t		pid;
GMutex      mutex_interface;

GtkWidget 	*text_view;
GtkWidget 	*timer_entry;
GtkWidget 	*progress_bar;
GTimer		*timer;

gint 		timer_state = STOPPED;	
gdouble		total_seconds = 0;
gchar 		curr_time[8];
gboolean	stopped_manually = FALSE;


void close_demonstration(int signal)
{
	g_print("Close signal is caught, terminating..\n");
	exit(0);
}

void set_timer()
{
	gint seconds = total_seconds;
	gint minutes = seconds / 60;
	seconds -= 60 * minutes;

	sprintf(curr_time, "%02d:%02d", minutes, seconds);
	gtk_entry_set_text(GTK_ENTRY(timer_entry), curr_time);
}

gboolean timer_function(void)
{
	gulong gulong;
	
	if(timer_state == STARTED){
		total_seconds = floor(g_timer_elapsed(timer, &gulong) * 100 + 0.5) / 100;
		gtk_progress_bar_pulse(GTK_PROGRESS_BAR(progress_bar));
		set_timer();
	} else if (timer_state == STOPPED){ 
		set_timer();
	}
	return TRUE;
}

gboolean timer_start()
{
	if(timer_entry){
		g_timer_start(timer);
		timer_state = STARTED;
	}
	else 
		warnx("Timer entry wasn't initialized");
	
	return G_SOURCE_REMOVE;
}

gboolean timer_stop()
{
	if (timer_entry){
		if (timer_state == STARTED){
			g_timer_stop(timer);
			timer_state = STOPPED;
			stopped_manually = TRUE;
		}
	}
	return G_SOURCE_REMOVE;
}

void notify(void){

	g_print("\nTimer will not be called again!\n");
}

/*
*	Calling this once to init demo window
*/
void* draw_demo_window()
{	
	if (!gtk_init_check(0, NULL))
		g_print("**Problem initializing window system**\n");
	else
	{
		demo_builder = gtk_builder_new_from_file("glade/timer_window.glade");
		demo_window = GTK_WIDGET(gtk_builder_get_object(demo_builder, "demo_window_main"));
		text_view = GTK_WIDGET(gtk_builder_get_object(demo_builder, "textview_demo"));
		timer_entry = GTK_WIDGET(gtk_builder_get_object(demo_builder, "timer_entry"));
		progress_bar = GTK_WIDGET(gtk_builder_get_object(demo_builder, "demo_progressbar"));
		gtk_builder_connect_signals(demo_builder, NULL);
 		// g_signal_connect(G_OBJECT(demo_window), "new-message-received", 
   //                      G_CALLBACK(print_demo_message), (gpointer)&msg);
		g_object_unref(demo_builder);
		
			// g_print("**gtk_check status OK**\n"); 
		if (demo_window)
		{
			gtk_widget_show(demo_window);
			// g_print("**Demo window should have been show already**\n");
		}
		else
			g_print("**Demo window is null, couldn't initialize**\n");

		timer = g_timer_new();
		g_timer_stop(timer);
		g_timeout_add_full(G_PRIORITY_DEFAULT, 1000, (GSourceFunc)timer_function, NULL, (GDestroyNotify)notify);
		// g_timeout_add(1000, (GSourceFunc) timer_function, NULL);

		gtk_main();
	}

		// return demo_window;
	// }
	return NULL;
}

/*
*	This function is called from main thread 
*	via g_idle_add() for every demo 
*	message needed to print
*/
gboolean print_demo_message(gpointer data)
{
	
	// GtkTextBuffer	*buffer_demo;
	GtkTextIter *iter;
	gint 		char_count;
	gchar 		*end_message;
	
	/*	Cast message back to gchar array	*/
	if (data == NULL)
		warnx("Transferred demo message is empty");
	gchar* message = malloc(256);
	sprintf(message, "%s\n %s\n", curr_time, (gchar*)data);

	if (stopped_manually){
		gint seconds = total_seconds;
		gint minutes = seconds / 60;
		seconds -= 60 * minutes;

		end_message = malloc(120);
		sprintf(end_message, "\n---------------\n \
Итоговое время удержания: %02d мин %02d сек\n", \
			minutes, seconds);
		strcat(message, end_message);
		free(end_message);
		stopped_manually = FALSE;
	}
	g_mutex_lock(&mutex_interface);

	if (!demo_window)
	{
		warnx("Demo window isn't initialized yet!");
		demo_window = draw_demo_window();
	}
	
	if (!text_view)
	{
		warnx("Couldn't find demo window TextView");
	}

	if (!buffer_demo)
		buffer_demo = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));

	gint lines = gtk_text_buffer_get_line_count(GTK_TEXT_BUFFER(buffer_demo));
	
	gtk_text_buffer_insert_at_cursor(GTK_TEXT_BUFFER(buffer_demo), message, strlen(message));
	free(message);
	// char_count = gtk_text_buffer_get_char_count (buffer_demo);
	// g_print("Current buffer size = %d characters\n", char_count);

	// if (char_count == 0)
	// 	gtk_text_buffer_get_start_iter(buffer_demo, iter);
	// else 
	// 	gtk_text_buffer_get_end_iter(buffer_demo, iter);
	g_mutex_unlock(&mutex_interface);
	//free(data);
	// g_free(message);

	return G_SOURCE_REMOVE;
}

void on_demo_window_main_destroy()
{
	gtk_main_quit();
}

int catch_signal(int signal, void (*handler)(int))
{
	struct sigaction action;
	action.sa_handler = handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;
	return sigaction(signal, &action, NULL);
}

/*Наборы открытых портов*/
/*Структура вариант 1 */

/*struct Port
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
} Port_set;*/

/*Структура вариант 2*/
/*typedef struct Port_set {
    int set_id;
    char *set_description;
    struct {
        int port_id;
        int port_num;
        char *port_description;
    } port[5];
    
} Port_set;
*/

/*char* mallocByString(const char *str) {
    char* p = (char*) malloc(strlen(str) + 1);
    strcpy(p, str);
    return p;
}
 
void freeSet(Port_set* port_set) {
    free(port_set->set_id);
    free(port_set->set_description);
    int i=0;
    for(i=0;i<5;i++){
        free(port_set->port[i].port_num);
        free(port_set->port[i].port_description);
    }
      
}*/

/*void util_write_xml_structures(int count_set, Port_set port_set[], char *file_name) {
    
  printf("Файл найден: %s \n", file_name);

    FILE *file;  
 
  file = fopen(file_name, "w"); 

  if(file == NULL) {  
      warnx("*** not found file\n");  
  }  

    int i;
	int j;
	for (i=0;i<count_set;i++)
	{
 		fprintf(file,
		"<set id=\"%d\">\n"
		"    <set_description>%s</set_description>>\n",
		port_set[i].set_id, port_set[i].set_description);
    
    	for(j=0;j<5;j++){
     		fprintf(file,
			"    <port id=\"%d\">\n"
			"        <num>%d</num>\n"
			"        <description>%s</description>\n"
			"    </port>\n",
			port_set[i].port[j].port_id,port_set[i].port[j].port_num, port_set[i].port[j].port_description);
    	}

		fprintf(file,
		"</set>\n");
	}

	fclose(file);  
   
}*/

/*
int  
count_line_in_file(const char *file_name)  
{  
  FILE *file;  
 
  file = fopen(file_name, "r"); 
  printf("%s", file_name);
 
  if(file == NULL) {  
      warnx("*** not found file\n");  
  }  
 
  int count = 0;  
 
  while(fscanf(file, "%*[^\n]%*c") != EOF)  
      count++;  
   
  fclose(file);  
 
  return count;  
}  */

/*int util_read_xml_structures(Port_set port_set[], char *file_name)  
{  
  
  printf("Файл найден: %s \n", file_name);

  FILE *file;  
 
  file = fopen(file_name, "r"); 


  if(file == NULL) {  
      warnx("*** not found file\n");  
  }  
 
  struct Port prt_temp;
struct Port_set prtset_tmp;
//struct Port_set masset[4];
int c,i,j,count_set,count_port=0;
int inTag=0,inSpace=0;//местоположение считывания
char tag[1000], space[1000];
tag[0]='\0';
space[0]='\0';
int count_chat_in_tag=0, count_chat_in_space=0;
int flag=0;//1-set,2-set-desc,3-port,4-num,5-desc
int param=0;
j=1;

while((c=fgetc(file))!=EOF)
{
	if(c=='<')
	{
		inTag=1;
		inSpace=0;
		//printf("Space:%s\n",space);
		if(flag==4 && tag[0]!='/')
		{
			param=0;
			param=(space[0]-'0');
			for(i=1;space[i]!='\0';i++)
			{
				param*=10;
				param+=(space[i]-'0');
			}
			prt_temp.port_num=param;
			//printf(" %d - param num in %d , tag is %s space is %s\n",param,j,tag,space);
		}
		else if(flag==5 && tag[0]!='/')
		{
			for(i=0;space[i]!='\0';i++)
			{
				prt_temp.port_description[i]=space[i];
			}
			prt_temp.port_description[i]='\0';
		}
		else if(flag==2 && tag[0]!='/')
		{
			for(i=0;space[i]!='\0';i++)
			{
				prtset_tmp.set_description[i]=space[i];
				//prt_temp.port_description[i]=space[i];
			}
			prtset_tmp.set_description[i]='\0';
		}
		continue;
	}
	else if(c=='>')
	{
		inTag=0;
		inSpace=1;
		//printf("TAG:%s\n",tag);
		if(tag[0]=='s' && tag[1]=='e' && tag[2]=='t')
		{
			if(tag[3]=='_')
			 {
			 	flag=2;
			 }
			 else 
			 {
			 	flag=1;
			 	i=8;			 
			 	param=(tag[i]-'0');
			 		for(i=9;tag[i]!='"';i++)
			 		{
			 			param*=10;
			 			param+=(tag[i]-'0');
			 		}
			 	prtset_tmp.set_id=param;
			 	count_set++;
			 	//printf("%d -param %d count_set\n",prtset_tmp.set_id,count_set);			 	
			 }
		}
		else if(tag[0]=='/' && tag[1]=='s' && tag[2]=='e' && tag[3]=='t' && tag[4]!=' ')
		{
			port_set[count_set-1]=prtset_tmp;
			count_port=0;
		}
		else if(tag[0]=='p' && tag[1]=='o' && tag[2]=='r')
		{
			flag=3;
			i=9;			 
			param=(tag[i]-'0');
			for(i=10;tag[i]!='"';i++)
			{
				param*=10;
				param+=(tag[i]-'0');
			}
			prt_temp.port_id=param;
			count_port++;
		}
		else if(tag[0]=='/' && tag[1]=='p' && tag[2]=='o' && tag[3]=='r')
		{
			prtset_tmp.port[count_port-1]=prt_temp;
			
		}
		/*else if(tag[0]=='/' && tag[0]=='n' && tag[1]=='u' && tag[2]=='m')
		{
			flag=0;
			inSpace=0;
			printf("xyi!!!!!!!!!!!!!!");
		}*/
		/*else if(tag[0]=='n' && tag[1]=='u' && tag[2]=='m')
		{
			flag=4;
		}
		else if(tag[0]=='d' && tag[1]=='e' && tag[2]=='s')
		{
			flag=5;
		}
		continue;
	}
	/*else if(c=='/' || c=='\n')
	{
		inTag=0;
		inSpace=0;
	}*/
	/*else
	{
		if(inTag)
		{
			count_chat_in_space=0;
			tag[count_chat_in_tag]=c;
			count_chat_in_tag++;
			if(count_chat_in_tag > 0)
			{
				tag[count_chat_in_tag]='\0';
				
			}
		}
		else if(inSpace)
		{
			count_chat_in_tag=0;
			space[count_chat_in_space]=c;
			count_chat_in_space++;
			if(count_chat_in_space > 0)
			{
				space[count_chat_in_space]='\0';
				
			}
		}
	}
}
        
 
  fclose(file);  
  //return num_oktet;  
  /*
  i=0;
j=0;
//printf("*************\n");
for(i=0;i<count_set;i++)
{


printf("corteg %d => %s \n",masset[i].set_id, masset[i].set_description);
for(j=0;j<5;j++)
	{
		printf("port - %d  num - %d - %s \n",masset[i].port[j].port_id,masset[i].port[j].port_num,masset[i].port[j].port_description);
		//printf("port - %d - %d - %s \n",masset[i].port[j].port_id,masset[i].port[j].port_num,masset[i].port[j].port_description);
	}		
}
*/
 /* return count_set;
} */