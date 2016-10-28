/***********************************************************************
* Code listing from "Advanced Linux Programming," by CodeSourcery LLC  *
* Copyright (C) 2001 by New Riders Publishing                          *
* See COPYRIGHT for license information.                               *
***********************************************************************/

#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <sys/types.h>
#include <libxml/xmlmemory.h>

/*** Structs used in firewall.c and dns.c.     *************************/

struct query_struct {
  char *date;
  /* the two fields below describe time interval. None
   * of them can be NULL. */
  struct tm *btime; /* begin interval time. */
  struct tm *etime; /* final interval time. */
  char *time; /* time that will be returned. */
  /* firewall fields begin. */
  char *src;
  char *dst;
  char *proto;
  char *spt;
  char *dpt;
  /* firewall fields end. */
  /* dns fields begin. */
  char *client;
  char *query;
  /* dns fields end. */
};

struct query_options {
  int nat;
};

struct tg {
  const char *symbol; /* What symbol should be recognized. */
  int suc;            /* Next state. */
  int alt;            /* Alternative state, if fail. */
};


/*** Symbols defined in module.c  **************************************/

/* An instance of a loaded server module.  */
struct server_module {
  /* The shared library handle corresponding to the loaded module.  */
  void* handle;
  /* A name describing the module.  */
  const char* name;
  /* The function which generates the HTML results for this module.  */
  void (* generate_function) (int, xmlNodePtr);
};

/* The directory from which modules are loaded.  */
extern char* module_dir;

/* Attempt to load a server module with the name MODULE_PATH.  If a
   server module exists with this path, loads the module and returns a
   server_module structure representing it.  Otherwise, returns NULL.  */
extern struct server_module* module_open (const char* module_path);

/* Close a server module and deallocate the MODULE object.  */
extern void module_close (struct server_module* module);


/*** Symbols defined in config.c.     ************************************/

extern const char* conf_file;

extern xmlDocPtr conf_doc;

struct conf {
  char *name;
  char *value;
};

extern struct conf **conf_table;

extern void read_conf(xmlDocPtr doc);

extern char *search_data_at_conf_table(const char *name);

extern void clean_conf_table(void);

extern void check_conf_file(xmlDocPtr doc);


/*** Symbols defined in nat.c.     ************************************/

extern const char* nat_file;

extern xmlDocPtr nat_doc;

struct nat {
  char *network;
  int netmask;
  char *target;
};

extern struct nat **nat_table;

extern void read_nat_from_doc(xmlDocPtr doc);

extern void check_nat_file(xmlDocPtr doc);

extern int search_ip_at_nat_table(const char *ip);

extern void clean_nat_table(void);


/*** Symbols defined in common.c.  ************************************/

/* The name of this program.  */
extern const char* program_name;

/* If non-zero, print verbose messages.  */
extern int verbose;

/* Directory from which logs will be retrieved */
extern const char* fw_log_dir; /* firewall logs */
extern const char* dns_log_dir; /* dns logs */

/* Like malloc, except aborts the program if allocation fails.  */
extern void* xmalloc (size_t size);

/* Like realloc, except aborts the program if allocation fails.  */
extern void* xrealloc (void* ptr, size_t size);

/* Like strdup, except aborts the program if allocation fails.  */
extern char* xstrdup (const char* s);

/* Print an error message for failure involving CAUSE, including a
   descriptive MESSAGE, and end the program.  */
extern void error (const char* cause, const char* message);

/* Return the directory containing the running program's executable.
   The return value is a memory buffer which the caller must deallocate
   using free.  This function calls abort on failure.  */
extern char* get_self_executable_directory ();

extern char *get_log_file(const char *path, const char *date);

extern in_addr_t cidr_to_netmask(int cidr);

extern int belongs_to_class_cidr(char *ip, char *network, int netmask);

extern int valid_document(xmlDocPtr doc, const char *dtd_file);

extern void create_pid_file(void);

extern int get_previous_pid(int *pid);

extern void delete_pid_file(void);

extern int time_compare (struct tm *time1, struct tm *time0);

/* Verify if the given string is formed only by digits. */
extern int stronlydigits (const char *s);


/*** Symbols defined in server.c.  ************************************/

/* Run the server on LOCAL_ADDRESS and PORT.  */
extern void server_run (struct in_addr local_address, uint16_t port);

extern char *xml_result_message_begin;

extern char *xml_result_message_end;

extern void xml_error (int connection_fd, const char *type, const char *message);


#endif  /* SERVER_H */

