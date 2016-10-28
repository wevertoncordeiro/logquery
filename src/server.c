/***********************************************************************
* Code listing from "Advanced Linux Programming," by CodeSourcery LLC  *
* Copyright (C) 2001 by New Riders Publishing                          *
* See COPYRIGHT for license information.                               *
***********************************************************************/

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#define __USE_XOPEN /* glibc2 needs this */
#  include <time.h>
#undef __USE_XOPEN

#include "server.h"

/* TMP file that carry out the client request. */

char *tmp_file;

/* XML header and generic response format. */

char *xml_result_message_begin =
  "<?xml version='1.0'?>\n"
  "<result type=\"%s\">\n";

char *xml_result_message_end = 
  "</result>\n";

/* Handler for SIGCHLD, to clean up child processes that have
 * terminated.  */

static void clean_up_child_process ()
{
  int status;
  wait (&status);
}

/* Handler for SIGHUP, to die cleanly. */

static void die_cleanly ()
{
  clean_conf_table();
  xmlFreeDoc(conf_doc);
  exit(0);
}

/* Handler for SIGPIPE, to clean the server if the other side
 * reset the connection. */

static void close_connection ()
{
  if (nat_table != NULL) {
    clean_nat_table();
    xmlFreeDoc(nat_doc);
  }
  if (unlink(tmp_file) != -1)
    free(tmp_file);
  else
    error("unlink", strerror(errno));
  clean_conf_table();
  xmlFreeDoc(conf_doc);
  
  exit(0);
}

/* Send an xml error message to the client. */

void
xml_error
(int connection_fd, const char *type, const char *message)
{
  char *buffer;
  char *begin;
  char *template = "  <entry error=\"%s\" message=\"%s\"/>\n";

  buffer = (char *) xmalloc(strlen(type) + strlen(message) + strlen(template) + 1);
  sprintf(buffer, template, type, message);
  begin = (char *) xmalloc(strlen(xml_result_message_begin) + 6);
  sprintf (begin, xml_result_message_begin, "error");
  send (connection_fd, begin, strlen(begin), 0);
  send (connection_fd, buffer, strlen(buffer), 0);
  send (connection_fd, xml_result_message_end, strlen(xml_result_message_end), 0);
  free (buffer);
  free (begin);
}

static void handle_type
(int connection_fd, const char* type, xmlNodePtr cur)
{
  struct server_module* module = NULL;
  char module_file_name[64];

  snprintf (module_file_name, sizeof (module_file_name), "%s.so", type);
  /* Try to open the module.  */
  module = module_open (module_file_name);

  if (module == NULL) {
    /* An unsupported request was solicited. Send an error message. */
    xml_error(connection_fd, "201", "request type not supported");
  } else {
    /* The requested module was loaded successfully.  */

    /* Invoke the module, which will generate output and send it
       to the client file descriptor.  */
    (*module->generate_function) (connection_fd, cur);
    /* We're done with the module.  */
    module_close (module);
  }
}

/* Process a XML query and retrieve it's attributes.  */

static void handle_query (int connection_fd, const char* query_file)
{
  /* Code from http://xmlsoft.org/tutorial/ */ 
  xmlDocPtr doc;
  xmlNodePtr cur;

  /* Parse the XML document. */
  doc = xmlParseFile(query_file);
  /* Test if the document contains errors. */
  if (doc == NULL )
    xml_error(connection_fd,"200","document not parsed successfully");
  else {
    /* Validate the document. */
    if (!valid_document(doc, search_data_at_conf_table("query")))
      xml_error(connection_fd,"200","document not valid");
    else {
      xmlChar *uri;

      /* Get the root node of the XML document. */
      cur = xmlDocGetRootElement(doc);
      /* Get the request type. */
      uri = xmlGetProp(cur, (const xmlChar *) "type");
      handle_type(connection_fd, (const char *) uri, cur);
      xmlFree(uri);
    }
  }
  xmlFreeDoc(doc);
}

/* Handle a client connection on the file descriptor CONNECTION_FD.  */

static void handle_connection (int connection_fd)
{
  char buffer[1024];
  ssize_t bytes_read;
  FILE *tmp;
  int has_query = 0;

  /* Create a temporary file name to store the XML query. */
  tmp_file = xstrdup("/tmp/xmlQueryXXXXXX");
  if (mkstemp(tmp_file) == -1)
    error("mkstemp", strerror(errno));
  tmp = fopen(tmp_file, "w");
  if (tmp == NULL)
    error("fopen", strerror(errno));

  /* Read some data from the client and store it at FILE.  */
  while (!has_query) {

    memset(buffer, 0, sizeof(buffer));
    bytes_read = recv (connection_fd, buffer, sizeof (buffer) - 1, 0);
    if (bytes_read > 0) {
      /* Check if this is end of the query: newline and carriage return. */
      if (strstr(buffer, "\r\n\r\n"))
        has_query = 1;
      fputs (buffer, tmp);
      fflush(tmp);
    } else if (bytes_read == 0)
      /* The client closed the connection. Nothing to do. */
      break;
    else 
      /* The call to read failed.  */
      error ("read", strerror(errno));
  }
  if (has_query) {
    fclose(tmp);
    /* Call the function that will handle the query and send the
     * results back to the client. */
    handle_query(connection_fd, tmp_file);
  }
  if (unlink(tmp_file) != -1)
    free(tmp_file);
  else
    error("unlink", strerror(errno));
}

void server_run (struct in_addr local_address, uint16_t port)
{
  struct sockaddr_in socket_address;
  int rval;
  struct sigaction sigchld_action;
  struct sigaction sighup_action;
  struct sigaction sigpipe_action;
  int server_socket;
  int opt;

  /* Install a handler for SIGCHLD that cleans up child processes that
     have terminated.  */
  memset (&sigchld_action, 0, sizeof (sigchld_action));
  sigchld_action.sa_handler = &clean_up_child_process;
  sigaction (SIGCHLD, &sigchld_action, NULL);

  /* Install a handler for SIGHUP.  */
  memset (&sighup_action, 0, sizeof (sighup_action));
  sighup_action.sa_handler = &die_cleanly;
  sigaction (SIGHUP, &sighup_action, NULL);

  /* Install a handler for SIGPIPE that close the connection
     whenever the other side close it's socket descriptor. */
  memset (&sigpipe_action, 0, sizeof (sigpipe_action));
  sigpipe_action.sa_handler = &close_connection;
  sigaction (SIGPIPE, &sigpipe_action, NULL);

  /* Create a TCP socket.  */
  server_socket = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (server_socket == -1) {
    delete_pid_file ();
    error ("socket", strerror(errno));
  }
  opt = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, 
	         (char *) &opt, sizeof(int)) == -1) {
    delete_pid_file ();
    error("setsockopt: (SO_REUSEADDR)", strerror(errno));
  }
  opt = 1;
  if (setsockopt(server_socket, SOL_SOCKET, SO_KEEPALIVE, 
		 (char *) &opt, sizeof(int)) < 0) {
    delete_pid_file ();
    error("setsockopt: (SO_KEEPALIVE)", strerror(errno));
  }

  /* Construct a socket address structure for the local address on
     which we want to listen for connections.  */
  memset (&socket_address, 0, sizeof (socket_address));
  socket_address.sin_family = AF_INET;
  socket_address.sin_port = port;
  socket_address.sin_addr = local_address;
  /* Bind the socket to that address.  */
  rval = bind (server_socket, (struct sockaddr *) &socket_address,
               sizeof (socket_address));
  if (rval != 0) {
    delete_pid_file ();
    error ("bind", strerror(errno));
  }
  /*  Instruct the socket to accept connections.  */
  rval = listen (server_socket, 10);
  if (rval != 0) {
    delete_pid_file ();
    error ("listen", strerror(errno));
  }
  
  if (verbose) {
    /* In verbose mode, display the local address and port number
       we're listening on.  */
    socklen_t address_length;

    /* Find the socket's local address.  */
    address_length = sizeof (socket_address);
    rval = getsockname (server_socket, (struct sockaddr *) &socket_address, 
                         &address_length);
    assert (rval == 0);
    /* Print a message.  The port number needs to be converted from
       network byte order (big endian) to host byte order.  */
    printf ("(%s - %d) server listening on %s:%d\n", program_name, 
              getpid(), inet_ntoa (socket_address.sin_addr),
              (int) ntohs (socket_address.sin_port));
  }

#ifdef DAEMON_MODE
  if (verbose) {
    printf ("(%s - %d) operating in daemon mode\n", program_name, getpid());
  }
  /* Loop forever, handling connections.  */
  while (1) {
   pid_t child_pid;
#endif
    struct sockaddr_in remote_address;
    socklen_t address_length;
    int connection;

    /* Accept a connection.  This call blocks until a connection is
       ready.  */
    address_length = sizeof (remote_address);
    connection = accept (server_socket, (struct sockaddr *) &remote_address,
                          &address_length);
    if (connection == -1) {
      /* The call to accept failed.  */
      if (errno == EINTR)
        /* The call was interrupted by a signal.  Try again.  */
#ifdef DAEMON_MODE
        continue;
#else
        ;
#endif
      else {
        /* Something else went wrong.  */
        delete_pid_file ();
	error ("accept", strerror(errno));
      }
    }

#ifdef DAEMON_MODE
    /* Fork a child process to handle the connection.  */
    child_pid = fork ();
    if (child_pid == 0) {
#endif
      /* We have a connection.  Print a message if we're running in
         verbose mode.  */
      if (verbose) {
        socklen_t address_length;

        /* Get the remote address of the connection.  */
        address_length = sizeof (socket_address);
        rval = getpeername (connection, (struct sockaddr *) &socket_address,
                          &address_length);
        assert (rval == 0);
        /* Print a message.  */
        printf ("(%s - %d) connection accepted from %s\n", program_name, getpid(),
                 inet_ntoa (socket_address.sin_addr));
      }

      /* This is the child process.  It shouldn't use stdin or stdout,
         so close them.  */
      close (STDIN_FILENO);
      close (STDOUT_FILENO);
      /* Also this child process shouldn't do anything with the
         listening socket.  */
      close (server_socket);
      /* Handle a request from the connection.  We have our own copy
         of the connected socket descriptor.  */
      handle_connection (connection);
      /* All done; close the connection socket, and end the child
         process.  */
      close (connection);
      exit (0);
#ifdef DAEMON_MODE
    }
    else if (child_pid > 0) {
      /* This is the parent process.  The child process handles the
         connection, so we don't need our copy of the connected socket
         descriptor.  Close it.  Then continue with the loop and
         accept another connection.  */
      close (connection);
    }
    else {
      /* Call to fork failed.  */
      delete_pid_file ();
      error ("fork", strerror(errno));
    }
  }
#endif
}

