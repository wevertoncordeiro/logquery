/***********************************************************************
* Code listing from "Advanced Linux Programming," by CodeSourcery LLC  *
* Copyright (C) 2001 by New Riders Publishing                          *
* See COPYRIGHT for license information.                               *
***********************************************************************/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "server.h"

const char* program_name;

int verbose;

const char *fw_log_dir;

const char *dns_log_dir;

const char *nat_file;

void* xmalloc (size_t size)
{
  void* ptr = malloc (size);
  /* Abort if the allocation failed.  */
  if (ptr == NULL)
    abort ();
  else
    return ptr;
}

void* xrealloc (void* ptr, size_t size)
{
  ptr = realloc (ptr, size);
  /* Abort if the allocation failed.  */
  if (ptr == NULL)
    abort ();
  else
    return ptr;
}

char* xstrdup (const char* s)
{
  char* copy = strdup (s);
  /* Abort if the allocation failed.  */
  if (copy == NULL)
    abort ();
  else
    return copy;
}

void error (const char* cause, const char* message)
{
  /* Print an error message to stderr.  */
  fprintf (stderr, "%s: error: (%s) %s\n", program_name, cause, message);
  /* End the program.  */
  exit (1);
}

char* get_self_executable_directory ()
{
  int rval;
  char link_target[1024];
  char* last_slash;
  size_t result_length;
  char* result;

  /* Read the target of the symbolic link /proc/self/exe.  */
  rval = readlink ("/proc/self/exe", link_target, sizeof (link_target) - 1);
  if (rval == -1) {
    error ("readlink", strerror(errno));
    /* The call to readlink failed, so bail.  */
    abort ();
  } else
    /* NUL-terminate the target.  */
    link_target[rval] = '\0';
  /* We want to trim the name of the executable file, to obtain the
     directory that contains it.  Find the rightmost slash.  */
  last_slash = strrchr (link_target, '/');
  if (last_slash == NULL || last_slash == link_target)
    /* Something stange is going on.  */
    abort ();
  /* Allocate a buffer to hold the resulting path.  */
  result_length = last_slash - link_target;
  result = (char*) xmalloc (result_length + 1);
  /* Copy the result.  */
  strncpy (result, link_target, result_length);
  result[result_length] = '\0';
  return result;
}

int time_compare (struct tm *time1, struct tm *time0)
{
  /* Return a value less than, equal to or greater than 0 if time1 is
   * found to be, respectively, less than, equal to or greater than time0. */
  if (time1->tm_hour != time0->tm_hour)
    return (time1->tm_hour - time0->tm_hour);
  if (time1->tm_min != time0->tm_min)
    return (time1->tm_min - time0->tm_min);
  return (time1->tm_sec - time0->tm_sec);
}

char *get_log_file(const char *path, const char *date)
{
  struct dirent **namelist;
  char *result = NULL;
  int n;

  n = scandir(path, &namelist, 0, alphasort);
  if (n < 0)
    perror("scandir");
  else {
    int i = 2; /* first two entries are . and .. and should be discarded */

    while(i < n && result == NULL) {
      struct stat *file_stat;
      char *file_name;
      char *time_stamp;

      file_name = (char *) xmalloc(strlen(path) + strlen(namelist[i]->d_name) + 1);
      sprintf(file_name, "%s%s", path, namelist[i]->d_name);
      file_stat = (struct stat *) xmalloc (sizeof(struct stat));
      stat(file_name, file_stat);
      time_stamp = xstrdup((char *) ctime(&(file_stat->st_mtime)));
      time_stamp[24] = '\0';
      if (strstr (time_stamp, date))
        result = xstrdup(file_name);
      free(file_name);
      free(file_stat);
      free(time_stamp);
      free(namelist[i]);
      i++;
    }
    free(namelist);
  }
  return result;
}

in_addr_t cidr_to_netmask(int cidr)
{
  in_addr_t netmask;

  netmask = 0x0;
  while (cidr-- > 0)
    netmask |= (0x80000000 >> cidr);
  return netmask;
}

int belongs_to_class_cidr(char *ip, char *network, int netmask)
{
  in_addr_t in_ip, in_network, in_netmask;

  if (!(ip == NULL || network == NULL || netmask < 0 || netmask > 32)) {
    in_ip = htonl(inet_addr(ip));
    in_network = htonl(inet_addr(network));
    in_netmask = cidr_to_netmask(netmask);
    return ((in_ip & in_netmask) == in_network) ? 0 : 1;
  }
  return 1;
}

int valid_document(xmlDocPtr doc, const char *dtd_file)
{
  xmlDtdPtr dtd;
  xmlValidCtxtPtr ctxt;
  int result;

  if (dtd_file == NULL)
    error("(null)","unable to load dtd file");
  dtd = xmlParseDTD((const xmlChar *) NULL, (const xmlChar *) dtd_file);
  if (!dtd)
    error(dtd_file, "unable to load file");
  ctxt = xmlNewValidCtxt();
  if(!ctxt)
    error("xmlNewValidCtxt","unable to alloc context");
  result = xmlValidateDtd(ctxt, doc, dtd);
  xmlFreeValidCtxt(ctxt);
  /* When xmlValidateDtd returns 0, the document is not valid, when it
   * returns 1, the document is valid */
  return result;
}

void create_pid_file(void)
{
  FILE *fp;
  char *local_dir, *file_name;
  size_t len;
  int pid;

  local_dir = get_self_executable_directory ();
  len = strlen(local_dir) + strlen(program_name) +
         4 /* strlen(".pid") */ + 2;
  file_name = (char *) xmalloc(len);
  sprintf (file_name, "%s/%s.pid", local_dir, program_name);
try_again:
  /* Check that it exists.  */
  if (access (file_name, F_OK) != 0) {
    int tmp_errno;
    
    /* The file doesn't exit: we are okay to work. */
    fp = fopen(file_name, "w");
    tmp_errno = errno;
    free(file_name);
    free(local_dir);
    if (fp == NULL)
      error("fopen", strerror(tmp_errno));
    pid = (int) getpid();
    fprintf (fp, "%d\n", pid);
    fflush(fp);
    fclose(fp);
  } else {
    int tmp_errno;
    
    /* The file exist: we must give up. */
    char c_pid[8];

    fp = fopen(file_name, "r");
    tmp_errno = errno;
    if (fp == NULL)
      error("fopen", strerror(tmp_errno));
    if (fscanf(fp, "%d", &pid) == 1) {
      sprintf (c_pid, "%d", pid);
      error(c_pid, "there is another instance running");
    } else {
      /* File is empty, or in a non-recognized format. Delete it
       * and try it again.
       */
      fclose (fp);
      delete_pid_file ();
      goto try_again;
    }
  }
}

int get_previous_pid(int *pid)
{
  FILE *fp;
  char *local_dir, *file_name;
  size_t len;
  int my_pid;
  int tmp_errno;

  local_dir = get_self_executable_directory ();
  len = strlen(local_dir) + strlen(program_name) +
         4 /* strlen(".pid") */ + 2;
  file_name = (char *) xmalloc(len);
  sprintf (file_name, "%s/%s.pid", local_dir, program_name);
  fp = fopen(file_name, "r");
  tmp_errno = errno;
  free(file_name);
  free(local_dir);
  if (fp == NULL)
    error("fopen", strerror(tmp_errno));
  if (fscanf (fp, "%d", &my_pid) == 1) {
    fclose(fp);
    *pid = my_pid;
    return 1;
  }
  return 0;
}

void delete_pid_file(void)
{
  char *local_dir, *file_name;
  size_t len;
  int ret;
  int tmp_errno;
  
  local_dir = get_self_executable_directory ();
  len = strlen(local_dir) + strlen(program_name) +
         4 /* strlen(".pid") */ + 2;
  file_name = (char *) xmalloc(len);
  sprintf (file_name, "%s/%s.pid", local_dir, program_name);
  ret = unlink(file_name);
  tmp_errno = errno;
  free(local_dir);
  free(file_name);
  if (ret == -1)
    error("unlink", strerror(tmp_errno));
}

int stronlydigits(const char *s) {

  if((*s) == '\0')
    return 0;
  while ((*s) != '\0') {
    if(!isdigit(*s))
      return 0;
    s++;
  }
  return(1);
}

