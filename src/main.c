/***********************************************************************
* Code listing from "Advanced Linux Programming," by CodeSourcery LLC  *
* Copyright (C) 2001 by New Riders Publishing                          *
* See COPYRIGHT for license information.                               *
***********************************************************************/

#include <assert.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "server.h"

/* Description of long options for getopt_long.  */

static const struct option long_options[] = {
  { "address",          1, NULL, 'a' },
  { "conf-file",        1, NULL, 'c' },
  { "dns-log-dir",      1, NULL, 'd' },
  { "fw-log-dir",       1, NULL, 'f' },
  { "help",             0, NULL, 'h' },
  { "module-dir",       1, NULL, 'm' },
  { "nat-file",         1, NULL, 'n' },
  { "port",             1, NULL, 'p' },
  { "priority",		1, NULL, 'r' },
  { "user",		1, NULL, 'u' },
  { "verbose",          0, NULL, 'v' },
};

/* Description of short options for getopt_long.  */

static const char* const short_options = "a:c:d:f:hk:m:n:p:r:u:v";

/* Usage summary text. Compatibility with ISO C */

static const char* const usage_template_1 = 
  "Usage: %s [ options ]\n"
  "  -a, --address ADDR        Bind to local address\n"
  "  -c, --conf-file           Read the specified config file.\n"
  "  -d, --dns-log-dir         Read DNS logs from specified dir.\n"
  "  -f, --fw-log-dir          Read Firewall logs from specified dir.\n"
  "  -h, --help                Print this information.\n"
  "  -k [start | stop]         Options for daemon mode.\n";

static const char* const usage_template_2 =
  "  -m, --module-dir          Load modules from specified dir.\n"
  "  -n, --nat-file            Read NAT table from specified file.\n"
  "  -p, --port PORT           Bind to specified port.\n"
  "  -r, --priority            Set new process' priority [-19,20].\n"
  "  -u, --user USER           Userid/name to run logquery under.\n"
  "  -v, --verbose             Print verbose messages.\n";

/* Print usage information and exit.  If IS_ERROR is non-zero, write to
   stderr and use an error exit code.  Otherwise, write to stdout and
   use a non-error termination code.  Does not return.  */

static void print_usage (int is_error)
{
  fprintf (is_error ? stderr : stdout, usage_template_1, program_name);
  fprintf (is_error ? stderr : stdout, usage_template_2);
  exit (is_error ? 1 : 0);
}

int main (int argc, char* const argv[])
{
  struct in_addr local_address;
  uint16_t port;
  int next_option;
  int reload_conf = 0;
  int daemon_mode = 0;
  struct stat file_info;
  uid_t uid = 0;
  gid_t gid = 0;
  char *user = NULL;
  int has_uid;

  /* Store the program name, which we'll use in error messages.  */
  program_name = argv[0];
  if (strrchr(program_name, '/') != NULL)
    program_name = strrchr(program_name, '/') + 1;

  /* Set defaults for options.  Bind the server to loopack address only,
     and assign an unused port automatically.  */
  local_address.s_addr = htonl (INADDR_LOOPBACK);
  port = 0;
  /* Don't print verbose messages.  */
  verbose = 0;
  /* Read logs from the directory containing this executable. */
  dns_log_dir = get_self_executable_directory();
  assert(dns_log_dir != NULL);
  fw_log_dir = get_self_executable_directory();
  assert(fw_log_dir != NULL);

  /* Load modules from the directory containing this executable. */
  module_dir = get_self_executable_directory();
  assert(module_dir != NULL);

  /* User didn't specify user id to run this program under yet. */
  has_uid = 0;

  nat_file = NULL;
  nat_doc = NULL;

  conf_file = "xml/conf.xml";

  /* Checking conf file consistency. */

  /* Check that it exists.  */
  if (access (conf_file, F_OK) != 0)
    error (conf_file, "file does not exist");
  /* Check that it is accessible.  */
  if (access (conf_file, R_OK) != 0)
    error (conf_file, "file is not accessible");
  /* Make sure that it is a file.  */
  if (stat (conf_file, &file_info) != 0 || !S_ISREG (file_info.st_mode))
    error (conf_file, "not a file");
  /* It looks OK, so use it.  */
  conf_doc = xmlParseFile(conf_file);
  if (conf_doc == NULL)
    error(conf_file, "error processing file");
  check_conf_file(conf_doc);
  read_conf(conf_doc);

  /* Parse options.  */
  do {
    next_option =
      getopt_long (argc, argv, short_options, long_options, NULL);
    switch (next_option) {
    case 'a':
      /* User specified -a or --address.  */
      {
	struct hostent* local_host_name;

	/* Look up the host name the user specified.  */
	local_host_name = gethostbyname (optarg);
	if (local_host_name == NULL || local_host_name->h_length == 0)
	  /* Could not resolve the name.  */
	  error (optarg, "invalid host name");
	else
	  /* Host name is OK, so use it.  */
	  local_address.s_addr = 
	    *((int*) (local_host_name->h_addr_list[0]));
      }
      break;

    case 'c':
      /* User specified -c or --conf-file. */
      {
        conf_file = strdup (optarg);
        reload_conf = 1;
      }
      break;

   case 'd':
      /* User specified -d or --dns-log-dir. */
      {
        struct stat dir_info;

        /* Check that it exists.  */
        if (access (optarg, F_OK) != 0)
          error (optarg, "directory does not exist");
        /* Check that it is accessible.  */
        if (access (optarg, R_OK | X_OK) != 0)
          error (optarg, "directory is not accessible");
        /* Make sure that it is a directory.  */
        if (stat (optarg, &dir_info) != 0 || !S_ISDIR (dir_info.st_mode))
          error (optarg, "not a directory");
        /* It looks OK, so use it.  */
        dns_log_dir = strdup (optarg);
      }
      break;

    case 'f':
      /* User specified -f or --fw-log-dir. */
      {
        struct stat dir_info;

        /* Check that it exists.  */
        if (access (optarg, F_OK) != 0)
          error (optarg, "directory does not exist");
        /* Check that it is accessible.  */
        if (access (optarg, R_OK | X_OK) != 0)
          error (optarg, "directory is not accessible");
        /* Make sure that it is a directory.  */
        if (stat (optarg, &dir_info) != 0 || !S_ISDIR (dir_info.st_mode))
          error (optarg, "not a directory");
        /* It looks OK, so use it.  */
        fw_log_dir = strdup (optarg);
      }
      break;

    case 'h':
      /* User specified -h or --help.  */
      print_usage (0);

   case 'k':
      /* User specified -k. */
      {
        if (!strcmp(optarg, "start"))
          /* When server starts, we will exit silently. */
          daemon_mode = 1;
        else if (!strcmp(optarg, "stop")) {
          /* The server must be shutten down. */
          pid_t pid;
	  int ret;
	  int tmp_errno;

          if (get_previous_pid(&pid)) {
	    delete_pid_file();
            ret = kill(pid, SIGHUP);
	    tmp_errno = errno;
            if (ret == -1) 
              error("kill", strerror(tmp_errno));
	  }
	  /* We also have to exit */
          exit(0);
        }
      }
      break;

   case 'm':
      /* User specified -m or --module-dir. */
      {
        struct stat dir_info;

        /* Check that it exists.  */
        if (access (optarg, F_OK) != 0)
          error (optarg, "directory does not exist");
        /* Check that it is accessible.  */
        if (access (optarg, R_OK | X_OK) != 0)
          error (optarg, "directory is not accessible");
        /* Make sure that it is a directory.  */
        if (stat (optarg, &dir_info) != 0 || !S_ISDIR (dir_info.st_mode))
          error (optarg, "not a directory");
        /* It looks OK, so use it.  */
        module_dir = strdup (optarg);
      }
      break;

    case 'n':
      /* User specified -n or --nat-file. */
      {
        struct stat file_info;

        /* Check that it exists.  */
        if (access (optarg, F_OK) != 0)
          error (optarg, "file does not exist");
        /* Check that it is accessible.  */
        if (access (optarg, R_OK) != 0)
          error (optarg, "file is not accessible");
        /* Make sure that it is a directory.  */
        if (stat (optarg, &file_info) != 0 || !S_ISREG (file_info.st_mode))
          error (optarg, "not a file");
        /* It looks OK, so use it.  */
        nat_file = strdup (optarg);
        nat_doc = xmlParseFile(nat_file);
        if (nat_doc == NULL)
          error(nat_file, "error processing file");
        check_nat_file(nat_doc);
      }
      break;

    case 'p':
      /* User specified -p or --port.  */
      {
	long value;
	char* end;

	value = strtol (optarg, &end, 10);
	if (*end != '\0')
	  /* The user specified non-digits in the port number.  */
	  print_usage (1);
	/* The port number needs to be converted to network (big endian)
           byte order.  */
	port = (uint16_t) htons (value);
      }
      break;

    case 'r':
      /* User specified -r or --priority. */
      {
        int who;
	long prio;
	char *end;

	who = getpid();
	prio = strtol (optarg, &end, 10);
	if (*end != '\0')
	  /* The user specified non-digits in the prio number.  */
	  print_usage (1);
	if (setpriority (PRIO_PROCESS, who, prio)) {
	  int tmp_errno;
	  
	  tmp_errno = errno;
	  error("setpriority", strerror(tmp_errno));
	}
      }
      break;
    
    case 'u':
      /* User specified -u or --user. */
      {
	struct passwd *pw;
	int tmp_errno;
	
        if(stronlydigits(optarg)) {
          uid = (uid_t) atoi(optarg);
	  pw = getpwuid (uid);
	  tmp_errno = errno;
	  if (pw == NULL)
            error("getpwuid", strerror(tmp_errno));
	} else {
          pw = getpwnam(optarg);
	  tmp_errno = errno;
          if (pw == NULL)
            error("getpwnam", strerror(tmp_errno));
	}
        uid = pw->pw_uid;
        gid = pw->pw_gid;
	user = xstrdup(pw->pw_name);
        endpwent();
	has_uid = 1;
      }
      break;
    
    case 'v':
      /* User specified -v or --verbose.  */
      verbose = 1;
      break;

    case '?':
      /* User specified an nrecognized option.  */
      print_usage (1);

    case -1:  
      /* Done with options.  */
      break;

    default:
      abort ();
    }
  } while (next_option != -1);

  /* This program takes no additional arguments.  Issue an error if the
     user specified any.  */
  if (optind != argc)
    print_usage (1);

  /* If running in daemon mode, we must create a new process instance and
   * save our pid file. */
  if (daemon_mode) {

#ifdef DAEMON_MODE
    pid_t pid;

    /* Daemon mode and verbose are mutually exclusive. */
    verbose = 0;
    /* Fork a new process, so we will disconnect it from tty. */
    pid = fork();
    if (pid == -1)
      error("fork", strerror(errno));
    if (pid != 0)
      /* The parent process must die. */
      exit (0);
#endif

    create_pid_file();
  }
    
  /* If user has specified an alternative user id to run under, we should 
   * drop root privileges. */
  if (has_uid) {
    int tmp_errno;
    
    if (setgid(gid)) {
      tmp_errno = errno;
      delete_pid_file();
      error ("setuid", strerror(tmp_errno));
    } if (setuid(uid)) {
      tmp_errno = errno;
      delete_pid_file();
      error ("setgid", strerror(tmp_errno));
    }
  }
  
  if (reload_conf) {
    /* Checking conf file consistency. */
    struct stat file_info;

    /* Check that it exists.  */
    if (access (conf_file, F_OK) != 0)
      error (conf_file, "file does not exist");
    /* Check that it is accessible.  */
    if (access (conf_file, R_OK) != 0)
      error (conf_file, "file is not accessible");
    /* Make sure that it is a directory.  */
    if (stat (conf_file, &file_info) != 0 || !S_ISREG (file_info.st_mode))
      error (conf_file, "not a file");
    /* It looks OK, so use it.  */
    conf_doc = xmlParseFile(conf_file);
    if (conf_doc == NULL)
      error(conf_file, "error processing file");
    check_conf_file(conf_doc);
    read_conf(conf_doc);
  }

  /* Print the current config, if we're running verbose.  */
  if (verbose) {
    pid_t my_pid = getpid();
    
    if (has_uid)
      printf ("(%s - %d) Running as user %s\n", program_name, my_pid, user);
    printf ("(%s - %d) DNS logs will be read from %s\n", program_name, my_pid, dns_log_dir);
    printf ("(%s - %d) Firewall logs will be read from %s\n", program_name, my_pid, fw_log_dir);
    printf ("(%s - %d) Modules will be loaded from %s\n", program_name, my_pid, module_dir);
    printf ("(%s - %d) Config parameters retrieved from %s\n", program_name, my_pid, conf_file);
    if (nat_file != NULL)
      printf ("(%s - %d) NAT table will be retrieved from %s\n", program_name, my_pid, nat_file);
  }

  /* Run the server.  */
  server_run (local_address, port);

  return 0;
}

