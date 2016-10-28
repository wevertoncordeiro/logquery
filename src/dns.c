#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#define __USE_XOPEN /* glibc2 needs this */
#  include <time.h>
#undef __USE_XOPEN

#include "server.h"

#define MODULE_NAME		"dns"

#define REFUSE -1 /* Denotate fil while recognizing. */

#define BEGIN           0
#define PROCESSING      1
#define END             2

/* This variable tells whether the server must continue processing entries. */

int processing_state;

/* This variable tells in which position from NAT table is IP address */

int pos_nat_table;

struct tg tg_dns[] = {
/* 0 */ { "MONTH", 1, REFUSE },
/* 1 */ { "DAY_XX", 2, REFUSE },
/* 2 */ { "TIME_USEC", 3, REFUSE },
/* 3 */ { "CLIENT", 4, 3 },
/* 4 */ { "TAG_QUERY", 5, REFUSE },
/* 5 */ { "QUERY", 6, REFUSE },
/* 6 */ { NULL, 6, 6 } /* final state. */
};

/* Program function for parsing log lines. */

int program_function
(int current_state, const char *tok, struct tg *automata, struct query_struct *qt,
 struct query_struct *query, struct query_options *opt)
{
  /* current_state: the current state of the automata
   * tok: the symbol to be read by the automata
   * automata: the struct that contaisn the automata
   * qt: variable that will contains the line's parsed fields
   * query: query request, fields that the line must match
   * opt: query options, rules that will direct the matching
   * 
   * return codes:
   * ret == REFUSE: line not recognized
   * anyone else: so far so good
   */
  if (tok == NULL)
    return REFUSE;
  if (!strcmp(automata[current_state].symbol, "MONTH")) {
    /* Month was requested. */
    if (!(strcmp(tok, "Jan") && strcmp(tok, "Feb") && strcmp(tok, "Mar") &&
        strcmp(tok, "Apr") && strcmp(tok, "May") && strcmp(tok, "Jun") &&
        strcmp(tok, "Jul") && strcmp(tok, "Aug") && strcmp(tok, "Sep") &&
        strcmp(tok, "Oct") && strcmp(tok, "Nov") && strcmp(tok, "Dec"))) {
      if (!strncmp(query->date, tok, strlen(tok))) {
        qt->date = xstrdup(tok); /* Storing MONTH in the query_struct fields DATE. */
        return automata[current_state].suc;
      } else
        /* As it doesn't match the query filter, the line must be discarded. */
        return REFUSE;
    } else
      return automata[current_state].alt;

  } else if (!strcmp(automata[current_state].symbol, "DAY_XX")) {
    /* Day number was requested: Restrict Two Digits */
    int d;
    char *end;

    d = strtol(tok, &end, 10);
    if (*end == '\0') {
      char *tmp = (char *) xmalloc(strlen(qt->date) + 3);
      if (d < 10)
        sprintf (tmp, "%s %2d", qt->date, d);
      else
        sprintf (tmp, "%s %d", qt->date, d);
      if (!strcmp(query->date, tmp)) {
        free(qt->date);
        qt->date = tmp; /* Storing "MONTH DAY_XX" in the query_struct field DAY. */
        return automata[current_state].suc;
      } else
        return REFUSE;
    } else
      return automata[current_state].alt;

  } else if (!strcmp(automata[current_state].symbol, "TIME_USEC")) {
    /* Time was requested. */
    struct tm tm;
    char *buffer;
    size_t len;

    buffer = strchr(tok, '.');
    if (buffer != NULL) {
      len = buffer - tok;
      buffer = (char *) xmalloc (len + 1);
      strncpy(buffer, tok, len);
      buffer[len] = '\0';
      if (strlen((char *) strptime(buffer, "%H:%M:%S", &tm)) == 0) {
        if (time_compare(&tm, query->btime) >= 0 && time_compare(&tm, query->etime) <= 0) {
          qt->time = xstrdup(buffer); /* Storing TIME_USEC in the field TIME. */
          free(buffer);
          /* We have to cofirm we have in processing state. */
          processing_state = PROCESSING;
          return automata[current_state].suc;
        } else {
          /* We gues from now on the time field won't match the request. */
          if (processing_state == PROCESSING)
            processing_state = END;
          free(buffer);
          return REFUSE;
        }
      }
      free(buffer);
    }
    return automata[current_state].alt;

  } else if (!strcmp(automata[current_state].symbol, "CLIENT")) {
    char *buffer;
    size_t len;

    buffer = strchr(tok, '#');
    if (buffer != NULL) {
      len = buffer - tok;
      buffer = (char *) xmalloc(len + 1);
      strncpy(buffer, tok, len);
      buffer[len] = '\0';
      if (opt->nat == 1) {

        if (pos_nat_table != -1) {
          if (!belongs_to_class_cidr(buffer, nat_table[pos_nat_table]->network,
               nat_table[pos_nat_table]->netmask)) {
            qt->client = xstrdup(buffer); /* Storing CLIENT in the field CLIENT. */
            free(buffer);
            return automata[current_state].suc;
          } else {
            free(buffer);
            return REFUSE;
          }
        }
      }
      /* Process request normally if we don't find the given IP at NAT_TABLE. */
      if (query->client == NULL || !strncmp(query->client, buffer, 
          strlen(query->client))) {
        qt->client = xstrdup(buffer); /* Storing CLIENT in the field CLIENT. */
        free(buffer);
        return automata[current_state].suc;
      } else {
        free(buffer);
        return REFUSE;
      }
    } else
      return automata[current_state].alt;

  } else if (!strcmp(automata[current_state].symbol, "TAG_QUERY")) {
    if (!strncmp(tok, "query", 5))
      return automata[current_state].suc;
    return automata[current_state].alt;

  } else if (!strcmp(automata[current_state].symbol, "QUERY")) {
    if (query->query == NULL || strstr(tok, query->query) != NULL) {
      qt->query = xstrdup(tok); /* Storing QUERY in the field QUERY. */
      return automata[current_state].suc;
    } 
    return REFUSE;

  }
  /* If the symbol that the automata needs to read this time cannot
   * be processed here, we must give up of recognizing the line. */
  return REFUSE;
}

void process_line
(int connection_fd, const char *line, struct query_struct *query,
 struct query_options *opt)
{
  int current_state = 0;
  char *buffer, *tok;
  char *dns_template =
    "  <entry date=\"%s\" time=\"%s\" client=\"%s\" query=\"%s\"/>\n";
  struct query_struct *qt;

  qt = (struct query_struct *) xmalloc(sizeof(struct query_struct));
  memset(qt, 0, sizeof(struct query_struct));

  buffer = xstrdup(line);
  tok = strtok(buffer, " ");
  do {
    current_state = program_function(current_state, tok, tg_dns, qt, query, opt);
    tok = strtok(NULL, " ");
  } while (current_state != -1 && tg_dns[current_state].symbol != NULL);

  free(buffer);
  if (current_state != -1) {
    size_t len;

    len = strlen(dns_template) + strlen(qt->date) + strlen(qt->time) +
          strlen(qt->client) + strlen(qt->query) + 1;
    buffer = (char *) xmalloc(len);
    sprintf (buffer, dns_template, qt->date, qt->time, qt->client, qt->query);
    send (connection_fd, buffer, strlen(buffer), 0);
    free (qt->date);
    free (qt->time);
    free (qt->client);
    free (qt->query);
    free (buffer);
  } else {
    if (qt->date != NULL)
      free(qt->date);
    if (qt->time != NULL)
      free(qt->time);
    if (qt->src != NULL)
      free(qt->src);
    if (qt->dst != NULL)
      free(qt->dst);
    if (qt->proto != NULL)
      free(qt->proto);
    if (qt->spt != NULL)
      free(qt->spt);
    if (qt->dpt != NULL)
      free(qt->dpt);
  }
  free (qt);
}

/* Process the query attributes and send the results to
 * the file descriptor CONNECTION_FD. */

void
process_query
(int connection_fd, struct query_struct *query, struct query_options *opt)
{
  char *log_file = NULL;
  gzFile gzfd;

  log_file = get_log_file(dns_log_dir, query->date);
  if (log_file == NULL)
    xml_error(connection_fd, "401", "no entries found matching date");
  else {
    gzfd = gzopen(log_file, "rb");
    free (log_file);
    if (gzfd == NULL)
      xml_error(connection_fd, "301", "file access error");
    else {
      char *buffer, *buf;
      char line[4096];

      buffer = (char *) xmalloc(strlen(xml_result_message_begin) +
                                 strlen(MODULE_NAME) + 1);
      sprintf (buffer, xml_result_message_begin, MODULE_NAME);
      send (connection_fd, buffer, strlen(buffer), 0);
      free (buffer);
      if (opt->nat == 1) {
        read_nat_from_doc(nat_doc);
        /* Here we assume query->client is not NULL */
        pos_nat_table = search_ip_at_nat_table(query->client);
      }
      processing_state = BEGIN;
      do {
        memset(line, 0, sizeof(line));
        buf = gzgets(gzfd, line, sizeof(line));
        /* Done to increase speed */
        if (buf != NULL)
          process_line(connection_fd, line, query, opt);
      } while (buf != NULL && (processing_state == BEGIN || processing_state == PROCESSING));
      if (opt->nat == 1) {
        clean_nat_table();
        xmlFreeDoc(nat_doc);
      }
      send (connection_fd, xml_result_message_end, strlen(xml_result_message_end), 0);
      gzclose(gzfd);
    }
  }
}

void module_generate
(int connection_fd, xmlNodePtr cur)
{
  struct query_struct *query;
  struct query_options *opt;
  int error = 0;    /* Error control. */

  query = (struct query_struct *) xmalloc(sizeof(struct query_struct));
  memset(query, 0, sizeof(struct query_struct));

  opt = (struct query_options *) xmalloc(sizeof(struct query_options));
  opt->nat = -1;

  cur = cur->xmlChildrenNode;
  /* Process the received XML request and retrieve it's attributes. */
  while (!error && cur != NULL) {
    xmlChar *uri;

    if ((!xmlStrcmp(cur->name, (const xmlChar *) "field"))) {
      /* We are processing a valid field. Let's check it's name and
       * retrieve it's attributes. */
      uri = xmlGetProp(cur, (const xmlChar *) "name");
      if ((!xmlStrcmp(uri, (const xmlChar *) "date"))) {
        /* Retrieving DATE. */
        uri = xmlNodeGetContent(cur);
        query->date = xstrdup((const char *) uri);
      } else if ((!xmlStrcmp(uri, (const xmlChar *) "btime"))) {
        /* Retrieving BEGIN TIME. */
        uri = xmlNodeGetContent(cur);
        query->btime = (struct tm *) xmalloc(sizeof(struct tm));
        if (strlen((char *) strptime((const char *) uri,
               "%H:%M:%S", query->btime)) != 0) {
          error = 1;
          xml_error(connection_fd, "201",
            "time format not recognized");
        }
      } else if ((!xmlStrcmp(uri, (const xmlChar *) "etime"))) {
        /* Retrieving END TIME. */
        uri = xmlNodeGetContent(cur);
        query->etime = (struct tm *) xmalloc(sizeof(struct tm));
        if (strlen((char *) strptime((const char *) uri,
               "%H:%M:%S", query->etime)) != 0) {
          error = 1;
          xml_error(connection_fd, "201",
            "time format not recognized");
        }
      } else if ((!xmlStrcmp(uri, (const xmlChar *) "client"))) {
        /* Retrieving CLIENT. */
        uri = xmlNodeGetContent(cur);
        query->client = xstrdup((const char *) uri);
      } else if ((!xmlStrcmp(uri, (const xmlChar *) "query"))) {
        /* Retrieving QUERY. */
        uri = xmlNodeGetContent(cur);
        query->query = xstrdup((const char *) uri);
      } else {
        error = 1;
        xml_error(connection_fd, "201",
          "specified field name not supported for this type");
      }
      /* Free temporary attribute variable. */
      xmlFree(uri);
    } else if (!(xmlStrcmp(cur->name, (const xmlChar *) "option"))) {
      /* We are processing an option field. An option field contains
       * both name and value attributes. */
      uri = xmlGetProp(cur, (const xmlChar *) "name");
      if ((!xmlStrcmp(uri, (const xmlChar *) "nat"))) {
        /* Retrieving NAT. */
        uri = xmlNodeGetContent(cur);
        if (!(xmlStrcmp(uri, (const xmlChar *) "on")))
          opt->nat = 1;
        else if (!(xmlStrcmp(uri, (const xmlChar *) "off")))
          opt->nat = 0;
        else {
          error = 1;
          xml_error(connection_fd, "201", "unsupported option value");
        }
      } else {
        error = 1;
        xml_error(connection_fd, "201",
          "specified option name not supported for this type");
      }
    }
    /* Go to the next XML children. */
    cur = cur->next;
  }
  if (!error) {
    if (query->date != NULL && query->btime != NULL && query->etime != NULL) {
      if (time_compare(query->btime, query->etime) <= 0) {
        if ((opt->nat == 1 && query->client != NULL && nat_doc != NULL) || opt->nat != 1) {
          process_query(connection_fd, query, opt);
        } else if (nat_file == NULL) {
          xml_error(connection_fd, "201","nat table not available");
        } else {
          xml_error(connection_fd, "201","field dependency not resolved");
        }
      } else {
        xml_error(connection_fd, "201","time end must be greater or equals to date begin");
      }
    } else
      xml_error(connection_fd, "201","timestamp fields must not be ingnored");
  }
  /* Cleaning *query */
  if (query->date != NULL)
    free(query->date);
  if (query->btime != NULL)
    free(query->btime);
  if (query->etime != NULL)
    free(query->etime);
  if (query->client != NULL)
    free(query->client);
  if (query->query != NULL)
    free(query->query);
  free(query);
  /* Cleaning *opt */
  free (opt);
}

