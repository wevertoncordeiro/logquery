#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "server.h"

const char* nat_file;

xmlDocPtr nat_doc;

struct nat **nat_table = NULL;

void read_nat_from_doc(xmlDocPtr doc)
{
  /* Code from http://xmlsoft.org/tutorial/ */
  xmlNodePtr cur;
  size_t len, lenp;
  int count = 0;

  cur = xmlDocGetRootElement(doc);
  cur = cur->xmlChildrenNode;
  len = sizeof(struct nat);
  lenp = sizeof(struct nat *);
  while (cur != NULL) {
    char *network, *target;
    long netmask;

    if (!xmlStrcmp(cur->name, (const xmlChar *) "entry")) {

      network = xstrdup((const char *) xmlGetProp(cur, (const xmlChar *) "network"));
      netmask = strtol((const char *) xmlGetProp(cur, (const xmlChar *) "netmask"), NULL, 10);
      target = xstrdup((const char *) xmlNodeGetContent(cur));

      nat_table = (struct nat **) xrealloc((void *) nat_table, (count + 1) * lenp);
      nat_table[count] = (struct nat *) xmalloc(len);
      nat_table[count]->network = network;
      nat_table[count]->netmask = netmask;
      nat_table[count]->target = target;
      count++;
      cur = cur->next;
    }
    cur = cur->next;
  }
  nat_table = (struct nat **) xrealloc((void *) nat_table, (count + 1) * lenp);
  nat_table[count] = (struct nat *) xmalloc(len);
  nat_table[count]->network = NULL;
  nat_table[count]->netmask = 0;
  nat_table[count]->target = NULL; 
}

int search_ip_at_nat_table(const char *ip)
{
  int i;

  for (i = 0; nat_table[i]->target != NULL; i++)
    if (!strcmp(nat_table[i]->target, ip))
      return i;
  return -1;
}

void clean_nat_table(void)
{
  int i = 0;

  while(nat_table[i]->target != NULL) {
    free(nat_table[i]->target);
    free(nat_table[i]->network);
    free(nat_table[i]);
    i++;
  }
  free(nat_table[i]);
  free(nat_table);
  nat_table = NULL;
}

void check_nat_file(xmlDocPtr doc)
{
  if (!valid_document(doc, search_data_at_conf_table("nat")))
    error("nat file", "document is not according to DTD");
}

