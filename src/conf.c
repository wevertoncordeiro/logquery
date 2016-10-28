#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "server.h"

const char* conf_file;

xmlDocPtr conf_doc;

struct conf **conf_table = NULL;

void read_conf(xmlDocPtr doc)
{
  /* Code from http://xmlsoft.org/tutorial/ */
  xmlNodePtr cur;
  size_t len, lenp;
  int count = 0;

  cur = xmlDocGetRootElement(doc);
  cur = cur->xmlChildrenNode;
  len = sizeof(struct conf);
  lenp = sizeof(struct conf *);
  while (cur != NULL) {
    char *name;
    char *value;

    if (!xmlStrcmp(cur->name, (const xmlChar *) "entry")) {

      name = xstrdup((const char *) xmlGetProp(cur, (const xmlChar *) "name"));
      value = xstrdup((const char *) xmlNodeGetContent(cur));

      conf_table = (struct conf **) xrealloc((void *) conf_table, (count + 1) * lenp);
      conf_table[count] = (struct conf *) xmalloc(len);
      conf_table[count]->name = name;
      conf_table[count]->value = value;
      count++;
      cur = cur->next;
    }
    cur = cur->next;
  }
  conf_table = (struct conf **) xrealloc((void *) conf_table, (count + 1) * lenp);
  conf_table[count] = (struct conf *) xmalloc(len);
  conf_table[count]->name = NULL;
  conf_table[count]->value = NULL;
}

char *search_data_at_conf_table(const char *name)
{
  int i;

  for (i = 0; conf_table[i]->name != NULL; i++)
    if (!strcmp(conf_table[i]->name, name))
      return conf_table[i]->value;
  return NULL;
}

void clean_conf_table(void)
{
  int i = 0;

  while(conf_table[i]->name != NULL) {
    free(conf_table[i]->name);
    free(conf_table[i]->value);
    free(conf_table[i]);
    i++;
  }
  free(conf_table[i]);
  free(conf_table);
  conf_table = NULL;
}

void check_conf_file(xmlDocPtr doc)
{
  if (!valid_document(doc, "dtd/conf.dtd"))
    error("conf file","document is not according to DTD");
}

