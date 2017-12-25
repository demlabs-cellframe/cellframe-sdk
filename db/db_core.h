#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <stddef.h>
#include <mongoc.h>

extern int db_core_init();
extern void db_core_deinit();

extern void db_core_refresh();

extern int db_input_validation(const char * str);

extern mongoc_client_t *mongo_client;


#endif
