#include <string.h>
#include <bson.h>
#include <bcon.h>
#include <mongoc.h>
#include "common.h"
#include "config.h"
#include "db_core.h"
#define LOG_TAG "db"

mongoc_client_t *mongo_client = NULL;

int db_core_init()
{
    mongoc_init();

    mongo_client = mongoc_client_new (my_config.db_path);

    log_it(DEBUG, "Checking connection to database...");
    if(!mongoc_client_get_server_status(mongo_client, NULL, NULL, NULL))
    {
        log_it(ERROR, "Can't connect to database");
        return -1;
    }

    return 0;
}

void db_core_deinit()
{
    mongoc_client_destroy (mongo_client);
    mongoc_cleanup ();
}



void db_core_refresh()
{

}


int db_input_validation(const char * str)
{
        // The compiler will stack "multiple" "strings" "end" "to" "end"
        // into "multiplestringsendtoend", so we don't need one giant line.
        static const char *nospecial="0123456789"
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                ".=@?_!#$%";

        while(*str) // Loop until (*url) == 0.  (*url) is about equivalent to url[0].
        {
                // Can we find the character at *url in the string 'nospecial'?
                // If not, it's a special character and we should return 0.
                if(strchr(nospecial, *str) == NULL) return(0);
                str++; // Jump to the next character.  Adding one to a pointer moves it ahead one element.
        }

        return(1); // Return 1 for success.
}
