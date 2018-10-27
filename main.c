#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "example.h"
#include "ss_api.h"

void ss_test1(void)
{
    int ret;
    int i;
    char buf[1024];
    
    struct ss_buff * pbuff = ss_buff_alloc();

    for ( i = 0 ; i < 100000 ; i++ )
    {
        ret = ss_buff_write( pbuff, buf, sizeof(buf) );
        if ( ret != sizeof(buf) )
        {
            printf(" write failed! ret = %d. %d \n", ret, i );
            break;
        }

        ret = ss_buff_read( pbuff, buf, sizeof(buf) );
        if ( ret != sizeof(buf) )
        {
            printf(" read failed! ret = %d. %d \n", ret, i );
            break;
        }
    }

    ss_buff_free( pbuff);
}

void ss_test2(void)
{
    int ret;
    int i;
    char buf[1713];
    
    struct ss_buff * pbuff = ss_buff_alloc();

    for ( i = 0 ; i < 100000 ; i++ )
    {
        ret = ss_buff_write( pbuff, buf, sizeof(buf) );
        if ( ret != sizeof(buf) )
        {
            printf(" write failed! ret = %d. %d \n", ret, i );
            break;
        }

        ret = ss_buff_read( pbuff, buf, sizeof(buf) );
        if ( ret != sizeof(buf) )
        {
            printf(" read failed! ret = %d. %d \n", ret, i );
            break;
        }
    }

    ss_buff_free( pbuff);
}


int main(int argc, char * argv[])
{
    int i;
    int flag = 0;
    pthread_t tid;

    ss_init(argc, argv);

    pthread_create(&tid, NULL, (void *(*)(void*))ss_run, NULL);

    for ( i = 0 ; i < argc ; i++ )
    {
        if ( 0 == strcmp(argv[i],"server") )
        {
            flag = 1;
        }

        if ( 0 == strcmp(argv[i],"client") )
        {
            flag = 0;
        }
    }

    pthread_create(&tid, NULL, stat_display, NULL);

    if ( flag )
    {
        // server port 1100
        server_init(argc, argv);
    }
    else
    {
        // client addr 127.0.0.1 port 1100
        client_init(argc, argv);
    }

    return 0;
}

