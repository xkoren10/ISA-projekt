/*
*   @brief ISA projekt - Tunelování datových přenosů přes DNS dotazy
*   @author Matej Koreň (xkoren10)
*   @file dns_receiver.c - Serverová aplikácia
*/
#include "dns_receiver.h"
#include "dns_receiver_events.h"


// From https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize)
{
    int buffer = 0;
    int bitsLeft = 0;
    int count = 0;
    for (const uint8_t *ptr = encoded; count < bufSize && *ptr; ++ptr)
    {
        uint8_t ch = *ptr;
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-')
        {
            continue;
        }
        buffer <<= 5;

        // Deal with commonly mistyped characters
        if (ch == '0')
        {
            ch = 'O';
        }
        else if (ch == '1')
        {
            ch = 'L';
        }
        else if (ch == '8')
        {
            ch = 'B';
        }

        // Look up one base32 digit
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
        {
            ch = (ch & 0x1F) - 1;
        }
        else if (ch >= '2' && ch <= '7')
        {
            ch -= '2' - 26;
        }
        else
        {
            return -1;
        }

        buffer |= ch;
        bitsLeft += 5;
        if (bitsLeft >= 8)
        {
            result[count++] = buffer >> (bitsLeft - 8);
            bitsLeft -= 8;
        }
    }
    if (count < bufSize)
    {
        result[count] = '\000';
    }
    return count;
}

void ChangetoDnsNameFormat(unsigned char *dns, char *host)
{   // Načítava znaky pokým nenájde '.', zapíše ich počet a znaky samotné

    int lock = 0, i;
    strcat((char *)host, ".");  // Pre koncový znak \0

    for (i = 0; i < (int)strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++;
        }
    }
    *dns++ = '\0';
}


int save_data(char *message, char *dir_path, int id)
{

    static FILE *file_ptr = NULL;
    char result[1024];
    

    base32_decode((uint8_t *)message, (uint8_t *)result, 1024); // dekóduje správu

    if (id == 0)    // ak je to prvý paket, vytvorí sa súbor na zápis podľa jeho obsahu
    {
        memset(path, 0, 1024);
        strcat(strcat(strcat(path, dir_path), "/"), result);
        file_ptr = fopen(path, "w");
        if (!file_ptr)
        {
            fprintf(stderr, "Error creating file !\n");
            return 1;
        }
    }

    else if ((int)strlen(message) == 0 && (file_ptr != NULL))   // ak je dĺžka správy nulová, ukonči zápis
    {
        struct stat st;
        stat(path, &st);
        fclose(file_ptr);

        //--------------------------------------------------------
        dns_receiver__on_transfer_completed(path, (int)st.st_size);
        //--------------------------------------------------------
        memset(path,0,1024);    // vyčisti cestu k súboru
    }

    else        // inak zapisuj do súboru dekódovanú správu
    {
        if (file_ptr != NULL)
        {
            fwrite(result, 1, strlen(result), file_ptr);
        }
        else
        {
            fprintf(stderr, "Error writing in file !\n");
            return 1;
        }
    }

    return 0;
}


//dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_dirPATH} [SRC_FILEPATH]*/
int main(int argc, char **argv)
{

    char basehost[1024], basehost_encoded[1024];
    char dst_dirpath[1024];
    unsigned char dns_buffer[65536], message[1024], message_segment[64];

    int main_socket;

    // Spracovanie argumentov
    if (argc != 3)
    {
        fprintf(stderr, "Wrong ammount of arguments given!\n");
        exit(EXIT_FAILURE);
    }

    else
    {

        strcpy(basehost, argv[1]);
        strcpy(dst_dirpath, argv[2]);
    }

    fprintf(stderr,"---------------- Arguments --------------------\n");
    fprintf(stderr, "basehost - %s, %d\n", basehost, (int)strlen(basehost));
    fprintf(stderr, "dst - %s, %d\n", dst_dirpath, (int)strlen(dst_dirpath));
    fprintf(stderr,"-----------------------------------------------\n");

    // Vytvorenie zložky pre dáta
    struct stat stat_info = {0};
    if (stat(dst_dirpath, &stat_info) == -1)
    {
        mkdir(dst_dirpath, 0777);
    }

    // Vytvorenie socketu
    if ((main_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("ERROR: socket");
        exit(EXIT_FAILURE);
    }

    // Nastavenia adries
    struct sockaddr_in server, client;

    memset(&server, 0, sizeof(server));
    memset(&client, 0, sizeof(client));

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY; 
    server.sin_port = htons(PORT);       // DNS port = 53

    // Binding socketu na port
    if (bind(main_socket, (struct sockaddr *)&server, sizeof(server)))
    {
        fprintf(stderr, "Failed to bind socket to port %d.\n", (int)server.sin_port);
    }

    socklen_t len = sizeof(client);

    int num_received;
    int size,header_id;
    memset(dns_buffer, 0, sizeof(dns_buffer));

    // Prevedieme na dns formát pre porovnanie s prichádzajúcimi paketmi
    ChangetoDnsNameFormat((unsigned char *)basehost_encoded, basehost);

    // V cykle čakáme na pakety 
    fprintf(stderr,"---------------- Listening --------------------\n");
    while ((num_received = recvfrom(main_socket, dns_buffer, 1024, 0, (struct sockaddr *)&client, &len)) >= 0)
    {


        // Extrakcia query
        unsigned char *query_ptr = dns_buffer + sizeof(struct dns_header_t);
        struct dns_header_t *header = (struct dns_header_t *)&dns_buffer;
        header_id = (int)ntohs(header->id);
        size = (int)(sizeof(struct dns_header_t) + (strlen((const char *)query_ptr) + 1) + sizeof(struct dns_question));

        // Ak sa basehost zhoduje, paket spracujeme
        if (strcmp((const char *)query_ptr + (strlen((const char *)query_ptr) - strlen((const char *)basehost_encoded)), basehost_encoded) != 0)
        {
            continue;
        }

        memset(message, 0, sizeof(message));
        uint8_t segment_size;

        // Odstránenie dĺžok jednotlivých labelov
        while ((segment_size = *((uint8_t *)query_ptr)) && !(query_ptr == query_ptr + (strlen((const char *)query_ptr) - strlen((const char *)basehost_encoded))))
        {
            if (segment_size > 63)  // Nesprávny dĺžka labelu
            { 
                return -1;
            }

            // Uloženie segmentu do bufferu pre správu
            strncpy((char *)message_segment, (char *)query_ptr + 1, segment_size);
            strcat((char *)message, (char *)message_segment);
            memset(message_segment, 0, sizeof(message_segment));

            query_ptr += segment_size + 1;
        }

        if(header_id == 0){
        //--------------------------------------
        dns_receiver__on_transfer_init(&client.sin_addr);
        //--------------------------------------
        }

        //--------------------------------------------------------------------------------------------------------------
        dns_receiver__on_chunk_received(&client.sin_addr, path, header_id, size);
        //--------------------------------------------------------------------------------------------------------------

        //-------------------------------------------------------------------------------------------------
        dns_receiver__on_query_parsed(path, (char *)message);
        //-------------------------------------------------------------------------------------------------

        // Podľa úspešnosti uloženia dát as vracia odpoveď
        if (save_data((char *)message, dst_dirpath, header_id )!= 0)   // Chyba
        {
            header->qr = 1;    // response
            header->rcode = 2; // server error

            if (sendto(main_socket, dns_buffer, size, 0, (struct sockaddr *)&client,
                       sizeof(client)) == -1)
            {
                perror("sendto failed");
            }
        }
        else
        {
            header->qr = 1; // response

            if (sendto(main_socket, dns_buffer, size, 0, (struct sockaddr *)&client,
                       sizeof(client)) == -1)
            {
                perror("sendto failed");
            }
        }
        fprintf(stderr,"-----------------------------------------------\n");
    }

    // Zatvorenie socketu
    close(main_socket);
    return 0;
}