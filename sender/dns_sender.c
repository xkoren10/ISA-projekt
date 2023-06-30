/*
*   @brief ISA projekt - Tunelování datových přenosů přes DNS dotazy
*   @author Matej Koreň (xkoren10)
*   @file dns_sender.c - Klientska aplikácia
*/

#include "dns_sender.h"
#include "dns_sender_events.h"

// From https://github.com/google/google-authenticator-libpam/blob/master/src/base32.c
int base32_encode(const uint8_t *data, int length, uint8_t *result,
                  int bufSize)
{

    if (length < 0 || length > (1 << 28))
    {
        return -1;
    }
    int count = 0;
    if (length > 0)
    {
        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;
        while (count < bufSize && (bitsLeft > 0 || next < length))
        {
            if (bitsLeft < 5)
            {
                if (next < length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            int index = 0x1F & (buffer >> (bitsLeft - 5));
            bitsLeft -= 5;
            result[count++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[index];
        }
    }
    if (count < bufSize)
    {
        result[count] = '\000';
    }
    return count;
}

void ChangetoDnsNameFormat(unsigned char *dns, char *host)
{ // Načítava znaky pokým nenájde '.', zapíše ich počet a znaky samotné

    int lock = 0, i;
    strcat((char *)host, "."); // Pre koncový znak \0

    dns += strlen((const char *)dns);

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

void send_chunk(char *base32_encode, size_t num_written,
                char *ip, char *basehost, int main_socket)
{

    static unsigned short chunk_id = 0; // Počítadlo chunkov
    unsigned char buffer[65536], *qname;

    memset(buffer, 0, sizeof(buffer));

    struct dns_header_t *header = NULL;
    struct dns_header_t *response_header = NULL;
    struct dns_question *qinfo = NULL;

    unsigned char response[1024]; // Buffer pre odpoveď

    memset(response, 0, sizeof(response));
    response_header = (struct dns_header_t *)&response; // Hlavička odpovede

    header = (struct dns_header_t *)&buffer;
    header->id = htons(chunk_id); // ID
    header->qr = 0;               // Query
    header->opcode = 0;           // Standard query
    header->aa = 0;               // Neautoritatívna odpoveď
    header->tc = 0;               // Neskrátená otázka
    header->rd = 1;               // Vyžadovaná rekurzia
    header->ra = 0;               // Možná rekurzia (Nastavovaná v odpovedi)
    header->z = 0;                // Rezervované
    header->ad = 1;               // Neautentické dáta
    header->cd = 0;               // Checking
    header->rcode = 0;            // Návratový kód
    header->q_count = htons(1);   // 1 otázka
    header->ans_count = 0;        // 0 odpovedí
    header->auth_count = 0;       // Ignorujeme entries
    header->add_count = 0;        // Ignorujeme entries

    qname = (unsigned char *)&buffer[sizeof(struct dns_header_t)]; // qname je za headerom

    int num_labels = num_written / 60 + (num_written % 60 ? 1 : 0);

    // Pridávanie labels pred sekvenciu dát, maximálne 64 znakov
    for (int i = 0; i < num_labels; ++i)
    {
        int start = i * 60;
        size_t count =
            (start + 60 <= (int)num_written) ? 60 : num_written - start;
        memcpy(qname + (strlen((const char *)qname)), &count, 1);
        memcpy(qname + (strlen((const char *)qname)), base32_encode + start, count);
    }

    ChangetoDnsNameFormat(qname, basehost);

    qinfo = (struct dns_question *)&buffer[sizeof(struct dns_header_t) + (strlen((const char *)qname) + 1)]; // qinfo je za qname
    qinfo->qtype = htons(1);                                                                                 // A dotaz (ipv4)
    qinfo->qclass = htons(1);                                                                                // Internetová adresa

    struct sockaddr_in sender;
    sender.sin_addr.s_addr = inet_addr(ip); // -u parameter
    sender.sin_family = AF_INET;
    sender.sin_port = htons(PORT); // dns port

    //---------------------------------------------
    dns_sender__on_transfer_init(&sender.sin_addr);
    //------------------------------------------------------------------
    dns_sender__on_chunk_encoded(dst_filepath, chunk_id, base32_encode);
    //------------------------------------------------------------------

    // Odoslanie paketu
    int send_ret;
    send_ret = sendto(main_socket, (char *)buffer, sizeof(struct dns_header_t) + (strlen((const char *)qname) + 1) + sizeof(struct dns_question),
                      0, (struct sockaddr *)&sender, sizeof(struct sockaddr_in));
    //---------------------------------------------------------------------------------------------------------------------------------------------------------------
    dns_sender__on_chunk_sent(&sender.sin_addr, dst_filepath, chunk_id, (int)(sizeof(struct dns_header_t) + (strlen((const char *)qname) + 1) + sizeof(struct dns_question)));
    //---------------------------------------------------------------------------------------------------------------------------------------------------------------

    chunk_id++; // predpríprava na ďalší packet

    if (send_ret == -1) // chyba odoslania
    {
        fprintf(stderr, "sendto failed.\n");
        exit(EXIT_FAILURE);
    }

    // Ošetrenie spätnej väzby

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(main_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);  // nastavenie timeout-u pri príjmaní


    int num_received;
    socklen_t socklen = sizeof(struct sockaddr_in);
    if ((num_received = recvfrom(main_socket, response, sizeof(response), 0,
                                 (struct sockaddr *)&sender, &socklen)) == -1)
    {
        fprintf(stderr, "Recv failed - no response.\n");
        exit(EXIT_FAILURE);
    }

    // Odpoveď zo serveru nemá response kód 2 -> dáta boli uložené
    if (response_header->qr == 1 && header->rcode != 2)
    {
        fprintf(stderr,"--- Packet received. --- \n");
        fprintf(stderr,"-------------------------\n");
    }

    else // chyba na strane serveru
    {
        fprintf(stderr, "--- fix ur server bro. --- \n ");
        exit(EXIT_FAILURE);
    }
}

//  dns_sender [-u UPSTREAM_DNS_IP] {BASE_HOST} {DST_FILEPATH} [SRC_FILEPATH]
int main(int argc, char **argv)
{

    char upstream[16];
    char basehost[1024];
    char dst_filepath_encoded[1024];
    char src_filepath[1024];
    FILE *source_file = stdin;

    struct in_addr direct_ip;
    char base32_data_buf[256];
    memset(src_filepath, 0, 1024);

    // Spracovanie argumentov
    if ((argc == 1) || (argc > 6))
    {
        fprintf(stderr, "Wrong ammount of arguments given!\n");
        exit(EXIT_FAILURE);
    }

    else
    {
        if (strcmp(argv[1], "-u") == 0)
        {
            strcpy(upstream, argv[2]);
            strcpy(basehost, argv[3]);
            strcpy(dst_filepath, argv[4]);

            if (argc == 6)
                strcpy(src_filepath, argv[5]);
        }

        else
        {
            // Prvý implicitný dns server v resolv.conf
            FILE *implicit_dns = popen("cat /etc/resolv.conf | grep -oP '(?<=nameserver )[^ ]*'", "r");
            fgets(upstream, 1024, implicit_dns);
            upstream[strcspn(upstream, "\n")] = 0;
            pclose(implicit_dns);

            strcpy(basehost, argv[1]);
            strcpy(dst_filepath, argv[2]);

            if (argc == 4)
                strcpy(src_filepath, argv[3]);
        }
    }

    fprintf(stderr,"---------------- Arguments --------------------\n");
    fprintf(stderr, "upstream - %s, %d\n", upstream, (int)strlen(upstream));
    fprintf(stderr, "basehost - %s, %d\n", basehost, (int)strlen(basehost));
    fprintf(stderr, "dst - %s, %d\n", dst_filepath, (int)strlen(dst_filepath));
    fprintf(stderr, "src - %s, %d\n", src_filepath, (int)strlen(src_filepath));
    fprintf(stderr,"-----------------------------------------------\n");

    // Podpora IPv4
    if (inet_aton(upstream, &direct_ip) == 0)
    {
        fprintf(stderr, "Parameter 'basehost' should be an IPv4 address !\n");
        return 1;
    }

    if (strlen(src_filepath) > 0)
    {
        source_file = fopen(src_filepath, "r");
        if (!source_file)
        {
            fprintf(stderr, "Error opening file !\n");
            return 1;
        }
    }

    int main_socket;

    // Vytvorenie socketu
    if ((main_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        fprintf(stderr, "ERROR: socket");
        exit(EXIT_FAILURE);
    }

    // Prvý paket - dst_filepath
    fprintf(stderr,"---------------- Destination --------------------\n");
    size_t dst_num_written =
        base32_encode((uint8_t *)&dst_filepath,
                      (int)strlen(dst_filepath),
                      (uint8_t *)dst_filepath_encoded, 256);
    
    dst_filepath_encoded[dst_num_written] = '\0';
    send_chunk(dst_filepath_encoded, dst_num_written,
               upstream, basehost, main_socket);

    // Parsovanie súboru
    while (!feof(source_file))
    {
        dns_payload.length = 0;
        memset(dns_payload.data, 0, BLOCK);

        dns_payload.length = (uint8_t)fread(dns_payload.data, 1, BLOCK, source_file); // načítanie 120 znakov

        size_t num_written =
            base32_encode((uint8_t *)&dns_payload.data,
                          sizeof(struct Payload) - BLOCK + dns_payload.length,
                          (uint8_t *)base32_data_buf, 256);

        base32_data_buf[num_written] = '\0';

        send_chunk(base32_data_buf, num_written,
                   upstream, basehost, main_socket);


    }

    // Posledný ukončovací paket - len basehost

    memset(dst_filepath_encoded, 0, 1024); // Pre prázdny qname

    send_chunk(dst_filepath_encoded, 0,
               upstream, basehost, main_socket);

    struct stat st;
    stat(src_filepath, &st);

    //---------------------------------------------------------------
    dns_sender__on_transfer_completed(dst_filepath, (int)st.st_size);
    //---------------------------------------------------------------

    // Zatvorenie súboru a socketu
    fclose(source_file);
    close(main_socket);
    return 0;
}