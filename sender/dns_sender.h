/*
*   @brief ISA projekt - Tunelování datových přenosů přes DNS dotazy
*   @author Matej Koreň (xkoren10)
*   @file dns_sender.h
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>


#define BLOCK 120
#define PORT 53



/// @brief Payload structure
struct __attribute__((__packed__)) Payload {
  uint8_t length;
  char data[BLOCK];
} dns_payload;


/// @brief DNS header structure, as defined in RFC1035
struct dns_header_t{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
} ;



/// @brief DNS question strucure (without qname)
struct dns_question
{
	unsigned short qtype;
	unsigned short qclass;
};

/// Global file path
char dst_filepath[1024];

/// @brief Change hostname (www.example.com) to valid dns format (\03www\07example\03com)
/// @param dns 
/// @param host 
void ChangetoDnsNameFormat( unsigned char* dns,char* host);

/// @brief Assemble dns packet and send it to server via socket
/// @param base32_encode 
/// @param num_written 
/// @param ip 
/// @param basehost 
/// @param main_socket 
void send_chunk(char *base32_encode, size_t num_written,
                char *ip, char *basehost,int main_socket);


int base32_encode(const uint8_t *data, int length, uint8_t *result, int bufSize);

