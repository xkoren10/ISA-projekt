/*
*   @brief ISA projekt - Tunelování datových přenosů přes DNS dotazy
*   @author Matej Koreň (xkoren10)
*   @file dns_receiver.h
*/

#include "../sender/dns_sender.h"

char path[1024];

/// @brief Function to decode received message.
/// @param encoded 
/// @param result 
/// @param bufSize 
/// @return Ammonut of decoded symbols.
int base32_decode(const uint8_t *encoded, uint8_t *result, int bufSize);

/// @brief Decodes the message and saves it to a specified file
/// @param message
/// @param dir_path
/// @param id
/// @return Ammonut of decoded symbols.
int save_data(char *message, char *dir_path, int id);

