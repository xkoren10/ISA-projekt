# @brief ISA projekt - Tunelování datových přenosů přes DNS dotazy
# @author Matej Koreň
# @file Makefile

CC=gcc
CFLAGS=-std=gnu99 -Wall -Wextra -pedantic

.PHONY: all clean sender receiver

all: sender receiver

sender: sender/dns_sender.c sender/dns_sender_events.c
	$(CC) $(CFLAGS) sender/dns_sender.c sender/dns_sender_events.c -o dns_sender
	

receiver: receiver/dns_receiver.c  receiver/dns_receiver_events.c
	$(CC) $(CFLAGS) receiver/dns_receiver.c  receiver/dns_receiver_events.c -o dns_receiver



clean:
	
	rm -f *.o
	rm -f dns_sender
	rm -f dns_receiver
