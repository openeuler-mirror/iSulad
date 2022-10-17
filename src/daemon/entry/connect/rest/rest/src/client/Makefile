LDADD = -ldl -lnghttp2

client: tcp_client.o http_parser.o
	cc -o client tcp_client.o http_parser.o $(LDADD)

tcp_client.o: tcp_client.c 
	cc $(DEBUG) -c tcp_client.c

http_parser.o: http_parser.c 
	cc $(DEBUG) -c http_parser.c

clean:
	rm client *.o
