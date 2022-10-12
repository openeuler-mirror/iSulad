LDADD = -ldl -levent -lnghttp2
DEBUG = -g

test: test.o server.o session.o stream_context.o ioevent.o
	cc -o test main.o server.o session.o stream_context.o ioevent.o $(LDADD)

test.o: main.c
	cc $(DEBUG) -c main.c

server.o: server.c 
	cc $(DEBUG) -c server.c

stream_context.o: stream_context.c
	cc $(DEBUG) -c stream_context.c

session.o: session.c
	cc $(DEBUG) -c session.c 

ioevent.o: ioevent.c 
	cc $(DEBUG) -c ioevent.c

clean: 
	rm test *.o