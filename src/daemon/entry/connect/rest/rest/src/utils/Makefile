LDADD = -lpthread
DEBUG = -g

rq_test: rq_test.o rqueue.o buffer_rqueue.o
	cc -o rq_test rq_test.o rqueue.o buffer_rqueue.o $(LDADD)

rq_test.o: rq_test.c
	cc $(DEBUG) -c rq_test.c

rqueue.o: rqueue.c
	cc $(DEBUG) -c rqueue.c

buffer_rqueue.o: buffer_rqueue.c 
	cc $(DEBUG) -c buffer_rqueue.c

clean:
	rm rq_test *.o