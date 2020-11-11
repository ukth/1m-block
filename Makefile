all: 1m-block

1m-block: main.cpp
	gcc -o 1m-block main.cpp -lnetfilter_queue

clean:
	rm -f report-1m-block *.o
