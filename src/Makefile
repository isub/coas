#ORACLE_HOME=/u01/app/oracle/product/11.2.0/db_1
OCI_L	= -L$(ORACLE_HOME)/lib/
LIB		= -lpthread -lclntsh
OCI_H	= -I$(ORACLE_HOME)/rdbms/public
UTL_DIR	= ../../utils
UTL_H	= -I../../

all: clean coas

coas: ./obj/deamon.o ./obj/coas.o ./obj/radius.o ./obj/md5.o ./obj/log.o ./obj/pspacket.o ./obj/config.o
	g++ ./obj/deamon.o ./obj/coas.o ./obj/radius.o ./obj/md5.o ./obj/log.o ./obj/pspacket.o ./obj/config.o -o ../coas $(OCI_L) $(LIB)
./obj/deamon.o: ./deamon/main.cpp ./deamon/main.h
	g++ -c ./deamon/main.cpp -o ./obj/deamon.o
./obj/coas.o: ./coas/coas.cpp ./coas/coas.h
	g++ -c ./coas/coas.cpp $(OCI_H) -o ./obj/coas.o
./obj/radius.o: ./radiusclient/radius.cpp ./radiusclient/radius.h
	g++ -c ./radiusclient/radius.cpp -o ./obj/radius.o
./obj/md5.o: ./md5/md5.cpp ./md5/md5.h
	g++ -c ./md5/md5.cpp -o ./obj/md5.o
./obj/pspacket.o: $(UTL_DIR)/pspacket/pspacket.cpp $(UTL_DIR)/pspacket/pspacket.h
	g++ -c $(UTL_DIR)/pspacket/pspacket.cpp -o ./obj/pspacket.o $(UTL_H)
./obj/log.o: $(UTL_DIR)/log/log.cpp $(UTL_DIR)/log/log.h
	g++ -c $(UTL_DIR)/log/log.cpp -o ./obj/log.o
./obj/config.o: $(UTL_DIR)/config/config.cpp $(UTL_DIR)/config/config.h
	g++ -c $(UTL_DIR)/config/config.cpp -o ./obj/config.o

install:
	cp -f ../coas /usr/local/bin/coas

clean:
	rm -f ./obj/*.o ../coas