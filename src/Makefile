ORACLE_HOME=/u01/app/oracle/product/11.2.0/db_1
OCI_L=-L$(ORACLE_HOME)/lib/
LIB=-lpthread -lclntsh
OCI_H=-I$(ORACLE_HOME)/rdbms/public
UTL_DIR=../../utils

all: clean coas

coas: ./obj/deamon.o ./obj/coas.o ./obj/Radius.o ./obj/md5.o ./obj/Log.o ./obj/PSPacket.o ./obj/Config.o
	g++ ./obj/deamon.o ./obj/coas.o ./obj/Radius.o ./obj/md5.o ./obj/Log.o ./obj/PSPacket.o ./obj/Config.o -o ../coas $(OCI_L) $(LIB)
./obj/deamon.o: ./Deamon/main.cpp ./Deamon/main.h
	g++ -c ./Deamon/main.cpp -o ./obj/deamon.o
./obj/coas.o: ./coas/coas.cpp ./coas/coas.h
	g++ -c ./coas/coas.cpp $(OCI_H) -o ./obj/coas.o
./obj/Radius.o: ./RadiusClient/Radius.cpp ./RadiusClient/Radius.h
	g++ -c ./RadiusClient/Radius.cpp -o ./obj/Radius.o
./obj/md5.o: ./md5/md5.cpp ./md5/md5.h
	g++ -c ./md5/md5.cpp -o ./obj/md5.o
./obj/PSPacket.o: $(UTL_DIR)/pspacket/PSPacket.cpp $(UTL_DIR)/pspacket/PSPacket.h
	g++ -c $(UTL_DIR)/pspacket/PSPacket.cpp -o ./obj/PSPacket.o
./obj/Log.o: $(UTL_DIR)/log/Log.cpp $(UTL_DIR)/log/Log.h
	g++ -c $(UTL_DIR)/log/Log.cpp -o ./obj/Log.o
./obj/Config.o: $(UTL_DIR)/config/Config.cpp $(UTL_DIR)/config/Config.h
	g++ -c $(UTL_DIR)/config/Config.cpp -o ./obj/Config.o

install:
	cp -f ../coas /usr/local/bin/coas

clean:
	rm -f ./obj/*.o ../coas