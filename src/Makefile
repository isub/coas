#ORACLE_HOME=/u01/app/oracle/product/11.2.0/db_1
OCI_L	= -L$(ORACLE_HOME)/lib/
LIB		= -lpthread -lclntsh
OCI_H	= -I$(ORACLE_HOME)/rdbms/public
UTL_DIR	= ../../utils
UTL_H	= -I${UTL_DIR}/src
UTL_SRC = ${UTL_DIR}/src/utils

all: clean coas

coas: ./obj/deamon.o ./obj/coas.o ./obj/radius.o ./obj/md5.o ./obj/log.o ./obj/pspacket.o ./obj/config.o
	g++ ./obj/deamon.o ./obj/coas.o ./obj/radius.o ./obj/md5.o ./obj/log.o ./obj/pspacket.o ./obj/config.o -o ../coas $(OCI_L) $(LIB)
./obj/deamon.o: ./deamon/main.cpp ./deamon/main.h
	g++ -c --std=c++11 -Wall -Wextra ${UTL_H} ./deamon/main.cpp -o ./obj/deamon.o
./obj/coas.o: ./coas/coas.cpp ./coas/coas.h
	g++ -c --std=c++11 -Wall -Wextra ${UTL_H} ${OCI_H} ./coas/coas.cpp -o ./obj/coas.o
./obj/radius.o: ./radiusclient/radius.cpp ./radiusclient/radius.h
	g++ -c --std=c++11 -Wall -Wextra ${UTL_H} ./radiusclient/radius.cpp -o ./obj/radius.o
./obj/md5.o: ./md5/md5.cpp ./md5/md5.h
	g++ -c --std=c++11 -Wall -Wextra ./md5/md5.cpp -o ./obj/md5.o
./obj/pspacket.o: $(UTL_SRC)/pspacket/pspacket.cpp $(UTL_SRC)/pspacket/pspacket.h
	g++ -c --std=c++11 -Wall -Wextra ${UTL_H} $(UTL_SRC)/pspacket/pspacket.cpp -o ./obj/pspacket.o
./obj/log.o: $(UTL_SRC)/log/log.cpp $(UTL_SRC)/log/log.h
	g++ -c --std=c++11 -Wall -Wextra $(UTL_SRC)/log/log.cpp -o ./obj/log.o
./obj/config.o: $(UTL_SRC)/config/config.cpp $(UTL_SRC)/config/config.h
	g++ -c --std=c++11 -Wall -Wextra $(UTL_SRC)/config/config.cpp -o ./obj/config.o

install:
	cp -f ../coas /usr/local/bin/coas

clean:
	rm -f ./obj/*.o ../coas
