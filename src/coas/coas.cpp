#include <stdio.h>
#include <map>
#include <vector>
#include <string>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>

#include "../md5/md5.h"
#include "../radiusclient/radius.h"
#include "../../../utils/log/log.h"
#include "../../../utils/coacommon.h"
#include "../../../utils/pspacket/pspacket.h"
#include "../../../utils/config/config.h"
#define OTL_ORA10G
#include "../../../utils/otlv4.h"
#include "coas.h"

CLog g_coLog;

extern int g_iEvent;

std::map<std::string,SSrvParam*> g_mapServers;	/* NAS list */

int g_iListenerSock;	/* TCP-сокет CoA-сенсора */
CConfig g_coConf;	/* конфигурация модуля */
std::string g_strServiceLog;	/* имя лог-файла */
std::string g_strCoASensorIp;	/* ip-адрес coa-сенсора */
unsigned short g_usCoASensorPort;	/* порт CoA-сенсора */

static std::string g_strDBUser;	/* DB user name */
static std::string g_strDBPswd;	/* DB user password */
static std::string g_strDBHost;	/* DB host name */
static std::string g_strDBPort;	/* DB port number */
static std::string g_strDBSrvc;	/* DB service name */
static std::string g_strNASQuery;	/* NAS list query */
static char g_mcDBConnTempl[] = "%s/%s@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=%s)(PORT=%s))(CONNECT_DATA=(SERVICE_NAME=%s)))";

std::map<u_long,std::string> g_mapDefRealms;	/* default realm list */
std::map<std::string,std::string> g_mapServices;	/* service rename rules */
std::vector<std::string> g_vectSrvcPrfx;	/**/

int g_iTruncSrvcName = 1;	/* отсекать префикс и доп. сведения в имени сервиса */
int g_iRenameSrvc = 1;	/* периеменовывать сервис */

int g_iRadReqTimeout;	/* RADIUS request time out */

std::string g_strUser;	/* имя пользователя */
std::string g_strGroup;	/* имя группа */

SConnectInfo *g_pmsoConnInf;	/* указатель на массив tcp-подключений */
unsigned int g_uiThrdCnt;	/* количество программных потоков */
unsigned int g_uiQueueLen;	/* длина очереди TCP-подккючений */
unsigned int g_uiDebug; /* глубина отладки */

timeval g_sotvLastSuccess = {0};
timeval g_sotvLastError = {0};

/* семафор для ожидания свободных потоков */
static sem_t g_tSem;

int ApplyConf ();
void ChangeOSUserGroup ();
int CreateNASList ();
int RequestOperateAdminReq (std::multimap<unsigned short,SPSReqAttr*> &p_mmapAttrList, SPSRequest *p_psoResp, size_t p_stBufSize);
int RequestOperateMonitReq (SPSRequest *p_psoResp, size_t p_stBufSize);
int TimeValueToString (timeval &p_soTimeVal, char *p_pmBuf, size_t p_stBufSize);
int RequestOperateCommandReq (std::multimap<unsigned short,SPSReqAttr*> &p_mmapAttrList, SPSRequest *p_psoResp, size_t p_stBufSize, SConnectInfo *p_psoConnInfo);
int RequestOperateUnsupportedReq (__uint16_t p_ui16ReqType, SPSRequest *p_psoResp, size_t p_stBufSize);

int InitCoASensor () {
	int iRetVal = 0;

	do {
		if (0 != ApplyConf ()) {
			iRetVal = -1;
			break;
		}
		if (0 != g_coLog.Init (g_strServiceLog.c_str())) {
			iRetVal = -1;
			break;
		}
		ChangeOSUserGroup ();
		if (0 != InitSocket (&g_iListenerSock, g_strCoASensorIp.c_str(), g_usCoASensorPort, g_uiQueueLen)) {
			iRetVal = -1;
			break;
		}
		if (0 != CreateNASList ()) {
			iRetVal = -1;
			break;
		}
		if (0 != InitThreadPool (&g_pmsoConnInf, g_uiThrdCnt)) {
			iRetVal = -1;
			break;
		}
	} while (0);

	return iRetVal;
}

void DeInitCoASensor ()
{
	/* прекращаем чтение сокета */
	if (-1 != g_iListenerSock) {
		shutdown (
			g_iListenerSock,
			SHUT_RD);
	}

	/* завершаем работу потоков */
	DeInitThreadPool (g_pmsoConnInf, g_uiThrdCnt);

	/* закрываем сокет */
	if (-1 != g_iListenerSock) {
		shutdown (g_iListenerSock, SHUT_RDWR);
		if (0 != close (g_iListenerSock)) {
			g_coLog.WriteLog ("Can not close socket. Error: '%d'", errno);
		}
	}
}

int InitSocket (
	int *p_piLsnrSock,
	const char *p_pszIpAddr,
	unsigned short p_usPort,
	int p_iConnectQueueLen)
{
	int iRetVal = 0;
	char mcErr[2048];

	do {
		/*	Проверка параметров
		 */
		if (0 == p_piLsnrSock) {
			iRetVal = -1;
			g_coLog.WriteLog ("coas: InitSocket: p_piLsnrSock null pointer");
			break;
		}
		/*	Создаем сокет
		 */
		*p_piLsnrSock = socket(
			PF_INET,
			SOCK_STREAM,
			0);
		if (-1 == *p_piLsnrSock) {
			iRetVal = errno;
			if (strerror_r (iRetVal, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: InitSocket: socket error: '%d': '%s'", iRetVal, mcErr);
			break;
		}
		g_coLog.WriteLog ("coas: InitSocket: Socket created");

		/*	Задаем опции сокета
		 */
		u_long ulOn;
		ulOn = 1;
		iRetVal = setsockopt(
			*p_piLsnrSock,
			SOL_SOCKET,
			SO_REUSEADDR,
			(char*)&ulOn,
			sizeof(ulOn));
		if (-1 == iRetVal) {
			iRetVal = errno;
			if (strerror_r (iRetVal, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: InitSocket: 'setsockopt' error: '%d': '%s'", iRetVal, mcErr);
			break;
		}
		g_coLog.WriteLog ("coas: InitSocket: Socket option changed");

		/*	Изменяется режим ввода-вывода сокета
		 */
		iRetVal = ioctl(
			*p_piLsnrSock,
			FIONBIO,
			&ulOn);
		if (-1 == iRetVal) {
			iRetVal = errno;
			if (strerror_r (iRetVal, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: InitSocket: 'ioctl' error: '%d': '%s'", iRetVal, mcErr);
			break;
		}
		g_coLog.WriteLog ("coas: InitSocket: Socket ioctl completed");

		sockaddr_in soAddrIn;

		soAddrIn.sin_addr.s_addr = inet_addr (p_pszIpAddr);
		soAddrIn.sin_port = htons (p_usPort);
		soAddrIn.sin_family = AF_INET;

		iRetVal = bind(
			*p_piLsnrSock,
			(sockaddr*)&soAddrIn,
			sizeof(soAddrIn));
		if (-1 == iRetVal) {
			iRetVal = errno;
			if (strerror_r (iRetVal, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: InitSocket: Socket binding error: '%d': '%s'", iRetVal, mcErr);
			break;
		}
		g_coLog.WriteLog ("coas: InitSocket: Socket binded successfully");

		iRetVal = listen(
			*p_piLsnrSock,
			p_iConnectQueueLen);
		if (-1 == iRetVal) {
			char mcErr[256];
			iRetVal = errno;
			if (strerror_r (iRetVal, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: InitSocket: Listening socket error: '%d': '%s'", iRetVal, mcErr);
			break;
		}
		g_coLog.WriteLog ("coas: InitSocket: Listening socket started");
	} while (0);

	return iRetVal;
}

int InitThreadPool (SConnectInfo *p_ppmsoConnInf[], int p_iConnCnt)
{
	int iRetVal = 0;

	*p_ppmsoConnInf = reinterpret_cast<SConnectInfo*> (malloc (sizeof(SConnectInfo) * p_iConnCnt));

	if (0 == (*p_ppmsoConnInf)) {
		iRetVal = errno;
		return -1;
	}

	/* инициализация семафора ожидания потоков */
	if (0 != sem_init (&g_tSem, 0, (int) g_uiThrdCnt)) {
		iRetVal = errno;
		return -1;
	}

	for (int i=0; i < p_iConnCnt; ++i) {
		(*p_ppmsoConnInf)[i].m_bIsFree = true;
		(*p_ppmsoConnInf)[i].m_uiThrdNum = i;
		(*p_ppmsoConnInf)[i].m_iSock = -1;
		(*p_ppmsoConnInf)[i].m_hThrdId = (unsigned int)-1;
		(*p_ppmsoConnInf)[i].m_bCont = true;
		iRetVal = pthread_mutex_init (&((*p_ppmsoConnInf)[i].m_mMutex), NULL);
		if (iRetVal) {
			break;
		}
		/* блокируем мьютекс */
		iRetVal = pthread_mutex_lock (&((*p_ppmsoConnInf)[i].m_mMutex));
    if (iRetVal) {
      break;
    }
		/* создаем поток */
		iRetVal = pthread_create (&((*p_ppmsoConnInf)[i].m_hThrdId), NULL, RequestOperate, &((*p_ppmsoConnInf)[i]));
		if (iRetVal) {
			break;
		}
	}

	return iRetVal;
}

int DeInitThreadPool (SConnectInfo *p_pmsoConnInf, int p_iConnCnt)
{
	int iRetVal = 0;

	SConnectInfo *psoConnInfo;
	/* завершаем обработку запросов */
	for (int iInd = 0; iInd < p_iConnCnt; ++iInd) {
		psoConnInfo = &p_pmsoConnInf[iInd];
		psoConnInfo->m_bCont = false;
		psoConnInfo->m_bIsFree = false;
		/* освобождаем мьютекс чтобы поток мог корректно завершиться */
		pthread_mutex_unlock (&(psoConnInfo->m_mMutex));
		/* если сокет открыт закрываем его */
		if (-1 != psoConnInfo->m_iSock) {
			shutdown (psoConnInfo->m_iSock, SHUT_RDWR);
			close (psoConnInfo->m_iSock);
			psoConnInfo->m_iSock = -1;
		}
	}
	/* ожидаем завершения работы всех потоков */
	for (int iInd = 0; iInd < p_iConnCnt; ++iInd) {
		pthread_join (psoConnInfo->m_hThrdId, NULL);
		pthread_mutex_destroy (&(psoConnInfo->m_mMutex));
	}
	/* уничтожение семафора ожидания потоков */
	sem_destroy (&g_tSem);

	return iRetVal;
}

int RequestManager ()
{
	int iRetVal = 0;
	static unsigned int uiConnNum = 0;
	char mcIpAddr[32];

	do {
		/* проверяем значение дескриптора сокета входящих подключений */
		if (-1 == g_iListenerSock) {
			/* если дескриптор содержит недопустимое значение делать вообще нечего */
			g_coLog.WriteLog ("coas: RequestManager: unexpected internal error occurred: invalid listener socket");
			break;
		}

		int iFnRes;
		pollfd soPollFD;
		char mcErr[256];
		int iErrCode;

		soPollFD.fd = g_iListenerSock;
		soPollFD.events = POLLIN;

		iFnRes = poll (&soPollFD, 1, 1000);

		/* Если состояние сокетов не изменилось или произошла ошибка завершаем обработку */
		if (0 >= iFnRes) {
			/* если возникла ошибка, пишем в лог */
			if (iFnRes) {
				iErrCode = errno;
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
				if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#else
				if (mcErr != strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#endif
					*mcErr = 0;
				}
				g_coLog.WriteLog ("coas: RequestManager: 'poll' error: code: '%d'; description: '%s'", iErrCode, mcErr);
				iRetVal = -1;
			}
			break;
		}

		/* ожидаем освобождения потока */
		iFnRes = sem_wait (&g_tSem);
		if (iFnRes) {
			/* если возникла ошибка семафора */
			iErrCode = errno;
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#else
			if (mcErr != strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#endif
				*mcErr = 0;
			}
			g_coLog.WriteLog ("coas: RequestManager: 'sem_wait' error: code: '%d'; descritpion: '%s'", iErrCode, mcErr);
			iRetVal = -1;
			break;
		}
		/* Поиск свободного элемента массива для хранения информации о подключениях */
		unsigned int uiInd;
		for (uiInd = 0; uiInd < g_uiThrdCnt; ++uiInd) {
			if (g_pmsoConnInf[uiInd].m_bIsFree) {
				/* нашли свободный поток. сразу занимаем его */
				g_pmsoConnInf[uiInd].m_bIsFree = false;
				g_pmsoConnInf[uiInd].m_uiConnNum = uiConnNum ++;
				break;
			}
		}
		if (uiInd >= g_uiThrdCnt) {
			/* если свободный поток так и не нашли */
			g_coLog.WriteLog ("coas: RequestManager: unexpected internal error occurred: all threads are busy");
			iRetVal = -1;
			break;
		}
		/* Если свободный элемент найден */
		socklen_t stFromLen;
		stFromLen = sizeof(g_pmsoConnInf[uiInd].m_soFrom);
		memset (&(g_pmsoConnInf[uiInd].m_soFrom), 0, stFromLen);
		/* Принимаем входящее подключение */
		g_pmsoConnInf[uiInd].m_iSock = accept (g_iListenerSock, (sockaddr*)&(g_pmsoConnInf[uiInd].m_soFrom), &stFromLen);
		if (-1 == g_pmsoConnInf[uiInd].m_iSock) {
			/* если принять новое подключение не удалось */
			iErrCode = errno;
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#else
			if (mcErr != strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#endif
				*mcErr = 0;
			}
			g_coLog.WriteLog ("Conn: '%08u'; coas: RequestManager: 'accept' error: code: '%d'; description: '%s'", g_pmsoConnInf[uiInd].m_uiConnNum, iErrCode, mcErr);
			/* метим поток свободным */
			g_pmsoConnInf[uiInd].m_bIsFree = true;
			break;
		}
		/* если входящее подключение принято удачно */
		my_inet_ntoa_r (g_pmsoConnInf[uiInd].m_soFrom.sin_addr, mcIpAddr, sizeof (mcIpAddr));
		g_coLog.WriteLog(
			"Conn: '%08u'; Thrd: '%04u'; coas: RequestManager: Connection to '%s:%u' accepted",
			g_pmsoConnInf[uiInd].m_uiConnNum,
			uiInd,
			mcIpAddr,
			ntohs (g_pmsoConnInf[uiInd].m_soFrom.sin_port));
		/* снимаем блокировку с потока */
		iFnRes = pthread_mutex_unlock (&(g_pmsoConnInf[uiInd].m_mMutex));
		/* если мьютекс разблокировался удачно с этого момента должна начаться обработка запроса в назначенном потоке */
		if (iFnRes) {
			/* если возникла ошибка мьютекса */
			iErrCode = errno;
#if (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#else
			if (mcErr != strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
#endif
				*mcErr = 0;
			}
			my_inet_ntoa_r (g_pmsoConnInf[uiInd].m_soFrom.sin_addr, mcIpAddr, sizeof (mcIpAddr));
			g_coLog.WriteLog(
				"Conn: '%08u'; Thrd: '%04u'; coas: RequestManager: 'pthread_mutex_unlock' error: '%d'; description: '%s'. Connection to '%s:%u' will be closed",
				g_pmsoConnInf[uiInd].m_uiConnNum,
				uiInd,
				iErrCode,
				mcErr,
				mcIpAddr,
				ntohs (g_pmsoConnInf[uiInd].m_soFrom.sin_port));
			/* освобождаем поток */
			if (-1 != g_pmsoConnInf[uiInd].m_iSock) {
				shutdown (g_pmsoConnInf[uiInd].m_iSock, SHUT_RDWR);
				close (g_pmsoConnInf[uiInd].m_iSock);
				g_pmsoConnInf[uiInd].m_iSock = -1;
			}
			g_pmsoConnInf[uiInd].m_bIsFree = true;
			break;
		}
	} while (0);

	return iRetVal;
}

void* RequestOperate (void* p_pvParam)
{
	int iFnRes;
	SConnectInfo *psoConnInfo = reinterpret_cast<SConnectInfo*> (p_pvParam);
	pollfd soPollFD;
	char mcRem[0x2000];
	int iRemLen;
	unsigned int uiReqNum = (unsigned int) -1;
	int iErr;
	char mcErr[2048];
	char mcIpAddr[32];

	g_coLog.WriteLog ("Thrd: '%04u'; coas: RequestOperate: started", psoConnInfo->m_uiThrdNum);

	while (psoConnInfo->m_bCont) {
		/* пока продолжается работа потока */
		/* ожидаем освобождения мьютекса */
		iFnRes = pthread_mutex_lock (&(psoConnInfo->m_mMutex));
		if (! psoConnInfo->m_bCont) {
			/* если работа потока завершена выходим из цикла */
			break;
		}
		if (iFnRes) {
			/* если возникла ошибка с мьютексом */
			if (strerror_r (iErr, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog (
				"Conn: '%08u'; Thrd: '%04u'; coas: RequestOperate: 'pthread_mutex_lock' error: code: '%d'; description: '%s'",
				psoConnInfo->m_uiConnNum, psoConnInfo->m_uiThrdNum, iFnRes, mcErr);
			/* это фатальная ошибка, завершаем работу потока */
			break;
		}

		/* обрабатываем до тех пор, пока сокет находится в рабочем состоянии */
		do {
			/* готовимся к чтению из сокета */
			soPollFD.fd = psoConnInfo->m_iSock;
			soPollFD.events = POLLIN;
			/* ждем немного */
			iFnRes = poll (&soPollFD, 1, 500);
			/* если истекло время ожидания */
			if (0 == iFnRes) {
				continue;
			}

			/* получаем ip-адрес клиента */
			my_inet_ntoa_r (psoConnInfo->m_soFrom.sin_addr, mcIpAddr, sizeof (mcIpAddr));

			/* если возникла ошибка при ожидании изменений в сокете */
			if (0 > iFnRes) {
				g_coLog.WriteLog (
					"Conn: '%08u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': poll returned result mask: '%08x': error: code: '%d'",
					psoConnInfo->m_uiConnNum,
					psoConnInfo->m_uiThrdNum,
					mcIpAddr,
					(unsigned int) ntohs (psoConnInfo->m_soFrom.sin_port),
					soPollFD.revents,
					errno);
				break;
			}
			/*	Получаем данные от клиента coa-сенсора */
			iFnRes = recv (psoConnInfo->m_iSock, psoConnInfo->m_mcPSReq, sizeof(psoConnInfo->m_mcPSReq), 0);
			/*  Если данные не получены, завершаем обработку */
			if (0 > iFnRes) {
				iErr = errno;
				if (strerror_r (iErr, mcErr, sizeof(mcErr) - 1)) {
					*mcErr = 0;
				}
				g_coLog.WriteLog (
					"Conn: '%08u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': 'recv' error: '%d'; description: '%s'",
					psoConnInfo->m_uiConnNum,
					psoConnInfo->m_uiThrdNum,
					mcIpAddr,
					(unsigned int)ntohs(psoConnInfo->m_soFrom.sin_port),
					iErr,
					mcErr);
				break;
			}
			/* если соединение закрыто */
			if (0 == iFnRes) {
				g_coLog.WriteLog (
					"Conn: '%08u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': 'recv' error: connection is closed",
					psoConnInfo->m_uiConnNum,
					psoConnInfo->m_uiThrdNum,
					mcIpAddr,
					(unsigned int)ntohs(psoConnInfo->m_soFrom.sin_port));
				break;
			}
			/* сохраняем размер полученных данных */
			psoConnInfo->m_iReqLen = iFnRes;

			/* инкрементируем счетчик запросов */
			++uiReqNum;

			CPSPacket coPSPack;
			std::multimap<unsigned short,SPSReqAttr*> mmapPSReqAttrList;
			SPSRequest *psoPSReq = (SPSRequest*)psoConnInfo->m_mcPSReq;
			SPSRequest *psoPSResp = (SPSRequest*)(psoConnInfo->m_mcPSResp);
			char mcParsedPSPack[0x1000];

			/* разбор пакета с валидацией */
			if (coPSPack.Parse (psoPSReq, psoConnInfo->m_iReqLen, mmapPSReqAttrList, 1)) {
				/* вывод сообщения о неудачной проверке пакета */
				iRemLen = snprintf (
					mcRem, sizeof (mcRem) - 1,
					"Conn/Req: '%08u/%u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': PSPacket validation failed:\n\t",
					psoConnInfo->m_uiConnNum,
					uiReqNum,
					psoConnInfo->m_uiThrdNum,
					mcIpAddr,
					(unsigned int)ntohs(psoConnInfo->m_soFrom.sin_port));
				if (0 < iRemLen) {
					if (iRemLen > sizeof (mcRem) - 1) {
						iRemLen = sizeof (mcRem) - 1;
					}
				} else {
					iRemLen = 0;
				}
				/* дамп полученного пакета */
				for (int i = 0; i < psoConnInfo->m_iReqLen; ++i) {
					iFnRes = snprintf (&(mcRem[iRemLen]), sizeof (mcRem) - 1 - iRemLen, "%02x", (unsigned int)psoConnInfo->m_mcPSReq[i]);
					if (0 < iFnRes) {
						if (iFnRes > sizeof (mcRem) - 1 - iRemLen) {
							iFnRes = sizeof (mcRem) - 1 - iRemLen;
							iRemLen += iFnRes;
							break;
						}
						iRemLen += iFnRes;
					} else {
						break;
					}
				}
				mcRem[iRemLen] = '\0';
				g_coLog.Dump (mcRem);
				break;
			}

			/* вывод заголовка сообщения о полученном пакете */
			iRemLen = snprintf (
				mcRem,
				sizeof (mcRem) - 1,
				"Conn/Req: '%08u/%u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': Received '%d' bytes:\n\t",
				psoConnInfo->m_uiConnNum,
				uiReqNum,
				psoConnInfo->m_uiThrdNum,
				mcIpAddr,
				(unsigned int)htons(psoConnInfo->m_soFrom.sin_port),
				iFnRes);
			if (0 < iRemLen) {
				if (iRemLen > sizeof (mcRem) - 1) {
					iRemLen = sizeof (mcRem) - 1;
				}
			} else {
				iRemLen = 0;
			}

			/* получаем текстовое представление запроса */
			iFnRes = coPSPack.Parse (psoPSReq, psoConnInfo->m_iReqLen, mcParsedPSPack, sizeof(mcParsedPSPack));
			if (0 < iFnRes) {
				int iStrLen = sizeof (mcRem) - iRemLen - 1 > iFnRes ? iFnRes : sizeof(mcRem) - iRemLen - 1;
				memcpy (&(mcRem[iRemLen]), mcParsedPSPack, iStrLen);
				iRemLen += iStrLen;
				mcRem[iRemLen] = '\0';
			}

			g_coLog.Dump (mcRem);

			*mcRem = '\0';
			/* инициализируем буфер ответа */
			coPSPack.Init (psoPSResp, sizeof(psoConnInfo->m_mcPSResp), ntohl ((psoPSReq)->m_uiReqNum));

			switch (ntohs (psoPSReq->m_usReqType)) {
			case ADMIN_REQ:
				iFnRes = RequestOperateAdminReq (mmapPSReqAttrList, psoPSResp, sizeof(psoConnInfo->m_mcPSResp));
				break;	/* ADMIN_REQ*/
			case MONIT_REQ:
				iFnRes = RequestOperateMonitReq (psoPSResp, sizeof(psoConnInfo->m_mcPSResp));
				break;	/* case: MONIT_REQ*/
			case COMMAND_REQ:
				iFnRes = RequestOperateCommandReq (mmapPSReqAttrList, psoPSResp, sizeof(psoConnInfo->m_mcPSResp), psoConnInfo);
				break;	/* case: COMMAND_REQ*/
			default:
				iFnRes = RequestOperateUnsupportedReq (psoPSReq->m_usReqType, psoPSResp, sizeof(psoConnInfo->m_mcPSResp));
				break;
			}

			coPSPack.EraseAttrList (mmapPSReqAttrList);

			__uint16_t ui16PackLen;

			/* валидация ответа */
			if (0 != coPSPack.Validate (psoPSResp, sizeof (psoConnInfo->m_mcPSResp))) {
				/* если валидация прошла неудачно */
				g_coLog.WriteLog (
					"Conn/Req: '%08u/%u'; Thrd: '%04u'; coas: RequestOperate: unexpected internal error: response packet validation failed",
					psoConnInfo->m_uiConnNum,
					uiReqNum,
					psoConnInfo->m_uiThrdNum);
				break;
			} else {
				/* валидация прошла успешно, получаем длину пакета */
				ui16PackLen = htons (psoPSResp->m_usPackLen);
			}
			/* отправляем ответ клиенту */
			iFnRes = send (psoConnInfo->m_iSock, (char*)psoPSResp, ui16PackLen, 0);
			if (0 > iFnRes) {
				/* если произошла ошибка при передаче ответа */
				iErr = errno;
				if (strerror_r (iErr, mcErr, sizeof (mcErr))) {
					*mcErr = 0;
				}
				g_coLog.WriteLog (
					"Conn: '%08u/%u'; Thrd: '%04u'; coas: RequestOperate: Connection to '%s:%u': 'send' error: code: '%d'; description: '%s'",
					psoConnInfo->m_uiConnNum,
					uiReqNum,
					psoConnInfo->m_uiThrdNum,
					mcIpAddr,
					(unsigned int)ntohs(psoConnInfo->m_soFrom.sin_port),
					iErr,
					mcErr);
				break;
			}
			iRemLen = snprintf(
				mcRem,
				sizeof(mcRem) - 1,
				"Conn/Req: '%08u/%u'; Thrd: '%04u'; coas: RequestOperate: response sent to '%s:%u' %d bytes:\n\t",
				psoConnInfo->m_uiConnNum,
				uiReqNum,
				psoConnInfo->m_uiThrdNum,
				mcIpAddr,
				(unsigned int)ntohs (psoConnInfo->m_soFrom.sin_port),
				iFnRes);
			/* если буфер успешно заполнен */
			if (0 < iRemLen) {
				/* если не вся строка уместилась в буфер */
				if (iRemLen > sizeof(mcRem) - 1) {
					iRemLen = sizeof(mcRem) - 1;
					mcRem[iRemLen] = '\0';
				}
			} else {
				iRemLen = 0;
			}
			iFnRes = coPSPack.Parse (psoPSResp, iFnRes, mcParsedPSPack, sizeof(mcParsedPSPack));
			if (0 < iFnRes) {
				size_t stStrLen = sizeof(mcRem) - iRemLen -1 > iFnRes ? iFnRes : sizeof(mcRem) - iRemLen -1;
				memcpy (&mcRem[iRemLen], mcParsedPSPack, stStrLen);
				iRemLen += stStrLen;
				mcRem[iRemLen] = '\0';
				g_coLog.Dump (mcRem);
			}
		} while (psoConnInfo->m_bCont);

		if (psoConnInfo->m_bCont) {
			/* если работа потока еще не завершена */
			/* если сокет открыт закрываем его */
			if (-1 != psoConnInfo->m_iSock) {
				shutdown (psoConnInfo->m_iSock, SHUT_RDWR);
				close (psoConnInfo->m_iSock);
				psoConnInfo->m_iSock = -1;
			}
			/* метим поток свободным */
			psoConnInfo->m_bIsFree = true;
			/* освобождаем семафор ожидания потока */
			iFnRes = sem_post (&g_tSem);
			if (iFnRes) {
				/* если возникли проблемы с семафором */
				g_coLog.WriteLog ("Conn: '%08u'; Thrd: '%04u'; coas: RequestOperate: 'sem_post' unexpected internal error: '%d'", psoConnInfo->m_uiConnNum, psoConnInfo->m_uiThrdNum, errno);
				/* это фатальная ошибка, завершаем работу потока */
				break;
			}
		}
	}

	if (psoConnInfo->m_bCont) {
		/* если это незапланированный (скорее всего аварийный) выход из потока освобождаем занятые ресурсы */
		/* закрываем сокет если он открыт */
		if (-1 != psoConnInfo->m_iSock) {
			shutdown (psoConnInfo->m_iSock, SHUT_RDWR);
			close (psoConnInfo->m_iSock);
			psoConnInfo->m_iSock = -1;
		}
		/* метим поток занятым */
		psoConnInfo->m_bIsFree = false;
	}

	g_coLog.WriteLog ("Thrd: '%04u'; coas: RequestOperate: thread stopped", psoConnInfo->m_uiThrdNum);

	pthread_exit (NULL);
}

int SendRequest (std::multimap<unsigned short,SPSReqAttr*> &p_mmapPSAttrList, SConnectInfo *p_psoConnInfo, char *p_pmcRem)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'SendRequest'");
	}
	int iRetVal = 0;
	SCommandParam soCmdParam;
	SPSRequest *psoPSReq;
	SPSReqAttr *psoPSReqAttr;
	unsigned short usPackLen;
	unsigned short usAttrLen;
	unsigned int uiBufSize;
	int iMsgLen;
	std::multimap<unsigned short,SPSReqAttr*>::iterator iterAttrList = p_mmapPSAttrList.end ();

	do {
		/*	Инициализация структуры */
		memset (&soCmdParam, 0, sizeof(soCmdParam));
		soCmdParam.m_uiRequestId = 0x100;

		/* получаем указатель на экземпляр радиус-клиента */
		soCmdParam.m_psoCoASrvrParam = GetCoASrvrInfo (p_mmapPSAttrList);
		p_psoConnInfo->m_psoCoASrvrParam = soCmdParam.m_psoCoASrvrParam;
		if (NULL == soCmdParam.m_psoCoASrvrParam) {
			strcpy (p_pmcRem, "CoA server not found");
			g_coLog.WriteLog ("coas: SendRequest: CoA server not found");
			iRetVal = -1;
			break;
		}

		soCmdParam.m_uiRequestId = soCmdParam.m_psoCoASrvrParam->m_pcoRadiusClient->GetNewId (43);
		if (0x100 <= soCmdParam.m_uiRequestId) {
			/*	Неверный идентификатор пакета */
			strcpy (p_pmcRem, "Can not get new packet id");
			g_coLog.WriteLog ("coas: SendRequest: Error: Can not get new packet id");
			iRetVal = -256;
			break;
		}

		/* формирование радиус пакета */
		for (iterAttrList = p_mmapPSAttrList.begin(); iterAttrList != p_mmapPSAttrList.end(); ++iterAttrList) {
			psoPSReqAttr = iterAttrList->second;
			usAttrLen = ntohs (psoPSReqAttr->m_usAttrLen);
			iRetVal = UpdateRadiusPacket (
				&soCmdParam,
				ntohs(psoPSReqAttr->m_usAttrType),
				(unsigned char*)psoPSReqAttr + sizeof(SPSReqAttr),
				usAttrLen - sizeof(SPSReqAttr),
				p_psoConnInfo->m_soFrom.sin_addr.s_addr);
			if (iRetVal) {
				sprintf (p_pmcRem, "error occurred while attribute '%04x' processing", (unsigned int)ntohs(psoPSReqAttr->m_usAttrType));
				g_coLog.WriteLog ("coas: SendRequest: %s", p_pmcRem);
				iRetVal = -1;
				break;
			}
		}

		if (0 != iRetVal) {
			break;
		}

		uiBufSize = sizeof(p_psoConnInfo->m_mucRadBuf);
		iRetVal = soCmdParam.m_psoCoASrvrParam->m_pcoRadiusClient->SendPack(
			soCmdParam.m_uiRequestId,
			soCmdParam.m_psoCoASrvrParam->m_mcCoASrvr,
			soCmdParam.m_psoCoASrvrParam->m_usPort,
			p_psoConnInfo->m_mucRadBuf,
			&uiBufSize,
			p_pmcRem);
	} while (0);

	/*	Освобождаем ресурсы, занятые запросом клиента Radius */
	if (soCmdParam.m_psoCoASrvrParam) {
		if (soCmdParam.m_psoCoASrvrParam->m_pcoRadiusClient) {
			if (0x100 > soCmdParam.m_uiRequestId) {
				soCmdParam.m_psoCoASrvrParam->m_pcoRadiusClient->ReleaseId (soCmdParam.m_uiRequestId);
			}
		}
	}

	return iRetVal;
}

SSrvParam * GetCoASrvrInfo (std::multimap<unsigned short,SPSReqAttr*> &p_ummapPSAttr)
{
	std::multimap<unsigned short,SPSReqAttr*>::iterator iterPSAttrList;
	SPSReqAttr *psoAttr;
	unsigned short usAttrLen;
	char mcCoASrvrIP[32];
	std::map<std::string,SSrvParam*>::iterator iterSrvParam;

	iterPSAttrList = p_ummapPSAttr.find (PS_NASIP);
	if (iterPSAttrList == p_ummapPSAttr.end()) {
		return NULL;
	}
	psoAttr = iterPSAttrList->second;
	usAttrLen = ntohs (psoAttr->m_usAttrLen) - sizeof (SPSReqAttr);
	if (sizeof(mcCoASrvrIP) <= usAttrLen) {
		return NULL;
	} else {
		memcpy (mcCoASrvrIP, (char*)psoAttr + sizeof(SPSReqAttr), usAttrLen);
		mcCoASrvrIP[usAttrLen] = '\0';
		iterSrvParam = g_mapServers.find (mcCoASrvrIP);
		if (iterSrvParam != g_mapServers.end()) {
			return iterSrvParam->second;
		} else {
			return NULL;
		}
	}

	return NULL;
}

int UpdateRadiusPacket (
	SCommandParam *p_psoCmdParam,
	const unsigned short p_usAttrType,
	const unsigned char *p_pmucAttrValue,
	const unsigned short p_usAttrLen,
	u_long p_ulFrom)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'UpdateRadiusPacket'");
	}
	int iRetVal = 0;
	char mcValue[256];

	if (sizeof (mcValue) <= p_usAttrLen) {
		return -1;
	} else {
		strncpy(
			mcValue,
			(char*) p_pmucAttrValue,
			p_usAttrLen);
		mcValue[p_usAttrLen] = '\0';
	}

	switch (p_usAttrType) {
	case PS_NASIP:
		/* обрабатывается в функции SendRequest*/
		break;
	case PS_NASPORT:
		p_psoCmdParam->m_psoCoASrvrParam->m_usPort = (unsigned short)atoi (mcValue);
		break;
	case PS_USERNAME:
		iRetVal = MakeUserNameAttr (mcValue, p_psoCmdParam, p_ulFrom);
		break;
	case PS_USERPSWD:
		iRetVal = MakeUserPswdAttr (mcValue, p_psoCmdParam, p_psoCmdParam->m_psoCoASrvrParam->m_mcSecret);
		break;
	case PS_SESSID:
		iRetVal = MakeSessionIdAttr (mcValue, p_psoCmdParam);
		break;
	case PS_ACCINFO:
		iRetVal = MakeAccountInfoAttr (mcValue, p_psoCmdParam);
		break;
	case PS_COMMAND:
		iRetVal = MakeCommandAttr (mcValue, p_psoCmdParam);
		break;
	default:
		iRetVal = -1;
	}

	return iRetVal;
}

int MakeUserNameAttr (const char *p_pszUserName, SCommandParam *p_psoCmdParam, u_long p_ulFrom)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeUserNameAttr'");
	}
	int iRetVal = 0;
	char mcBuf[0x100];
	const char *pcszTmp;
	SRadiusAttribute *psoAttr;
	int iStrLen;

	psoAttr = (SRadiusAttribute*) mcBuf;

	pcszTmp = strstr (p_pszUserName, "@");
	/* если реалма нет в имени пользователя */
	if (NULL == pcszTmp) {
		std::map<u_long,std::string>::iterator iterDefRealm;
		iterDefRealm = g_mapDefRealms.find (p_ulFrom);
		/* если реалм по умолчанию задан */
		if (iterDefRealm != g_mapDefRealms.end()) {
			iStrLen = snprintf ((char *) psoAttr->m_mucValue, sizeof (mcBuf) - sizeof (*psoAttr), "%s@%s", p_pszUserName, iterDefRealm->second.c_str());
		} else {
			iStrLen = snprintf ((char *) psoAttr->m_mucValue, sizeof (mcBuf) - sizeof (*psoAttr), "%s", p_pszUserName);
		}
	} else {
		iStrLen = snprintf ((char *) psoAttr->m_mucValue, sizeof (mcBuf) - sizeof (*psoAttr), "%s", p_pszUserName);
	}

	if (0 >= iStrLen || iStrLen > sizeof (mcBuf) - sizeof (*psoAttr)) {
		return -1;
	}

	psoAttr->m_ucType = 1;		/* User-Name*/
	psoAttr->m_ucLength = sizeof(*psoAttr) - sizeof(psoAttr->m_mucValue) + iStrLen;

	iRetVal = p_psoCmdParam->m_psoCoASrvrParam->m_pcoRadiusClient->AddAttr (p_psoCmdParam->m_uiRequestId, psoAttr);

	return iRetVal;
}

int MakeUserPswdAttr (const char *p_pszUserPswd, SCommandParam *p_psoCmdParam, char *p_szSecretKey)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeUserPswdAttr'");
	}
	int iRetVal = 0;
	char mcBuf[0x100];
	SRadiusAttribute *psoAttr;
	unsigned char *pmucSequence;	/* Хэшируемая последовательность */
	unsigned char mucDigest[16];	/* Хэш последовательности*/
	unsigned char *pmucPswd;		/* Шифруемый пароль*/
	unsigned int uiPartCnt;			/* Количество 16-октетных частей пароля*/
	size_t stPswdLen;				/* Длина пароля*/
	size_t stSecretLen;				/* Длина секретного ключа*/
	size_t stSeqLen;				/* Длина хэшируемой последовательности*/
	unsigned char mucResult[144];	/* Зашифрованный пароль*/
	unsigned int uiResLen;			/* Длина зашифрованного пароля*/

	pmucSequence = NULL;
	pmucPswd = NULL;
	uiResLen = 0;

	psoAttr = (SRadiusAttribute*) mcBuf;

	stPswdLen = strlen (p_pszUserPswd);

	uiPartCnt = stPswdLen / 16;
	uiPartCnt += (stPswdLen % 16) == 0 ? 0 : 1;

  /* выделяем блок памяти, инициализованный нулями */
	pmucPswd = (unsigned char*) calloc (uiPartCnt, 16);
	/*	Копируем пароль пользователя */
	memcpy (pmucPswd, p_pszUserPswd, stPswdLen);

	stSecretLen = strlen (p_szSecretKey);
	stSeqLen = stSecretLen + 16;

	/* выделяем блок памяти для хэшируемой последовательности заполненную нулями */
	pmucSequence = (unsigned char*) сalloc (stSeqLen, 1);
	/*	Копируем секретный ключ в хэшируемую последовательность */
	memcpy (pmucSequence, p_szSecretKey, stSecretLen);

	md5::md5_context soMD5Ctx;
	unsigned int uiIterCnt;

	uiIterCnt = 0;

	do {
		if (uiIterCnt) {
			/*	Копируем C[i-1] в хэшируемую последовательность */
			memcpy (&(pmucSequence[stSecretLen]), &(mucResult[uiIterCnt*16]), 16);
		}

		md5::md5_starts (&soMD5Ctx);
		md5::md5_update (&soMD5Ctx, pmucSequence, stSeqLen);
		md5::md5_finish (&soMD5Ctx, mucDigest);

		for (int i=0; i<16; ++i) {
			mucResult[uiResLen] = mucDigest[i] ^ pmucPswd[uiIterCnt * 16 + i];
			++uiResLen;
		}

		++uiIterCnt;

	} while (uiIterCnt < uiPartCnt);

	psoAttr->m_ucType = 2;		/* User-Password*/
	psoAttr->m_ucLength = sizeof(*psoAttr) - sizeof(psoAttr->m_mucValue) + uiResLen;
	memcpy (psoAttr->m_mucValue, mucResult, uiResLen);

	iRetVal = p_psoCmdParam->m_psoCoASrvrParam->m_pcoRadiusClient->AddAttr (p_psoCmdParam->m_uiRequestId, psoAttr);

	if (pmucPswd) {
		free (pmucPswd);
	}

	if (pmucSequence) {
		free (pmucSequence);
	}

	return iRetVal;
}

int MakeSessionIdAttr (const char *p_pszSessioId, SCommandParam *p_psoCmdParam)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeSessionIdAttr'");
	}
	int iRetVal = 0;
	char mcBuf[0x100];
	SRadiusAttribute *psoAttr;
	size_t stSessionLen;

	psoAttr = (SRadiusAttribute*) mcBuf;

	stSessionLen = strlen (p_pszSessioId);

	psoAttr->m_ucType = 44;		/* Acct-Session-Id*/
	psoAttr->m_ucLength = sizeof(*psoAttr) - sizeof(psoAttr->m_mucValue) + stSessionLen;
	memcpy (psoAttr->m_mucValue, p_pszSessioId, stSessionLen);

	iRetVal = p_psoCmdParam->m_psoCoASrvrParam->m_pcoRadiusClient->AddAttr (p_psoCmdParam->m_uiRequestId, psoAttr);

	return iRetVal;
}

int MakeAccountInfoAttr (const char *p_pszAccountInfo, SCommandParam *p_psoCmdParam)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeAccountInfoAttr'");
	}
	int iRetVal = 0;
	char mcBuf[0x100];
	SVSAAttr *psoVSAAttr;

	psoVSAAttr = reinterpret_cast<SVSAAttr*> (mcBuf);

	MakeVSAAttr (psoVSAAttr, (unsigned int) 9, (unsigned char) 250, p_pszAccountInfo, strlen (p_pszAccountInfo));

	iRetVal = p_psoCmdParam->m_psoCoASrvrParam->m_pcoRadiusClient->AddAttr (p_psoCmdParam->m_uiRequestId, (SRadiusAttribute*)psoVSAAttr);

	return iRetVal;
}

int MakeCommandAttr (const char *p_pszCommand, SCommandParam *p_psoCmdParam)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeCommandAttr'");
	}
	int iRetVal = 0;
	char mcBuf[0x100];
	SVSAAttr *psoVSAAttr;
	char* pszSubValue;
	char mcValue[0x100];
	int iFnRes = 0;
	unsigned int uiVendorId = 0;
	unsigned char ucVendorType = 0;

	/* ищем разделитель (допольнительное значение команды) */
	pszSubValue = (char *) strstr (p_pszCommand, "=");

	if (pszSubValue) {
		*pszSubValue = '\0';
		++pszSubValue;
	}

	psoVSAAttr = reinterpret_cast<SVSAAttr*> (mcBuf);

	if (0 == strcmp (CMD_ACCNT_LOGON, p_pszCommand)) { /* Account-Logon */
		if (pszSubValue) {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x01%s", pszSubValue);
		} else {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x01");
		}
		if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
			iFnRes = 0;
		}
		uiVendorId = (unsigned int) 9;
		ucVendorType = (unsigned char) 252;
	} else if (0 == strcmp (CMD_ACCNT_LOGOFF, p_pszCommand)) { /* Account-Logoff */
		if (pszSubValue) {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x02%s", pszSubValue);
		} else {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x02");
		}
		if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
			iFnRes = 0;
		}
		uiVendorId = (unsigned int) 9;
		ucVendorType = (unsigned char) 252;
	} else if (0 == strcmp (CMD_SESSION_QUERY, p_pszCommand)) { /* Session-Query */
		iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x04\x20");
		if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
			iFnRes = 0;
		}
		uiVendorId = (unsigned int) 9;
		ucVendorType = (unsigned char) 252;
	} else if (0 == strcmp (CMD_SRV_ACTIVATE, p_pszCommand)) { /* Service-Activate */
		if (pszSubValue) {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x0b%s", pszSubValue);
			if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
				iFnRes = 0;
			}
			uiVendorId = (unsigned int) 9;
			ucVendorType = (unsigned char) 252;
		} else {
			iRetVal = -1;
		}
	} else if (0 == strcmp (CMD_SRV_DEACTIVATE, p_pszCommand)) { /* Service-Deactivate */
		if (pszSubValue) {
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "\x0c%s", pszSubValue);
			if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
				iFnRes = 0;
			}
			uiVendorId = (unsigned int) 9;
			ucVendorType = (unsigned char) 252;
		} else {
			iRetVal = -1;
		}
	} else if (0 == strcmp (CMD_ERX_ACTIVATE, p_pszCommand)) { /* ERX-Service-Activate */
		do {
			/* если значение не указано нет смысла в дальнейшей обработке*/
			if (NULL == pszSubValue) { iRetVal = -1; break; }
			char *pszTag;
			unsigned char ucTag;
			int iStrLen;
			/* ищем тэг*/
			pszTag = strstr (pszSubValue, ":");
			if (NULL == pszTag) { iRetVal = -1; break; }
			++pszTag;
			/* ищем имя сервиса*/
			pszSubValue = strstr (pszTag, "=");
			if (NULL == pszSubValue) { iRetVal = -1; break; }
			*pszSubValue = '\0';
			++pszSubValue;
			/* получаем значение тэга*/
			ucTag = (unsigned char) atol (pszTag);
			mcValue[0] = ucTag;
			iStrLen = 1;
			iFnRes = snprintf (&mcValue[1], sizeof (mcValue) - 2, "%s", pszSubValue);
			if (0 < iFnRes || iFnRes > sizeof (mcValue) - 2) {
				iFnRes = 0;
			}
			uiVendorId = (unsigned int) 4874;
			ucVendorType = (unsigned char) 65;
		} while (0);
	} else if (0 == strcmp (CMD_ERX_DEACTIVATE, p_pszCommand)) { /* ERX-Service-Deactivate */
		do {
			if (NULL == pszSubValue) { iRetVal = -1; break; }
			iFnRes = snprintf (mcValue, sizeof (mcValue) - 1, "%s", pszSubValue);
			if (0 > iFnRes || iFnRes > sizeof (mcValue) - 1) {
				iFnRes = 0;
			}
			uiVendorId = (unsigned int) 4874;
			ucVendorType = (unsigned char) 66;
		} while (0);
	} else { /* ничего не подходит */
		iRetVal = -10;
	}

	if (0 == iRetVal) {
		MakeVSAAttr (psoVSAAttr, uiVendorId, ucVendorType, mcValue, iFnRes);
		iRetVal = p_psoCmdParam->m_psoCoASrvrParam->m_pcoRadiusClient->AddAttr (p_psoCmdParam->m_uiRequestId, (SRadiusAttribute*)psoVSAAttr);
	}

	return iRetVal;
}

void MakeVSAAttr (SVSAAttr *p_psoVSAAttr, unsigned int p_uiVendorId, unsigned char p_ucVendorType, const char *p_pmucAttrValue, unsigned int p_uiAttrLen)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'MakeVSAAttr'");
	}
	p_psoVSAAttr->m_ucType = 26;
	p_psoVSAAttr->m_uiVendorId = htonl (p_uiVendorId);
	p_psoVSAAttr->m_ucVendorType = p_ucVendorType;
	p_psoVSAAttr->m_ucLength = sizeof(*p_psoVSAAttr) - sizeof(p_psoVSAAttr->m_mcValue) + p_uiAttrLen;
	p_psoVSAAttr->m_ucVendorLen = p_uiAttrLen + sizeof(p_psoVSAAttr->m_ucVendorType) + sizeof(p_psoVSAAttr->m_ucVendorLen);
	memcpy (p_psoVSAAttr->m_mcValue, p_pmucAttrValue, p_uiAttrLen);
}

int AnalyseResponse (unsigned char *p_pmucResp, char *p_pmcRem)
{
	int iRetVal = 0;

	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'AnalyseResponse'");
	}

	do {
		SRadiusHeader *psoRadHdr;
		SRadiusAttribute *psoRadAttr;
		SVSAAttr *psoRadVSAAttr;
		unsigned short usPackSize;

		/* Проверяем код ответа*/
		psoRadHdr = reinterpret_cast<SRadiusHeader*> (p_pmucResp);
		switch (psoRadHdr->m_ucCode) {
			default:
			case 40:
			case 43:
				sprintf (p_pmcRem, "coas: AnalyseResponse: invalid packet code: '%u'", psoRadHdr->m_ucCode);
				iRetVal = -1;
				break;
			case 41:
			case 44:
				iRetVal = 0;
				break;
			case 42:
			case 45:
				sprintf (p_pmcRem, "coas: AnalyseResponse: [%u] CoA-NAK received", (unsigned int) psoRadHdr->m_ucCode);
				iRetVal = -45;
				break;
		}

	} while (0);

	return iRetVal;
}

int ApplyConf () {
	int iRetVal = 0;
	std::string strVal;
	std::vector<std::string> vectValueList;

	do {
		/*	Разбираем параметры */
		/* log file name */
		if (g_coConf.GetParamValue ("logfile", g_strServiceLog)) {
			printf ("ApplyConf: 'logfile' not defined");
			iRetVal = -1;
			break;
		}
		/* coa-sensor ip-address */
		if (g_coConf.GetParamValue ("coa_sensor_ip", g_strCoASensorIp)) {
			printf ("ApplyConf: 'coa_sensor_ip' not defined");
			iRetVal = -1;
			break;
		}
		/* coa-sensor port */
		if (g_coConf.GetParamValue ("coa_sensor_port", strVal)) {
			printf ("ApplyConf: 'coa_sensor_ip' not defined");
			iRetVal = -1;
			break;
		} else {
				g_usCoASensorPort = strtol (strVal.c_str(), 0, 10);
		}
		/* RADIUS request time out */
		if (g_coConf.GetParamValue ("radreqtimeout", strVal)) {
			g_iRadReqTimeout = 5;
		} else {
				g_iRadReqTimeout = strtol (strVal.c_str(), 0, 10);
		}
		/* DB user name */
		if (g_coConf.GetParamValue ("db_user", g_strDBUser)) {
			printf ("ApplyConf: 'db_user' not defined");
			iRetVal = -1;
			break;
		}
		/* DB user password */
		if (g_coConf.GetParamValue ("db_pswd", g_strDBPswd)) {
			printf ("ApplyConf: 'db_pswd' not defined");
			iRetVal = -1;
			break;
		}
		/* DB host name */
		if (g_coConf.GetParamValue ("db_host", g_strDBHost)) {
			printf ("ApplyConf: 'db_host' not defined");
			iRetVal = -1;
			break;
		}
		/* DB port */
		if (g_coConf.GetParamValue ("db_port", g_strDBPort)) {
			printf ("ApplyConf: 'db_port' not defined");
			iRetVal = -1;
			break;
		}
		/* DB service */
		if (g_coConf.GetParamValue ("db_srvc", g_strDBSrvc)) {
			printf ("ApplyConf: 'db_srvc' not defined");
			iRetVal = -1;
			break;
		}
		/* NAS list query */
		if (g_coConf.GetParamValue ("qr_nas_list", g_strNASQuery)) {
			printf ("ApplyConf: 'qr_nas_list' not defined");
			iRetVal = -1;
			break;
		}
		/* default realm list */
		if (0 == g_coConf.GetParamValue ("def_realm", vectValueList)) {
			in_addr inetAddr;
			std::string strIpAddr, strRealm;
			size_t stPos;
			for (std::vector<std::string>::iterator iter = vectValueList.begin(); iter != vectValueList.end(); ++iter) {
				strVal = *iter;
				stPos = strVal.find_first_of ('@');
				if (stPos == std::string::npos) { continue; }
				strIpAddr = strVal.substr (0, stPos);
				strRealm = strVal.substr (stPos + 1);
				inetAddr.s_addr = inet_addr (strIpAddr.c_str());
				if (INADDR_NONE == inetAddr.s_addr) { continue; }
				g_mapDefRealms.insert (std::make_pair (inetAddr.s_addr, strRealm));
			}
			vectValueList.clear ();
		}
		/* service rename rules */
		if (0 == g_coConf.GetParamValue ("srvc_rename", vectValueList)) {
			std::string strSrvName, strNewName;
			size_t stPos;
			for (std::vector<std::string>::iterator iter = vectValueList.begin(); iter != vectValueList.end(); ++iter) {
				strVal = *iter;
				stPos = strVal.find_first_of ('=');
				if (stPos == std::string::npos) { continue; }
				strSrvName = strVal.substr (0, stPos);
				strNewName = strVal.substr (stPos + 1);
				if (0 == strNewName.length ()) { continue; }
				g_mapServices.insert (std::make_pair (strSrvName, strNewName));
			}
			vectValueList.clear ();
		}
		/* service prefix list */
		if (0 == g_coConf.GetParamValue ("srvc_rename_prefix", vectValueList)) {
			for (std::vector<std::string>::iterator iter = vectValueList.begin(); iter != vectValueList.end(); ++iter) {
				strVal = *iter;
				if (0 == strVal.length ()) { continue; }
				g_vectSrvcPrfx.push_back (strVal);
			}
			vectValueList.clear ();
		}
		/* trunc service name flag */
		if (0 == g_coConf.GetParamValue ("trunc_srvc_name", strVal)) {
			g_iTruncSrvcName = atoi (strVal.c_str());
		}
		/*rename service flag */
		if (0 == g_coConf.GetParamValue ("rename_srvc", strVal)) {
				g_iRenameSrvc = atoi (strVal.c_str());
		}
		/* OS user name */
		g_coConf.GetParamValue ("user", g_strUser);
		/* OS user group */
		g_coConf.GetParamValue ("group", g_strGroup);
		/* thread count */
		if (0 == g_coConf.GetParamValue ("thrdcnt", strVal)) {
			g_uiThrdCnt = atol (strVal.c_str());
			if (0 == g_uiThrdCnt) { g_uiThrdCnt =1; }
		} else {
			g_uiThrdCnt = 1;
		}
		/* TCP queue length */
		if (0 == g_coConf.GetParamValue ("queuelen", strVal)) {
			g_uiQueueLen = atol (strVal.c_str());
			if (0 == g_uiQueueLen) { g_uiQueueLen =1; }
		} else {
			g_uiQueueLen = 1;
		}
		/* debug */
		if (0 == g_coConf.GetParamValue ("debug", strVal)) {
			g_uiDebug = atol (strVal.c_str());
		} else {
			g_uiDebug = 0;
		}
	} while(0);

	return iRetVal;
}

void ChangeOSUserGroup ()
{
	int iFnRes;
	passwd *psoPswd;
	group *psoGroup;
	gid_t idUser, idGroup;
	std::string strVal;

	// изменяем id пользователя ОС
	iFnRes = g_coConf.GetParamValue ("user", strVal);
	if (0 == iFnRes) {
		psoPswd = getpwnam (strVal.c_str());
		if (psoPswd) {
			idUser = psoPswd->pw_uid;
		} else {
			idUser = (gid_t)-1;
		}
	}

	strVal.clear();
	iFnRes = g_coConf.GetParamValue ("group", strVal);
	if (0 == iFnRes) {
		psoGroup = getgrnam (strVal.c_str());
		if (psoGroup) {
			idGroup = psoGroup->gr_gid;
		} else {
			idGroup = (gid_t)-1;
		}
	}
	g_coLog.SetUGIds (idUser, idGroup);
	if ((gid_t)-1 != idUser) {
		setuid (idUser);
	}
	if ((gid_t)-1 != idGroup) {
		setgid (idGroup);
	}
}

int CreateNASList ()
{
	int iRetVal = 0;
	SSrvParam *psoTmp;
	char mcNASName[128];
	char mcSecret[60];
	int iStrLen;
	otl_connect coDBConn;
	char mcConnStr[1024];

	do {
		/* подключение к БД */
		/* формируем строку подключения */
		iStrLen = snprintf(
			mcConnStr,
			sizeof(mcConnStr) - 1,
			g_mcDBConnTempl,
			g_strDBUser.c_str(),
			g_strDBPswd.c_str(),
			g_strDBHost.c_str(),
			g_strDBPort.c_str(),
			g_strDBSrvc.c_str());
		if (0 >= iStrLen) {
			iRetVal = errno;
			g_coLog.WriteLog ("CoASensd: CreateNASList: error: snprintf: code: '%d'", iRetVal);
			if (0 == iRetVal) {
				iRetVal = -1;
			}
			break;
		}
		/* попытка подключения к БД */
		try {
			coDBConn.rlogon (mcConnStr);
			g_coLog.WriteLog ("CoAd: CreateNASList: DB connected successfully");
		}
		catch (otl_exception &coOtlExc) {
			g_coLog.WriteLog ("CoAd: Can't connect to DB. Error: '%s'", coOtlExc.msg);
			iRetVal = coOtlExc.code;
			break;
		}

		try {
			otl_stream coOTLStream(
				1,
				g_strNASQuery.c_str(),
				coDBConn);
			char mcNASName[128];
			char mcCoASrvr[128];
			char mcCoAPort[32];
			char mcSecret[60];
			while (! coOTLStream.eof()) {
				coOTLStream
					>> mcNASName
					>> mcCoASrvr
					>> mcCoAPort
					>> mcSecret;
				psoTmp = new SSrvParam;
				memset (psoTmp, 0, sizeof(*psoTmp));
				psoTmp->m_usPort = strtol (mcCoAPort, 0, 10);
				iStrLen = strlen(mcSecret) > sizeof(psoTmp->m_mcSecret) - 1 ? sizeof(psoTmp->m_mcSecret) - 1 : strlen(mcSecret);
				strncpy (psoTmp->m_mcSecret, mcSecret, iStrLen);
				iStrLen = strlen(mcCoASrvr) > sizeof(psoTmp->m_mcCoASrvr) - 1 ? sizeof(psoTmp->m_mcCoASrvr) - 1 : strlen(mcCoASrvr);
				strncpy (psoTmp->m_mcCoASrvr, mcCoASrvr, iStrLen);
				psoTmp->m_pcoRadiusClient = new CRadiusClient (psoTmp, g_iRadReqTimeout);
				if (NULL == psoTmp->m_pcoRadiusClient) {
					iRetVal = -1;
					break;
				}
				if (0 != psoTmp->m_pcoRadiusClient->Init()) {
					g_coLog.WriteLog ("Can not initialize radius client");
					iRetVal = -1;
					break;
				}
				g_mapServers.insert (std::make_pair(std::string(mcNASName), psoTmp));
			}
		}
		catch (otl_exception &coOTLExc) {
			g_coLog.WriteLog ("CoAd: CreateNASList: Can't execute query. Error: '%s'", coOTLExc.msg);
			iRetVal = coOTLExc.code;
		}
		/* завершение соединения с БД */
		coDBConn.logoff();
	} while (0);

	return iRetVal;
}

void my_inet_ntoa_r (struct in_addr &in, char *p_pszOut, int p_iBufSize)
{
	int iFnRes;

	iFnRes = snprintf (
		p_pszOut,
		p_iBufSize - 1,
		"%u.%u.%u.%u",
		in.s_addr & 0x000000FF,
		(in.s_addr & 0x0000FF00) >> 8,
		(in.s_addr & 0x00FF0000) >> 16,
		(in.s_addr & 0xFF000000) >> 24);
	if (0 < iFnRes) {
		if (iFnRes > p_iBufSize - 1) {
			iFnRes = p_iBufSize - 1;
		}
		p_pszOut[iFnRes] = '\0';
	} else {
		*p_pszOut = '\0';
	}
}

int RequestOperateAdminReq (std::multimap<unsigned short,SPSReqAttr*> &p_mmapAttrList, SPSRequest *p_psoResp, size_t p_stBufSize)
{
	int iRetVal = 0;

	do {
		CPSPacket coPSPack;
		std::multimap<unsigned short,SPSReqAttr*>::iterator iterAttrList;
		std::basic_string<char> bstrPSCmd;
		__uint16_t ui16AttrLen;

		coPSPack.SetReqType (p_psoResp, p_stBufSize, ADMIN_RSP, 0);

		iterAttrList = p_mmapAttrList.find (PS_ADMCMD);
		/* если в массиве найден искомый атрибут, содержащий непустое значение */
		if (iterAttrList != p_mmapAttrList.end() && ntohs (iterAttrList->second->m_usAttrLen) > sizeof(SPSReqAttr)) {
			ui16AttrLen = ntohs (iterAttrList->second->m_usAttrLen) - sizeof (SPSReqAttr);
			bstrPSCmd.assign (((char *) iterAttrList->second) + sizeof (SPSReqAttr), ui16AttrLen);
			if (0 == bstrPSCmd.compare ("stop")) {
				/* получена команда "stop" */
				coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, "0", 1, 0);
				g_iEvent = 'T';
			} else {
				/* unsupported PS_ADMCMD value*/
				coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, "-1", 2, 0);
				coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_DESCR, bstrPSCmd.c_str (), bstrPSCmd.length (), 0);
			}
		} else {
			/* attribute PS_ADMCMD not found*/
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, "-1", 2, 0);
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_DESCR, "'command' attribute not found", 29, 0);
		}
	} while (0);

	return iRetVal;
}

int RequestOperateMonitReq (SPSRequest *p_psoResp, size_t p_stBufSize)
{
	int iRetVal = 0;

	do {
		CPSPacket coPSPack;
		int iFnRes;
		char mcInfo[128];

		/* задаем тип запроса*/
		coPSPack.SetReqType (p_psoResp, p_stBufSize, MONIT_RSP, 0);

		/* PS_RESULT*/
		coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, "0", 1, 0);

		/* PS_LASTOK*/
		iFnRes = TimeValueToString (g_sotvLastSuccess, mcInfo, sizeof (mcInfo));
		if (iFnRes > 0) {
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_LASTOK, mcInfo, iFnRes, 0);
		}

		/* PS_LASTER*/
		iFnRes = TimeValueToString (g_sotvLastError, mcInfo, sizeof (mcInfo));
		if (iFnRes > 0) {
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_LASTER, mcInfo, iFnRes, 0);
		}

		/* PS_STATUS*/
		coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_STATUS, "running", 7, 0);
	} while (0);

	return iRetVal;
}

int TimeValueToString (timeval &p_soTimeVal, char *p_pmBuf, size_t p_stBufSize)
{
	int iRetVal = 0;

	do {
		int iStrLen = 0;
		int iFnRes;
		time_t tmTime;
		tm soTm;

		tmTime = p_soTimeVal.tv_sec;
		if (NULL == localtime_r (&tmTime, &soTm)) {
			goto conv_failed;
		}
		iFnRes = strftime (p_pmBuf, p_stBufSize, "%Y.%m.%d %H:%M:%S", &soTm);
		if (0 >= iFnRes) {
			goto conv_failed;
		}
		iStrLen = iFnRes;
		iFnRes = snprintf (&p_pmBuf[iStrLen], p_stBufSize - 1 - iStrLen, ",%03u", p_soTimeVal.tv_usec / 1000);
		/* если буфер успешно заполнен */
		if (0 < iFnRes) {
			if (iFnRes > p_stBufSize - 1 - iStrLen) {
				iFnRes = p_stBufSize - 1 - iStrLen;
			}
			iStrLen += iFnRes;
		}

		/* все преобразования успешно завершены, выходим из блока */
		iRetVal = iStrLen;
		break;

		/* в случае ошибки забиваем буфер нулевой датой */
		conv_failed:
		iFnRes = snprintf (p_pmBuf, p_stBufSize - 1, "0000.00.00 00:00:00,000");
		if (0 < iFnRes) {
			if (iFnRes > p_stBufSize - 1) {
				iFnRes = p_stBufSize - 1;
			}
			iRetVal = iFnRes;
		}
	} while (0);

	return iRetVal;
}

int RequestOperateCommandReq (std::multimap<unsigned short,SPSReqAttr*> &p_mmapAttrList, SPSRequest *p_psoResp, size_t p_stBufSize, SConnectInfo *p_psoConnInfo)
{
	int iRetVal = 0;

	do {
		int iFnRes;
		int iReqRes;
		const char *pszTmpStr;
		char mcResCode[32];
		CPSPacket coPSPack;
		bool bDescrIsCrtd = false;
		__uint16_t ui16AttrLen;
		char mcRem[0x1000] = { '\0' };

		/* задаем тип запроса */
		coPSPack.SetReqType (p_psoResp, p_stBufSize, COMMAND_RSP, 0);

		iFnRes = SendRequest (p_mmapAttrList, p_psoConnInfo, mcRem);

		if (0 == iFnRes) {
			iReqRes = AnalyseResponse (p_psoConnInfo->m_mucRadBuf, mcRem);
		} else {
			iReqRes = iFnRes;
		}

		/* Формирование ответа */

		/* Формируем поле Result */
		iFnRes = snprintf (mcResCode, sizeof (mcResCode) - 1, "%d", iReqRes);
		if (0 < iFnRes) {
			if (iFnRes > sizeof (mcResCode) - 1) {
				iFnRes = sizeof (mcResCode) - 1;
			}
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, mcResCode, iFnRes, 0);
		}

		if (0 == iReqRes || -45 == iReqRes) {
			/* если от получен ответ от coa-сервера */
			gettimeofday (&g_sotvLastSuccess, NULL);
		}  else {
			/* если нет внятного ответа от coa-сервера */
			gettimeofday (&g_sotvLastError, NULL);
			goto radius_no_answer;
		}

		/* Анализ ответа */
		unsigned char *pucLastAttr;
		char mcAttrName[1024];
		char mcAttrValue[2048];
		char *pszTmpPtr;
		unsigned int uiAVLen;
		unsigned char ucAttrType;
		unsigned int uiVendorId;
		unsigned char ucVendorTypeId;

		/* обходим все атрибуты ответа */
		pucLastAttr = NULL;
		while ((pucLastAttr = p_psoConnInfo->m_psoCoASrvrParam->m_pcoRadiusClient->EnumAttr(p_psoConnInfo->m_mucRadBuf, pucLastAttr, mcAttrName, mcAttrValue, &ucAttrType, &uiAVLen, &uiVendorId, &ucVendorTypeId))) {
			ui16AttrLen = uiAVLen;
			switch (ucAttrType) {
			case 1:		/* User-Name*/
				if (0 < ui16AttrLen) {
					coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_USERNAME, mcAttrValue, ui16AttrLen, 0);
				}
				break;
			case 8:		/* Framed-IP-Address*/
				if (0 < ui16AttrLen) {
					coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_FRAMEDIP, mcAttrValue, ui16AttrLen, 0);
				}
				break;
			case 18:	/* Reply-Message*/
				if (0 < ui16AttrLen) {
					coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_DESCR, mcAttrValue, ui16AttrLen, 0);
					bDescrIsCrtd = true;
				}
				break;
			case 26:	/* VSA*/
				switch (uiVendorId) {
				case 9:	/* Cisco*/
					switch (ucVendorTypeId) {
					case 252: { /* Cisco-Command-Code */
							if (mcAttrValue[0] == 4) {
								coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_SESSTATUS, &mcAttrValue[1], 1, 0);
							}
						}
						break; /* Cisco-Command-Code */
					case 250: {	/* Cisco-Account-Info*/
							int iCmpRes = -1;
							int iShift;
							/* если необходимо обрезать имена сервисов */
							if (g_iTruncSrvcName) {
								/* ищем подходящий префикс */
								std::vector<std::string>::iterator iterSrvcPrfx = g_vectSrvcPrfx.begin();
								for (; iterSrvcPrfx != g_vectSrvcPrfx.end() && 0 != iCmpRes; ++iterSrvcPrfx) {
									iShift = iterSrvcPrfx->length ();
									iCmpRes = iterSrvcPrfx->compare (0, iShift, mcAttrValue, iShift);
								}
								/* если подходящий префикс не найден переходим к следующему атрибуту */
								if (0 != iCmpRes) {
									continue;
								}
								/* если префикс сервиса подходящий отсекаем хвост */
								pszTmpPtr = strstr (mcAttrValue, ";");
								if (pszTmpPtr) {
									*pszTmpPtr = '\0';
								}
							} else {
								iShift = 0;
							}
							/* если сервис надо переименовывать */
							if (g_iRenameSrvc) {
								/* ищем имя сервиса в таблице переименовывания */
								std::map<std::string,std::string>::iterator iterSrvcRen = g_mapServices.find (&mcAttrValue[iShift]);
								/* если не нашли переходим к следующему атрибуту */
								if (iterSrvcRen == g_mapServices.end()) {
									continue;
								}
								/* если нашли, то сохраняем параметры табличного значения */
								ui16AttrLen = iterSrvcRen->second.length ();
								pszTmpStr = iterSrvcRen->second.c_str ();
							} else {
								/* если переименовывать не надо передаем прежнее значение */
								pszTmpStr = &mcAttrValue[iShift];
								ui16AttrLen = strlen (&mcAttrValue[iShift]);
							}
							if (0 < ui16AttrLen) {
								coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_ACCINFO, pszTmpStr, ui16AttrLen, 0);
							}
						}
						break;	/* Account-Info*/
					}
					break;	/* Cisco*/
				}
				break;	/* VSA*/
			default:
				break;
			}
		}
		radius_no_answer:
		if (! bDescrIsCrtd && '\0' != *mcRem) {
			/* Формируем поле Description */
			ui16AttrLen = strlen (mcRem);
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_DESCR, mcRem, ui16AttrLen, 0);
		}
	} while (0);

	return iRetVal;
}

int RequestOperateUnsupportedReq (__uint16_t p_ui16ReqType, SPSRequest *p_psoResp, size_t p_stBufSize)
{
	int iRetVal = 0;

	do {
		CPSPacket coPSPack;
		char mcInfo[0x1000];
		int iStrLen;
		__uint16_t ui16ReqType;

		/* задем неопределенный тип запроса: тип запроса + 1 */
		ui16ReqType = ntohs (p_ui16ReqType);
		++ ui16ReqType;
		ui16ReqType = htons (ui16ReqType);
		coPSPack.SetReqType (p_psoResp, p_stBufSize, ui16ReqType, 0);

		/* задаем код результата '-1' - обшибка */
		coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_RESULT, "-1", 2, 0);

		/* описание ошибки */
		iStrLen = snprintf (mcInfo, sizeof (mcInfo) - 1, "Unsupported request type '%#04x'", ntohs (p_ui16ReqType));
		/* если буфер успешно заполнен */
		if (0 < iStrLen) {
			/* если строка не уместилась в буфере полностью */
			if (iStrLen > sizeof (mcInfo) - 1) {
				iStrLen = sizeof (mcInfo) - 1;
			}
			coPSPack.AddAttr (p_psoResp, p_stBufSize, PS_DESCR, mcInfo, (__uint16_t) iStrLen, 0);
		}
	} while (0);

	return iRetVal;
}
