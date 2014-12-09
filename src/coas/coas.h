#ifndef _COA_SENSOR_H_
#define _COA_SENSOR_H_

#ifdef WIN32
typedef unsigned __int16 uint16_t;
#endif

#include <pthread.h>

int InitCoASensor ();
void DeInitCoASensor ();

class CRadiusClient;
struct SPSReqAttr;

/* Информация о CoA-серверах */
struct SSrvParam {
	char m_mcCoASrvr[128];
	unsigned short m_usPort;
	char m_mcSecret[64];
	CRadiusClient *m_pcoRadiusClient;
};

/* Информация о потоке */
struct SConnectInfo {
	volatile bool m_bIsFree;			/* признак занятости потока */
	SSrvParam *m_psoCoASrvrParam;	/* параметры CoA-сервера */
	unsigned int m_uiThrdNum;			/* номер потока */
	unsigned int m_uiConnNum;			/* номер подключения */
	int m_iSock;									/* идентификатор сокета */
	sockaddr_in m_soFrom;					/* информация об отправителе сообщения */
	pthread_t m_hThrdId;					/* идентификтор потока */
	bool m_bCont;									/* признак продолжения работы потока */
/*	int m_iFutex;								/* идентификатор фьютекса */ /* попробуем заменить фьютексы на мьютексы */
	pthread_mutex_t m_mMutex;			/* мьютекс для синхронизации потоков */
	char m_mcPSReq[0x10000];						/* буфер для запроса сервера политик */
	int m_iReqLen;											/* объем данных, записанных в буфер m_mcPSReq */
	char m_mcPSResp[0x10000];						/* буфер для запроса сервера политик */
	unsigned char m_mucRadBuf[0x1000];	/* буфер для ответа по протоколу RADIUS */
};

/*	Заголовок VSA-атрибута */
#pragma pack(push,1)
struct SVSAAttr {
	unsigned char m_ucType;
	unsigned char m_ucLength;
	unsigned int m_uiVendorId;
	unsigned char m_ucVendorType;
	unsigned char m_ucVendorLen;
	unsigned char m_mcValue[1];
};
#pragma pack(pop)

class CRadiusClient;

/*	Параметры
 */
struct SCommandParam {
	SSrvParam *m_psoCoASrvrParam;
	unsigned int m_uiRequestId;
};

/*  Функция инициализации сокета
 */
int InitSocket(
	int *p_piLsnrSock,
	const char *p_pszIpAddr,
	unsigned short p_usPort,
	int p_iConnectQueueLen);

/*  Инициализация пула потоков */
int InitThreadPool (SConnectInfo **p_ppmsoConnInf, int p_iConnCnt);

/*  Деинициализация пула потоков */
int DeInitThreadPool (SConnectInfo *p_pmsoConnInf, int p_iConnCnt);

/*  Менеджер управления
 *  запросами
 */
int RequestManager ();

/*  Обработчик запросов на подключение
 *  по TCP
 */
void* RequestOperate (void* p_pvParam);

/*	Передача команды на исполнение
 *	серверу CoA
 */
int SendRequest (std::multimap<unsigned short,SPSReqAttr*> &p_mmapPSAttrList, SConnectInfo *p_psoConnInfo, char *p_pmcRem);

/*	Обработка командной строки,
 *	подготовка пакета RADUIS
 */
int UpdateRadiusPacket(
	SCommandParam *p_psoCmdParam,
	const unsigned short p_usAttrType,
	const unsigned char *p_pmucAttrValue,
	const unsigned short p_usAttrLen,
	u_long p_ulFrom);

/* указатель на экземпляр радиус-клиента */
SSrvParam * GetCoASrvrInfo (std::multimap<unsigned short,SPSReqAttr*> &p_mmapPSAttr);

/*	Формирование атрибутов
 *	пакета RADIUS
 *	в соответствии с UserName
 */
int MakeUserNameAttr(
	const char *p_pszUserName,
	SCommandParam *p_psoCmdParam,
	u_long p_ulFrom);

/*	Формирование атрибутов
 *	пакета RADIUS
 *	в соответствии с UserPswd
 */
int MakeUserPswdAttr(
	const char *p_pszSessioId,
	SCommandParam *p_psoCmdParam,
	char *p_szSecretKey);

/*	Формирование атрибутов
 *	пакета RADIUS
 *	в соответствии с SessionId
 */
int MakeSessionIdAttr(
	const char *p_pszSessioId,
	SCommandParam *p_psoCmdParam);

/*	Формирование атрибутов
 *	пакета RADIUS
 *	в соответствии с AccountInfo
 */
int MakeAccountInfoAttr(
	const char *p_pszAccountInfo,
	SCommandParam *p_psoCmdParam);

/*	Формирование атрибутов
 *	пакета RADIUS
 *	в соответствии с поступившей командой
 */
int MakeCommandAttr(
	const char *p_pszCommand,
	SCommandParam *p_psoCmdParam);

/*	Заполнение полей атрибута
 *	VSA
 */
void MakeVSAAttr (SVSAAttr *p_psoVSAAttr, unsigned int p_uiVendorId, unsigned char p_ucVendorType, const char *p_pmucAttrValue, unsigned int p_uiAttrLen);

int AnalyseResponse(
	unsigned char *p_pmucResp,
	char *p_pmcRem);

/* функция для безопасного преобразования структуры адрсеса в строковый формат */
void my_inet_ntoa_r (struct in_addr &in, char *p_pszOut, int p_iBufSize);

#endif
