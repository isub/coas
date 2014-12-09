#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <memory.h>
#include <ctype.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <string>
#include <sys/ioctl.h>
#include <poll.h>
#include <map>

#include "../md5/md5.h"
#include "../../../utils/log/Log.h"
#include "../coas/coas.h"
#include "Radius.h"

extern CLog g_coLog;
extern unsigned int g_uiDebug;

CRadiusClient::CRadiusClient (SSrvParam *p_psoCoASrvr, int p_iReqTimeout)
{
	m_vlLastPackId = -1;
	m_vbContSend = true;
	m_vbContRecv = true;
	m_psoCoASrvr = p_psoCoASrvr;
	m_iRequestTimeout = p_iReqTimeout ? p_iReqTimeout : 5;

	do {
		/*	Инициализация массива запросов */
		memset (m_msoPackQueue, 0, sizeof(m_msoPackQueue));
	} while (0);
}

int CRadiusClient::Init()
{
	int iRetVal = 0;

	for (int i = 0; i < sizeof(m_msoPackQueue)/sizeof(*m_msoPackQueue); ++i) {
		m_msoPackQueue[i].m_iCoASrvrSock = -1;
	}

	/* инициализация объекта синхронизации */
	iRetVal = pthread_mutex_init (&m_mMutexGetId, NULL);
	if (0 == iRetVal) {
		pthread_mutex_unlock (&m_mMutexGetId);
	}

	return iRetVal;
}

CRadiusClient::~CRadiusClient()
{
	bool bCompleted;

	/*  Запрещаем посылку запросов
	 */
	m_vbContSend = false;

	/*	Ожидаем корректного
	 *  завершения обработки запросов
	 */
	int iIterCnt = 5;
	while (0 < iIterCnt) {
		bCompleted = true;
		for (int i = 0; i < 0x100; ++i) {
			if (m_msoPackQueue[i].m_vbIsUsed) {
				bCompleted = false;
				break;
			}
		}
		if (bCompleted) {
			break;
		}
		sleep (1);
		--iIterCnt;
	}

	/*	Даем команду на завершение потока
	 *	сбора ответов
	 */
	m_vbContRecv = false;

	/*  Если были выявлены незавершенные потоки,
	 *  ждем, на всякий случай
	 */
	if (! bCompleted) {
		sleep (m_iRequestTimeout);
	}

	pthread_mutex_destroy (&m_mMutexGetId);
}

unsigned int CRadiusClient::GetNewId (unsigned char p_ucCode)
{
	unsigned int uiPackId;
	SRadiusHeader *psoTmpPtr;

	/* блокируем доступ к участку кода */
	pthread_mutex_lock (&m_mMutexGetId);

	/*	Назначение нового идентификатора
	 */
	uiPackId = ++m_vlLastPackId;
	uiPackId %= 0x100;

	/*	Если идентификатор занят
	 *	возвращаем ошибку
	 */
	if (m_msoPackQueue[uiPackId].m_vbIsUsed) {
		return (unsigned int)-1;
	}

	m_msoPackQueue[uiPackId].m_vbIsUsed = true;
	m_msoPackQueue[uiPackId].m_usRecvDataLen = 0;

	/*	Initialization of Radius header */
	psoTmpPtr = (SRadiusHeader*)m_msoPackQueue[uiPackId].m_mucSendBuf;
	psoTmpPtr->m_ucCode = p_ucCode;
	psoTmpPtr->m_ucIdentifier = (unsigned char)uiPackId;
	psoTmpPtr->m_usLength = sizeof(*psoTmpPtr) - sizeof(psoTmpPtr->m_msoAttributes);

	pthread_mutex_unlock (&m_mMutexGetId);
	/* участок кода освобожден */

	return uiPackId;
}


int CRadiusClient::AddAttr(
	unsigned int p_uiReqId,
	SRadiusAttribute *p_psoRadiusAttr)
{
	int iRetVal = 0;
	SRadiusHeader *psoRadHdr;

	if (0x100 <= p_uiReqId) {
		return -1;
	}

	if (! m_msoPackQueue[p_uiReqId].m_vbIsUsed) {
		char mcRem[128];
		int iRemLen;

		g_coLog.WriteLog ("RadiusClient: AddAttr: packet id '%d' is not used", p_uiReqId);
		return -1;
	}

	psoRadHdr = (SRadiusHeader*)(m_msoPackQueue[p_uiReqId].m_mucSendBuf);
	memcpy(
		&(m_msoPackQueue[p_uiReqId].m_mucSendBuf[psoRadHdr->m_usLength]),
		p_psoRadiusAttr,
		p_psoRadiusAttr->m_ucLength);
	psoRadHdr->m_usLength = psoRadHdr->m_usLength + p_psoRadiusAttr->m_ucLength;

	return iRetVal;
}

int CRadiusClient::SendPack(
	unsigned int p_uiReqId,
	char *p_pszCoAServerIp,
	unsigned short p_usCoAServerPort,
	unsigned char *p_pmucRecvBuf,
	unsigned int *p_puiBufSize,
	char* p_pmcRem)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'CRadiusClient::SendPack'");
	}
	int iRetVal = 0;
	int iRemLen;
	int iErrCode;
	char mcErr[2048];
	char *pszParsedPack = NULL;
	int iBufSize = 0x10000;
	int iParsPackLen;

	do {

		/*  Если дана команда на прекращение работы
		 */
		if (! m_vbContSend) {
			g_coLog.WriteLog ("RadiusClient: SendPack: received shutdown command");
			iRetVal -1;
			break;
		}

		/* создаем сокет для взаимодействия с CoA-сервером */
		m_msoPackQueue[p_uiReqId].m_iCoASrvrSock = CreateCoASrvrSock();
		if (-1 == m_msoPackQueue[p_uiReqId].m_iCoASrvrSock) {
			iRetVal = -1;
			break;
		}

		SRadiusHeader *psoTmpPtr;
		unsigned int uiPackLen;

		/*	Преобразовываем указатель
		 */
		psoTmpPtr = (SRadiusHeader*)m_msoPackQueue[p_uiReqId].m_mucSendBuf;

		/*	Проверка значения id пакета RADIUS
		 */
		if (0x100 <= p_uiReqId) {
			g_coLog.WriteLog ("RadiusClient: SendPack: invalid packet id: '%d'", p_uiReqId);
			iRetVal -1;
			break;
		}

		/*	Проверка используемости пакета
		 */
		if (! m_msoPackQueue[p_uiReqId].m_vbIsUsed) {
			g_coLog.WriteLog ("RadiusClient: SendPack: packet id '%d' is not used", p_uiReqId);
			iRetVal -1;
			break;
		}

		/*	Сохраняем значение в локальную переменную
		 *	т.к. в дальнейшем значение изменится
		 *	в результате перестановки байтов
		 */
		uiPackLen = psoTmpPtr->m_usLength;

		/*	Проверка размера пакета
		 */
		if (uiPackLen < 20
			&& uiPackLen > 4096) {
				g_coLog.WriteLog ("RadiusClient: SendPack: packet id: '%u'; invalid size: '%u'", p_uiReqId, uiPackLen);
				break;
		}

		sockaddr_in soDestAddr;

		/*	Переставляем байты в net-порядок
		 */
		psoTmpPtr->m_usLength = htons (psoTmpPtr->m_usLength);

		/*	Формируем аутентификатор
		 */
		CheckAuthenticator (psoTmpPtr, uiPackLen, true);

		soDestAddr.sin_family = AF_INET;
		soDestAddr.sin_addr.s_addr = inet_addr (p_pszCoAServerIp);
		/* если номер порта передан в параметре, используем его. в противном случае берем значение, полученное при инициализации */
		if (p_usCoAServerPort) {
			soDestAddr.sin_port = htons (p_usCoAServerPort);
		} else {
			soDestAddr.sin_port = htons (m_psoCoASrvr->m_usPort);
		}

		pszParsedPack = (char*) malloc (iBufSize);

		iParsPackLen = snprintf(
			pszParsedPack,
			iBufSize - 1,
			"RadiusClient: SendPack: Send packet to '%s:%u':\n",
			p_pszCoAServerIp,
			p_usCoAServerPort);
		if (0 < iParsPackLen) {
			if (iParsPackLen > iBufSize - 1) {
				iParsPackLen = iParsPackLen - 1;
			}
		}
		ParsePacket (m_msoPackQueue[p_uiReqId].m_mucSendBuf, pszParsedPack, &iParsPackLen);
		g_coLog.Dump (pszParsedPack);

		/* отправляем пакет CoA-серверу */
		iRetVal = sendto(
			m_msoPackQueue[p_uiReqId].m_iCoASrvrSock,
			(const char*)m_msoPackQueue[p_uiReqId].m_mucSendBuf,
			uiPackLen,
			0,
			(sockaddr*)&soDestAddr,
			sizeof(soDestAddr));
		if (-1 == iRetVal) {
			iErrCode = errno;
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			iRemLen = sprintf (p_pmcRem, "RadiusClient: SendPack: sendto packet id '%u' error: '%d': '%s'", p_uiReqId, iErrCode, mcErr);
			g_coLog.Dump (p_pmcRem);
			break;
		}

		/* пытаемся получить ответ от CoA-сервера */
		iRetVal = RecvCoASrvrResp (p_uiReqId);

		/*	Если при ожидании ответа возникла ошибка завершаем выполнение */
		if (iRetVal) {
			break;
		}

		if (*p_puiBufSize < m_msoPackQueue[p_uiReqId].m_usRecvDataLen) {
			g_coLog.WriteLog ("RadiusClient: SendPack: buffer size '%u' not enough for packet: id: '%u'; size: '%u'", *p_puiBufSize, p_uiReqId, uiPackLen);
			iRetVal = -1;
			break;
		}
		if (p_pmucRecvBuf && m_msoPackQueue[p_uiReqId].m_usRecvDataLen) {
			*p_puiBufSize = m_msoPackQueue[p_uiReqId].m_usRecvDataLen;
			memcpy (p_pmucRecvBuf, m_msoPackQueue[p_uiReqId].m_mucRecvBuf, m_msoPackQueue[p_uiReqId].m_usRecvDataLen);
		}
	} while (0);

	if (pszParsedPack) {
		free (pszParsedPack);
		pszParsedPack = NULL;
	}

	if (-1 != m_msoPackQueue[p_uiReqId].m_iCoASrvrSock) {
		close (m_msoPackQueue[p_uiReqId].m_iCoASrvrSock);
		m_msoPackQueue[p_uiReqId].m_iCoASrvrSock = -1;
	}

	return iRetVal;
}

int CRadiusClient::CreateCoASrvrSock ()
{
	int iRetVal = 0;
	int iCoASrvrSock;
	char mcMsg[0x2000];
	int iMsgLen;
	int iErrCode;
	char mcErr[2048];

	do {
		/*	Инициализация сокета
			*/
		iCoASrvrSock = socket(
			PF_INET,
			SOCK_DGRAM,
			0);
		if (-1 == iCoASrvrSock) {
			iErrCode = errno;
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("CRadiusClient: CreateCoASrvrSock : 'socket' error: '%d': '%s'", iErrCode, mcErr);
			iRetVal = -1;
			break;
		}

		/* Изменяем режим ввода-вывода сокета */
		u_long ulOn;
		ulOn = 1;

		iRetVal = ioctl(
			iCoASrvrSock,
			FIONBIO,
			&ulOn);
		if (-1 == iRetVal) {
			iErrCode = errno;
			if (strerror_r (iErrCode, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("CRadiusClient: CreateCoASrvrSock : 'ioctl' error: '%d': '%s'", iErrCode, mcErr);
			iRetVal = -1;
			break;
		}
		if (0 == iRetVal) {
			iRetVal = iCoASrvrSock;
		}
	} while (0);

	/* если фукнция выполнилась неудачно и сокет уже создан */
	if (-1 == iRetVal && -1 != iCoASrvrSock) {
		close (iCoASrvrSock);
	}

	return iRetVal;
}

unsigned int CRadiusClient::GetPackLen (unsigned char* p_pucRadPack)
{
	unsigned int uiRetVal;
	SRadiusHeader *psoRadiusHdr;

	psoRadiusHdr = (SRadiusHeader*)p_pucRadPack;
	uiRetVal = ntohs (psoRadiusHdr->m_usLength);

	return uiRetVal;
}

unsigned int CRadiusClient::GetAttrLen (unsigned char* p_pucRadAttr)
{
	unsigned int uiRetVal;
	SRadiusAttribute *psoRadAttr;

	psoRadAttr = (SRadiusAttribute*)p_pucRadAttr;
	uiRetVal = psoRadAttr->m_ucLength;

	return uiRetVal;
}

unsigned char* CRadiusClient::EnumAttr(
	unsigned char* p_pucRadPack,
	unsigned char* p_pucLastAttr,
	char *p_pszAttrName,
	char *p_pszAttrValue,
	unsigned char *p_pucAttrType,
	unsigned int *p_uiAVLen,
	unsigned int *p_uiVendorId,
	unsigned char *p_ucVendorType)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'CRadiusClient::EnumAttr'");
	}
	int iFnRes;
	unsigned int uiPackLen;
	unsigned int uiAttrValLen;
	SRadiusAttribute *psoRadAttr;
	static char mcPwdPad[256] = { '*' };

	/* !!! отсутствует проверка размера содержимого буфера p_pucRadPack !!! */

	if (NULL == p_pucLastAttr) {
		/* пропускаем заголовок пакета */
		p_pucLastAttr = p_pucRadPack + 20;
	} else {
		/* определяем длину предыдущего атрибута с учетом заголовка */
		uiAttrValLen = GetAttrLen (p_pucLastAttr);
		/* назначаем текущий атрибут */
		p_pucLastAttr += uiAttrValLen;
	}
	/* определяем длину пакета */
	uiPackLen = GetPackLen (p_pucRadPack);
	/* если вышли за пределы пакета */
	if (p_pucLastAttr >= (p_pucRadPack + uiPackLen)) {
		return NULL;
	}
	/* проверяем, не выходит ли текущий атрибут за пределы пакета */
	/* определяем длину предыдущего атрибута с учетом заголовка */
	uiAttrValLen = GetAttrLen (p_pucLastAttr);
	/* если вышли за пределы пакета */
	if (p_pucLastAttr + uiAttrValLen > (p_pucRadPack + uiPackLen)) {
		return NULL;
	}
	psoRadAttr = (SRadiusAttribute *) p_pucLastAttr;
	/* Выводим тип атрибута */
	if (p_pucAttrType) {
		*p_pucAttrType = psoRadAttr->m_ucType;
	}
	/* Выводим имя атрибута */
	if (p_pszAttrName) {
		strcpy (p_pszAttrName, msoAttrDetails[psoRadAttr->m_ucType].m_mcAttrName);
	}
	/* корректируем длину атрибута, оставляем длину значения атибута */
	uiAttrValLen -= sizeof (*psoRadAttr) - sizeof (psoRadAttr->m_mucValue);
	/* Выводим значение атрибута */
	if (p_pszAttrValue) {
		switch (msoAttrDetails[psoRadAttr->m_ucType].m_eAttrType) {
		case eADT_Password:
			memcpy (p_pszAttrValue, mcPwdPad, uiAttrValLen);
			p_pszAttrValue[uiAttrValLen] = '\0';
			break; /* eADT_Password */
		case eADT_String:
			memcpy (p_pszAttrValue, psoRadAttr->m_mucValue, uiAttrValLen);
			p_pszAttrValue[uiAttrValLen] = '\0';
			break; /* eADT_String */
		case eADT_Number:
			{
				unsigned int uiNumVal;
				switch (uiAttrValLen)
				{
				case 1:
					uiNumVal = psoRadAttr->m_mucValue[0];
					break;
				case 2:
					uiNumVal = ntohs (*(unsigned short*)&(psoRadAttr->m_mucValue[0]));
					break;
				case 4:
				default:
					uiNumVal = ntohl (*(unsigned int*)&(psoRadAttr->m_mucValue[0]));
					break;
				}
				/* переписываем длину значения атрибута, она теперь другая */
				iFnRes = sprintf (p_pszAttrValue, "0x%08x", uiNumVal);
				if (0 < iFnRes) {
					uiAttrValLen = (unsigned int) iFnRes;
				} else {
					uiAttrValLen = 0;
					*p_pszAttrValue = '\0';
				}
			}
			break; /* eADT_Number */
		case eADT_IpAddress:
			iFnRes = sprintf(
				p_pszAttrValue,
				"%u.%u.%u.%u",
				psoRadAttr->m_mucValue[0],
				psoRadAttr->m_mucValue[1],
				psoRadAttr->m_mucValue[2],
				psoRadAttr->m_mucValue[3]);
			if (0 < iFnRes) {
				uiAttrValLen = (unsigned int) iFnRes;
			} else {
				uiAttrValLen = 0;
				*p_pszAttrValue = '\0';
			}
			break; /* eADT_IpAddress */
		case eADT_VSA:
			if (p_uiVendorId) {
				*p_uiVendorId = ntohl (*((unsigned int *) (&(psoRadAttr->m_mucValue[0]))));
			}
			if (p_ucVendorType) {
				*p_ucVendorType = psoRadAttr->m_mucValue[4];
			}
			/* корректируем длину значения атрибута */
			uiAttrValLen -= 6;
			memcpy (p_pszAttrValue, &(psoRadAttr->m_mucValue[6]), uiAttrValLen);
			p_pszAttrValue[uiAttrValLen] = '\0';
			break; /* eADT_VSA */
		default:
			if (p_pszAttrValue) {
				*p_pszAttrValue = '\0';
			}
			uiAttrValLen = 0;
			break; /* default */
		}
	}
	/* передаем длину значения атрибута */
	if (p_uiAVLen) {
		*p_uiAVLen = uiAttrValLen;
	}

	return p_pucLastAttr;
}

void CRadiusClient::ReleaseId (unsigned char p_ucPackId)
{
	m_msoPackQueue[p_ucPackId].m_usRecvDataLen = 0;
	m_msoPackQueue[p_ucPackId].m_vbIsUsed = false;
}

/*	Поле Authenticator RADIUS-пакета (RFC 2866):
 *	Authenticator = MD5(Code + Identifier + Length + 16 zero octets + request attributes + shared secret)
 *	(where + indicates concatenation)
 */
bool CRadiusClient::CheckAuthenticator(
	SRadiusHeader* p_psoRadHdr,
	unsigned int p_uiDataLen,
	bool p_bWriteResult)
{
	bool bRetVal = true;
	unsigned char *pmucData = 0;

	/* проверка параметров */
	if (NULL == p_psoRadHdr) {
		return false;
	}

	do {

		/*	Выделяем память для формирования хэшированной строки
		 */
		pmucData = (unsigned char*) malloc (p_uiDataLen + strlen (m_psoCoASrvr->m_mcSecret));
		if (0 == pmucData) {
			break;
		}

		/*	Копируем пакет в буфер
		 */
		memcpy (pmucData, p_psoRadHdr, p_uiDataLen);

		switch (p_psoRadHdr->m_ucCode) {
			case 40:
			case 43:
				/*	Записываем в аутентификатор нули
				 */
				memset(
					((SRadiusHeader*)pmucData)->m_mucAuthenticator,
					0,
					sizeof(p_psoRadHdr->m_mucAuthenticator));
				break;
			case 41:
			case 42:
			case 44:
			case 45:
				/*	Копируем аутентификатор запроса
				 */
				memcpy(
					((SRadiusHeader*)pmucData)->m_mucAuthenticator,
					((SRadiusHeader*)(m_msoPackQueue[p_psoRadHdr->m_ucIdentifier].m_mucSendBuf))->m_mucAuthenticator,
					sizeof(((SRadiusHeader*)pmucData)->m_mucAuthenticator));
				break;
		}

		/*	Добавляем секретный ключ
		 */
		memcpy(
			&(pmucData[p_uiDataLen]),
			(unsigned char*)m_psoCoASrvr->m_mcSecret,
			strlen(m_psoCoASrvr->m_mcSecret));
		p_uiDataLen += strlen(m_psoCoASrvr->m_mcSecret);

		md5::md5_context soMD5Context;
		unsigned char mcDidgest[16];

		md5::md5_starts (&soMD5Context);
		md5::md5_update (&soMD5Context, pmucData, p_uiDataLen);
		md5::md5_finish (&soMD5Context, mcDidgest);

		if (p_bWriteResult) {
			memcpy (p_psoRadHdr->m_mucAuthenticator, mcDidgest, sizeof(p_psoRadHdr->m_mucAuthenticator));
		} else if (0 == memcmp (mcDidgest, p_psoRadHdr->m_mucAuthenticator, sizeof(p_psoRadHdr->m_mucAuthenticator))) {
				bRetVal = true;
		} else {
			bRetVal = false;
		}

	} while (0);

	if (pmucData) {
		free (pmucData);
	}

	return bRetVal;
}

int CRadiusClient::ParsePacket (unsigned char *p_pucBuf, char *p_pszOut, int *p_iLen)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'CRadiusClient::ParsePacket'");
	}
	int iRetVal = 0;
	SRadiusHeader *psoRadiusHdr;
	unsigned int uiPackLen;
	int iFnRes;

	psoRadiusHdr = (SRadiusHeader*)p_pucBuf;

	uiPackLen = GetPackLen (p_pucBuf);

	do {
		iFnRes = sprintf (&(p_pszOut[*p_iLen]), "Request code: %u\n", psoRadiusHdr->m_ucCode);
		if (0 < iFnRes) {
			*p_iLen += iFnRes;
		}

		iFnRes = sprintf (&(p_pszOut[*p_iLen]), "Packet identifier: %u\n", psoRadiusHdr->m_ucIdentifier);
		if (0 < iFnRes) {
			*p_iLen += iFnRes;
		}

		iFnRes = sprintf (&(p_pszOut[*p_iLen]), "Packet length: %u\n", ntohs (psoRadiusHdr->m_usLength));
		if (0 < iFnRes) {
			*p_iLen += iFnRes;
		}

		iFnRes = sprintf (&(p_pszOut[*p_iLen]), "Packet authentificator: ");
		if (0 < iFnRes) {
			*p_iLen += iFnRes;
		}

		for (int i = 0; i < sizeof(psoRadiusHdr->m_mucAuthenticator); ++i) {
			iFnRes = sprintf (&(p_pszOut[*p_iLen]), "%02x", psoRadiusHdr->m_mucAuthenticator[i]);
			if (0 < iFnRes) {
				*p_iLen += iFnRes;
			} else {
				break;
			}
		}

		iFnRes = sprintf (&(p_pszOut[*p_iLen]), "\n");
		if (0 < iFnRes) {
			*p_iLen += iFnRes;
		}

		unsigned char *pucEnumAttr = NULL;
		char mcEnumAttrName[1024];
		char mcEnumAttrVal[2048];
		unsigned char ucAttrType;
		EAttrDataType eAttrDataType;
		unsigned int uiAttrLen;
		unsigned int uiVendId;
		unsigned char ucVendType;

		while ((pucEnumAttr = EnumAttr (p_pucBuf, pucEnumAttr, mcEnumAttrName, mcEnumAttrVal, &ucAttrType, &uiAttrLen, &uiVendId, &ucVendType))) {
			// выводим имя атрибута
			iFnRes = sprintf (&(p_pszOut[*p_iLen]), "%s: ", mcEnumAttrName);
			if (0 < iFnRes) {
				*p_iLen += iFnRes;
			}
			eAttrDataType = msoAttrDetails[ucAttrType].m_eAttrType;
			switch (eAttrDataType) {
			case eADT_Password:
			case eADT_String:
			case eADT_Number:
			case eADT_IpAddress:
				iFnRes = sprintf (&(p_pszOut[*p_iLen]), "type: '%u'; value: ", (unsigned int) ucAttrType);
				if (0 < iFnRes) {
					*p_iLen += iFnRes;
				}
				memcpy (&(p_pszOut[*p_iLen]), mcEnumAttrVal, uiAttrLen);
				*p_iLen += uiAttrLen;
				break;
			case eADT_VSA:
				iFnRes = sprintf (&(p_pszOut[*p_iLen]), "Vendor id: '%u' type: '%u' len: '%u'; value: ", uiVendId, (unsigned int) ucVendType, (unsigned int) uiAttrLen);
				if (0 < iFnRes) {
					*p_iLen += iFnRes;
				}
				for (int i = 0; i < uiAttrLen; ++i) {
					if (0x20 <= mcEnumAttrVal[i] && 0x7F > mcEnumAttrVal[i]) {
						p_pszOut[*p_iLen] = mcEnumAttrVal[i];
						++ (*p_iLen);
					} else {
						iFnRes = sprintf (&(p_pszOut[*p_iLen]), "[%02x]", (unsigned int) mcEnumAttrVal[i]);
						if (0 < iFnRes) {
							*p_iLen += iFnRes;
						} else {
							break;
						}
					}
				}
				break;
			default:
				break;
			}

			iFnRes = sprintf (&(p_pszOut[*p_iLen]), "\n");
			if (0 < iFnRes) {
				*p_iLen += iFnRes;
			}
		}
	} while (0);


	return iRetVal;
}

int CRadiusClient::RecvCoASrvrResp (int p_iReqId)
{
	if (1 == g_uiDebug) {
		g_coLog.WriteLog ("debug 1: enter to 'CRadiusClient::RecvCoASrvrResp'");
	}
	int iRetVal = 0;
	int iFnRes;

	pollfd soPollFD;
	char mcBuf[0x2000];
	char mcParsedPack[0x2000];
	int iParsPackLen;
	char mcMsg[0x2000];
	int iMsgLen;
	int iErr;
	char mcErr[2048];
	char mcIpAddr[32];

	do {
		/* инициализация структуры для вызова функции poll */
		soPollFD.fd = m_msoPackQueue[p_iReqId].m_iCoASrvrSock;
		soPollFD.events = POLLIN;

		/* Проверяем наличие данных для чтения */
		iFnRes = poll (&soPollFD, 1, m_iRequestTimeout * 1000);

		/* Если состояние сокетов не изменилось завершаем обработку */
		if (0 > iFnRes) {
			iErr = errno;
			if (strerror_r (iErr, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("CRadiusClient: RecvCoASrvrResp: poll error code: '%d': '%s'", iErr, mcErr);
			break;
		}
		/* если исетекло время ожидания */
		if (0 == iFnRes) {
			g_coLog.WriteLog ("CRadiusClient: RecvCoASrvrResp: poll error: 'timed out': CoA-server: '%s': request id: '%d': ", m_psoCoASrvr->m_mcCoASrvr, p_iReqId);
			iRetVal = -1;
			break;
		}

		sockaddr_in m_soFrom;
		socklen_t stSockAddrLen;

		stSockAddrLen = sizeof(m_soFrom);
		iFnRes = recvfrom (m_msoPackQueue[p_iReqId].m_iCoASrvrSock, mcBuf, sizeof (mcBuf), 0, (sockaddr*) &m_soFrom, &stSockAddrLen);
		if (0 == iFnRes) {
			g_coLog.WriteLog ("CRadiusClient: RecvCoASrvrResp: 'recvfrom' returns '0'");
			iRetVal = -1;
			break;
		}
		if (-1 == iFnRes) {
			iErr = errno;
			if (strerror_r (iErr, mcErr, sizeof(mcErr) - 1)) {
				*mcErr = 0;
			}
			g_coLog.WriteLog ("CRadiusClient: RecvCoASrvrResp: 'recvfrom' error occurred: code: '%d'; descr: '%s'", iErr, mcErr);
			iRetVal = -1;
			break;
		}

		SRadiusHeader *psoRadHdr;

		psoRadHdr = (SRadiusHeader*)mcBuf;

		iParsPackLen = 0;

		iParsPackLen += sprintf(
			mcParsedPack,
			"CRadiusClient: RecvCoASrvrResp: ");

		// Если пакета нет в очереди или ожидается пакет с другим идентификатором
		if (! m_msoPackQueue[p_iReqId].m_vbIsUsed || p_iReqId != psoRadHdr->m_ucIdentifier) {
			iParsPackLen += sprintf(
				&(mcParsedPack[iParsPackLen]),
				"Unexpected ");
			iRetVal = -1;
		}
		my_inet_ntoa_r (m_soFrom.sin_addr, mcIpAddr, sizeof (mcIpAddr));
		iParsPackLen += sprintf(
			&(mcParsedPack[iParsPackLen]),
			"packed received from '%s:%u':\n",
			mcIpAddr,
			ntohs (m_soFrom.sin_port));
		ParsePacket(
			(unsigned char*)mcBuf,
			mcParsedPack,
			&iParsPackLen);
		g_coLog.Dump (mcParsedPack);
		/* после всех проверок копируем содержимое пакета в буфер */
		if (0 == iRetVal) {
			memcpy (m_msoPackQueue[p_iReqId].m_mucRecvBuf, mcBuf, iFnRes);
			m_msoPackQueue[p_iReqId].m_usRecvDataLen = iFnRes;
		}
	} while (0);

	return iRetVal;
}
