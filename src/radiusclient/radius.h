#ifndef _RADIUS_H
#define _RADIUS_H


struct SPackQueueElem {
	volatile bool m_vbIsUsed;
	unsigned char m_mucSendBuf[0x2000];
	unsigned char m_mucRecvBuf[0x2000];
	unsigned short m_usRecvDataLen;
	int m_iCoASrvrSock;
};


struct SRadiusHeader;


/*	Заголовок RADIUS-атрибута
 */
#pragma pack(push,1)
typedef struct {
	unsigned char m_ucType;
	unsigned char m_ucLength;
	unsigned char m_mucValue[1];
} SRadiusAttribute;
#pragma pack(pop)


struct SSrvParam;

class CRadiusClient {
public:
	/*	Конструкторы и деструктор
	 */
	CRadiusClient (SSrvParam *p_psoCoASrvr, int p_iReqTimeout);
	~CRadiusClient();

public:
	int Init ();
	int DeInit ();
	/*	Создает новый пакет,
	 *	выдает его идентификатор
	 */
	unsigned int GetNewId (unsigned char p_ucCode);
	/*	Добавляет к пакету новый атрибут
	 */
	int AddAttr(
		unsigned int p_uiReqId,
		SRadiusAttribute *p_psoRadiusAttr);
	/*	Инициирует посылку пакета
	 *	и ожидает поступление ответа
	 */
	int SendPack(
		unsigned int p_uiReqId,
		char *p_pszCoAServerIp,
		unsigned short p_usCoAServerPort,
		unsigned char *p_pmucRecvBuf,
		unsigned int *p_puiBufSize,
		char* p_pmcRem);
	/*	Перечисление атрибутов пакета RADIUS */
	unsigned char* EnumAttr(
		unsigned char* p_pucRadPack, /* указатель на буфер, содержащий исходный радиус-пакет */
		unsigned char* p_pucLastAttr, /* указатель на последний полученный атрибут */
		char *p_pszAttrName, /* имя атрибута */
		char *p_pszAttrValue, /* значение атрибута */
		unsigned char *p_pucAttrType, /* тип атрибута */
		unsigned int *p_uiAVLen, /* длина значения атрибута */
		unsigned int *p_uiVendorId, /* идентификатор вендора для атрибута VSA */
		unsigned char *p_ucVendorType); /* подтип атрибута, определеный вендором */
	/*	Освобождает занятые пакетом ресурсы
	 */
	void ReleaseId (unsigned char p_ucPackId);

private:
	volatile unsigned int m_uiLastPackId;
	SPackQueueElem m_msoPackQueue[0x100];
	volatile bool m_vbContSend;
	volatile bool m_vbContRecv;
	SSrvParam *m_psoCoASrvr;
	int m_iRequestTimeout;
	pthread_mutex_t m_mMutexGetId;

private:
	int CreateCoASrvrSock ();
	/* Длина пакета */
	unsigned int GetPackLen (unsigned char* p_pucRadPack);
	/*	Длина атрибута
	 */
	unsigned int GetAttrLen (unsigned char* p_pucRadAttr);
	/*	Проверка аутентификатора
	 *	если параметр p_bWriteResult равен true,
	 *	то в заголовок пакета p_psoRadHdr записывается
	 *	правильный аутентификатор
	 */
	bool CheckAuthenticator (SRadiusHeader* p_psoRadHdr, unsigned int p_uiDataLen, bool p_bWriteResult = false);
	/*	Парсинг пакета RADIUS
	 */
	int ParsePacket(
		unsigned char *p_pucBuf,
		char *p_pszOut,
		int *p_iLen);
	int RecvCoASrvrResp (int p_iReqId);
};


/*	Заголовок RADIUS-пакета
 */
#pragma pack(push,1)
struct SRadiusHeader {
	unsigned char m_ucCode;					// код запроса
	unsigned char m_ucIdentifier;			// идентификатор запроса
	unsigned short m_usLength;				// длина пакета
	unsigned char m_mucAuthenticator[16];	// аутентификатор
	SRadiusAttribute m_msoAttributes[1];	// массив атрибутов
};
#pragma pack(pop)


/*	Перечисление типов RADIUS-атрибутов
 */
enum EAttrDataType {
	eADT_Unused = 0,	// не используется
	eADT_Number = 1,	// число
	eADT_String = 2,	// строка
	eADT_Password = 3,	// CHAP-пароль
	eADT_IpAddress = 4,	// ip-адрес
	eADT_VSA = 26		// VSA-атрибут
};


/*	Описание струкуры,
 *	описывающей основные параметры RADIUS-атрибута
 */
struct SRadiusAttrDetails {
	char m_mcAttrName[64];			// attr name
	unsigned char m_ucLength;		// attr length
	unsigned char m_ucMinLength;	// attr min length
	unsigned char m_ucMaxLength;	// attr max length
	EAttrDataType m_eAttrType;		// attr type
};

static const SRadiusAttrDetails msoAttrDetails[] =
{
	{"Unused",							0,  0,  0,  eADT_Unused},		//   0
	{"User-Name",						0,  3,  0,  eADT_String},		//   1
	{"User-Password",					0,  18, 130,eADT_Password},		//   2
	{"CHAP-Password",					19, 0,  0,  eADT_Password},		//   3
	{"NAS-IP-Address",					6,  0,  0,  eADT_IpAddress},	//   4
	{"NAS-Port",						6,  0,  0,  eADT_Number},		//   5
	{"Service-Type",					6,  0,  0,  eADT_Number},		//   6
	{"Framed-Protocol",					6,  0,  0,  eADT_Number},		//   7
	{"Framed-IP-Address",				6,  0,  0,  eADT_IpAddress},	//   8
	{"Framed-IP-Netmask",				6,  0,  0,  eADT_IpAddress},	//   9
	{"Framed-Routing",					6,  0,  0,  eADT_Number},		//  10
	{"Filter-Id",						0,  3,  0,  eADT_String},		//  11
	{"Framed-MTU",						6,  0,  0,  eADT_Number},		//  12
	{"Framed-Compression",				6,  0,  0,  eADT_Number},		//  13
	{"Login-IP-Host",					6,  0,  0,  eADT_IpAddress},	//  14
	{"Login-Service",					6,  0,  0,  eADT_Number},		//  15
	{"Login-TCP-Port",					6,  0,  0,  eADT_Number},		//  16
	{"Unassigned",						0,  0,  0,  eADT_Unused},		//  17
	{"Reply-Message",					0,  3,  0,  eADT_String},		//  18
	{"Callback-Number",					0,  3,  0,  eADT_String},		//  19
	{"Callback-Id",						0,  3,  0,  eADT_String},		//  20
	{"Unassigned",						0,  0,  0,  eADT_Unused},		//  21
	{"Framed-Route",					0,  3,  0,  eADT_String},		//  22
	{"Framed-IPX-Network",				6,  0,  0,  eADT_Number},		//  23
	{"State",							0,  3,  0,  eADT_String},		//  24
	{"Class",							0,  3,  0,  eADT_String},		//  25
	{"Vendor-Specific",					0,  7,  0,  eADT_VSA},			//  26
	{"Session-Timeout",					6,  0,  0,  eADT_Number},		//  27
	{"Idle-Timeout",					6,  0,  0,  eADT_Number},		//  28
	{"Termination-Action",				6,  0,  0,  eADT_Number},		//  29
	{"Called-Station-Id",				0,  3,  0,  eADT_String},		//  30
	{"Calling-Station-Id",				0,  3,  0,  eADT_String},		//  31
	{"NAS-Identifier",					0,  3,  0,  eADT_String},		//  32
	{"Proxy-State",						0,  3,  0,  eADT_String},		//  33
	{"Login-LAT-Service",				0,  3,  0,  eADT_String},		//  34
	{"Login-LAT-Node",					0,  3,  0,  eADT_String},		//  35
	{"Login-LAT-Group",					0,  3,  0,  eADT_String},		//  36
	{"Framed-AppleTalk-Link",			6,  0,  0,  eADT_Number},		//  37
	{"Framed-AppleTalk-Network",		6,  0,  0,  eADT_Number},		//  38
	{"Framed-AppleTalk-Zone",			0,  3,  0,  eADT_String},		//  39
	{"Acct-Status-Type",				6,  0,  0,  eADT_Number},		//  40
	{"Acct-Delay-Time",					6,  0,  0,  eADT_Number},		//  41
	{"Acct-Input-Octets",				6,  0,  0,  eADT_Number},		//  42
	{"Acct-Output-Octets",				6,  0,  0,  eADT_Number},		//  43
	{"Acct-Session-Id",					0,  3,  0,  eADT_String},		//  44
	{"Acct-Authentic",					6,  0,  0,  eADT_Number},		//  45
	{"Acct-Session-Time",				6,  0,  0,  eADT_Number},		//  46
	{"Acct-Input-Packets",				6,  0,  0,  eADT_Number},		//  47
	{"Acct-Output-Packets",				6,  0,  0,  eADT_Number},		//  48
	{"Acct-Terminate-Cause",			6,  0,  0,  eADT_Number},		//  49
	{"Acct-Multi-Session-Id",			0,  3,  0,  eADT_String},		//  50
	{"Acct-Link-Count",					6,  0,  0,  eADT_Number},		//  51
	{"Acct-Input-Gigawords",			6,  0,  0,  eADT_Number},		//  52
	{"Acct-Output-Gigawords",			6,  0,  0,  eADT_Number},		//  53
	{"Unassigned",						0,  0,  0,  eADT_Unused},		//  54
	{"Event-Timestamp",					6,  0,  0,  eADT_Number},		//  55
	{"Egress-VLANID",					6,  0,  0,  eADT_Number},		//  56
	{"Ingress-Filters",					6,  0,  0,  eADT_Number},		//  57
	{"Egress-VLAN-Name",				0,  4,  0,  eADT_String},		//  58
	{"User-Priority-Table",				10,  0,  0, eADT_String},		//  59
	{"CHAP-Challenge",					0,  7,  0,  eADT_String},		//  60
	{"NAS-Port-Type",					6,  0,  0,  eADT_Number},		//  61
	{"Port-Limit",						6,  0,  0,  eADT_Number},		//  62
	{"Login-LAT-Port",					0,  3,  0,  eADT_String},		//  63
	{"Tunnel-Type",						6,  0,  0,  eADT_Number},		//  64
	{"Tunnel-Medium-Type",				6,  0,  0,  eADT_Number},		//  65
	{"Tunnel-Client-Endpoint",			0,  3,  0,  eADT_String},		//  66
	{"Tunnel-Server-Endpoint",			0,  3,  0,  eADT_String},		//  67
	{"Acct-Tunnel-Connection",			0,  3,  0,  eADT_String},		//  68
	{"Tunnel-Password",					0,  5,  0,  eADT_String},		//  69
	{"ARAP-Password",					18, 0,  0,  eADT_String},		//  70
	{"ARAP-Features",					16, 0,  0,  eADT_String},		//  71
	{"ARAP-Zone-Access",				6,  0,  0,  eADT_Number},		//  72
	{"ARAP-Security",					6,  0,  0,  eADT_Number},		//  73
	{"ARAP-Security-Data",				0,  3,  0,  eADT_String},		//  74
	{"Password-Retry",					6,  0,  0,  eADT_Number},		//  75
	{"Prompt",							6,  0,  0,  eADT_Number},		//  76
	{"Connect-Info",					0,  3,  0,  eADT_String},		//  77
	{"Configuration-Token",				0,  3,  0,  eADT_String},		//  78
	{"EAP-Message",						0,  3,  0,  eADT_String},		//  79
	{"Message-Authenticator",			18, 0,  0,  eADT_String},		//  80
	{"Tunnel-Private-Group-ID",			0,  3,  0,  eADT_String},		//  81
	{"Tunnel-Assignment-ID",			0,  3,  0,  eADT_String},		//  82
	{"Tunnel-Preference",				6,  0,  0,  eADT_Number},		//  83
	{"ARAP-Challenge-Response",			10, 0,  0,  eADT_String},		//  84
	{"Acct-Interim-Interval",			6,  0,  0,  eADT_Number},		//  85
	{"Acct-Tunnel-Packets-Lost",		6,  0,  0,  eADT_Number},		//  86
	{"NAS-Port-Id",						0,  3,  0,  eADT_String},		//  87
	{"Framed-Pool",						0,  3,  0,  eADT_String},		//  88
	{"CUI",								0,  3,  0,  eADT_String},		//  89
	{"Tunnel-Client-Auth-ID",			0,  3,  0,  eADT_String},		//  90
	{"Tunnel-Server-Auth-ID",			0,  3,  0,  eADT_String},		//  91
	{"NAS-Filter-Rule",					0,  3,  0,  eADT_String},		//  92
	{"Unassigned",						0,  0,  0,  eADT_Unused},		//  93
	{"Originating-Line-Info",			4,  0,  0,  eADT_String},		//  94
	{"NAS-IPv6-Address",				18, 0,  0,  eADT_String},		//  95
	{"Framed-Interface-Id",				10, 0,  0,  eADT_String},		//  96
	{"Framed-IPv6-Prefix",				20, 0,  0,  eADT_String},		//  97
	{"Login-IPv6-Host",					18, 0,  0,  eADT_String},		//  98
	{"Framed-IPv6-Route",				0,  3,  0,  eADT_String},		//  99
	{"Framed-IPv6-Pool",				0,  3,  0,  eADT_String},		// 100
	{"Error-Cause Attribute",			6,  3,  0,  eADT_Number},		// 101
	{"EAP-Key-Name",					0,  0,  0,  eADT_Unused},		// 102
	{"Digest-Response",					0,  0,  0,  eADT_Unused},		// 103
	{"Digest-Realm",					0,  0,  0,  eADT_Unused},		// 104
	{"Digest-Nonce",					0,  0,  0,  eADT_Unused},		// 105
	{"Digest-Response-Auth",			0,  0,  0,  eADT_Unused},		// 106
	{"Digest-Nextnonce",				0,  0,  0,  eADT_Unused},		// 107
	{"Digest-Method",					0,  0,  0,  eADT_Unused},		// 108
	{"Digest-URI",						0,  0,  0,  eADT_Unused},		// 109
	{"Digest-Qop",						0,  0,  0,  eADT_Unused},		// 110
	{"Digest-Algorithm",				0,  0,  0,  eADT_Unused},		// 111
	{"Digest-Entity-Body-Hash",			0,  0,  0,  eADT_Unused},		// 112
	{"Digest-CNonce",					0,  0,  0,  eADT_Unused},		// 113
	{"Digest-Nonce-Count",				0,  0,  0,  eADT_Unused},		// 114
	{"Digest-Username",					0,  0,  0,  eADT_Unused},		// 115
	{"Digest-Opaque",					0,  0,  0,  eADT_Unused},		// 116
	{"Digest-Auth-Param",				0,  0,  0,  eADT_Unused},		// 117
	{"Digest-AKA-Auts",					0,  0,  0,  eADT_Unused},		// 118
	{"Digest-Domain",					0,  0,  0,  eADT_Unused},		// 119
	{"Digest-Stale",					0,  0,  0,  eADT_Unused},		// 120
	{"Digest-HA1",						0,  0,  0,  eADT_Unused},		// 121
	{"SIP-AOR",							0,  0,  0,  eADT_Unused},		// 122
	{"Delegated-IPv6-Prefix",			0,  0,  0,  eADT_Unused},		// 123
	{"MIP6-Feature-Vector",				0,  0,  0,  eADT_Unused},		// 124
	{"MIP6-Home-Link-Prefix",			0,  0,  0,  eADT_Unused},		// 125
	{"Operator-Name",					0,  0,  0,  eADT_Unused},		// 126
	{"Location-Information",			0,  0,  0,  eADT_Unused},		// 127
	{"Location-Data",					0,  0,  0,  eADT_Unused},		// 128
	{"Basic-Location-Policy-Rules",		0,  0,  0,  eADT_Unused},		// 129
	{"Extended-Location-Policy-Rules",	0,  0,  0,  eADT_Unused},		// 130
	{"Location-Capable",				0,  0,  0,  eADT_Unused},		// 131
	{"Requested-Location-Info",			0,  0,  0,  eADT_Unused},		// 132
	{"Framed-Management-Protocol",		0,  0,  0,  eADT_Unused},		// 133
	{"Management-Transport-Protection",	0,  0,  0,  eADT_Unused},		// 134
	{"Management-Policy-Id",			0,  0,  0,  eADT_Unused},		// 135
	{"Management-Privilege-Level",		0,  0,  0,  eADT_Unused},		// 136
	{"PKM-SS-Cert",						0,  0,  0,  eADT_Unused},		// 137
	{"PKM-CA-Cert",						0,  0,  0,  eADT_Unused},		// 138
	{"PKM-Auth-Wait-Timeout",			0,  0,  0,  eADT_Unused},		// 139
	{"PKM-Cryptosuite-List",			0,  0,  0,  eADT_Unused},		// 140
	{"PKM-SAID",						0,  0,  0,  eADT_Unused},		// 141
	{"PKM-SA-Descriptor",				0,  0,  0,  eADT_Unused},		// 142
	{"PKM-Auth-Key",					0,  0,  0,  eADT_Unused},		// 143
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 144
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 145
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 146
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 147
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 148
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 149
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 150
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 151
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 152
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 153
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 154
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 155
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 156
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 157
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 158
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 159
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 160
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 161
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 162
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 163
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 164
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 165
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 166
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 167
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 168
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 169
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 170
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 171
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 172
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 173
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 174
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 175
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 176
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 177
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 178
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 179
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 180
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 181
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 182
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 183
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 184
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 185
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 186
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 187
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 188
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 189
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 190
	{"Unassigned",						0,  0,  0,  eADT_Unused},		// 191
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 192
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 193
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 194
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 195
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 196
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 197
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 198
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 199
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 200
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 201
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 202
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 203
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 204
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 205
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 206
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 207
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 208
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 209
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 210
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 211
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 212
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 213
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 214
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 215
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 216
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 217
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 218
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 219
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 220
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 221
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 222
	{"Experimental Use",				0,  0,  0,  eADT_Unused},		// 223
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 224
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 225
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 226
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 227
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 228
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 229
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 230
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 231
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 232
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 233
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 234
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 235
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 236
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 237
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 238
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 239
	{"Implementation Specific",			0,  0,  0,  eADT_Unused},		// 240
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 241
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 242
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 243
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 244
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 245
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 246
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 247
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 248
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 249
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 250
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 251
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 252
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 253
	{"Reserved",						0,  0,  0,  eADT_Unused},		// 254
	{"Reserved",						0,  0,  0,  eADT_Unused}		// 255
};

#endif
