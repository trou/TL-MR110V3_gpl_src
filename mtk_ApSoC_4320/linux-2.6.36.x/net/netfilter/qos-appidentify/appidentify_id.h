/*! Copyright(c) 2008-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     appidentify_id.h
 *\brief
 *\details
 *
 *\author   Yan Wei
 *\version  0.0.1
 *\date     08Oct13
 *
 *\warning
 *
 *\history \arg 0.0.1, 08Oct13, Yan Wei, Create the file.
 */
#ifndef __APPIDENTIFY_ID_H__
#define __APPIDENTIFY_ID_H__
/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
#include "appidentify_rules.h"

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
#define APPIDNTFY_APP_ID_DATA_COUNT       4
#define APPIDNTFY_APP_MAX_COUNT           (32 * APPIDNTFY_APP_ID_DATA_COUNT)
#define APP_ID_MAX = 4096                     /* ���֧��Ӧ�ø���������4096 */

#define IS_PROXY_ID_VALID(proxyId)      (((proxyId) > PROXY_ID_UNKNOWN) && ((proxyId) < PROXY_ID_MAX))

#define IS_APP_ID_DOUBLE_DIR(appId)     (appId & 0x8000)

#define APP_ID_DIR_SET(appId)           ((~appId + 1) | 0x8000)
#define APP_ID_VALUE_GET(appId)         ((~appId + 1) & 0x7FFF)

#define APP_ID_DIR_MASK(appId, dir)     ((0 == (dir))?(appId):((~appId + 1) | 0x8000))

#define APP_NORMAL_ID_SET(appId, value) (appId) = ((value) & 0x0FFF) | ((appId) & 0xF000)
#define APP_BASIC_ID_FLAG_SET(appId, value)  (appId) = (((value) & 0xF000) | ((appId) & 0x0FFF))
#define APP_BASIC_ID_VALUE_SET(appId, value)    \
        (appId) = (((((value) - APPMNGR_APPID_BASIC_NONE) << 12) & 0xF000) | ((appId) & 0x0FFF))
#define APP_NORMAL_ID_GET(appId)        (short)((appId)&0x0FFF)
#define APP_BASIC_ID_VALUE_GET(appId)   (short)((((appId)&0xF000) >> 12) + APPMNGR_APPID_BASIC_NONE)
#define APP_BASIC_ID_FLAG_GET(appId)    (short)((appId)&0xF000)

#define APP_BASIC_ID_UNKNOWN            (short)0xF000
#define APP_BASIC_ID_CHECKING           (short)0xE000

#define APP_NORMAL_ID_UNKNOWN           (short)0x0FFF
#define APP_NORMAL_ID_CHECKING          (short)0x0FFE

#define APP_ID_CHECKING                 (short)(APP_BASIC_ID_CHECKING | APP_NORMAL_ID_CHECKING)

#define APP_ID_GET(appId, ruleId) \
    do { \
            if (IS_BASIC_APP(ruleId)) \
            { \
                appId = APP_BASIC_ID_VALUE_GET(appId); \
            } \
            else \
            { \
                appId = APP_NORMAL_ID_GET(appId); \
            } \
        }while(0);

#define APP_ID_SET_BY_VALUE(appId, value) \
        do { \
            if (IS_BASIC_APP(value)) \
            { \
                APP_BASIC_ID_VALUE_SET(appId, value); \
            } \
            else \
            { \
                APP_NORMAL_ID_SET(appId, value); \
            } \
        }while(0);

#define APP_ID_SET_BY_RULE(appId, value, ruleId) \
        do { \
            if (IS_BASIC_APP(ruleId)) \
            { \
                APP_BASIC_ID_VALUE_SET(appId, value); \
            } \
            else \
            { \
                APP_NORMAL_ID_SET(appId, value); \
            } \
        }while(0);

#define APP_ID_SET_FLAG(appId,ruleId,value) \
        do { \
            if (IS_BASIC_APP(ruleId)) \
            { \
                appId = (value+1) << 12 | ((appId)&0x0FFF)); \
            } \
            else \
            { \
                APP_NORMAL_ID_SET(appId, value); \
            } \
        }while(0);


#define IS_RANDOM_PORT_RULE(mask) (APPIDNTFY_MASK_RANDOM_PORT == ((mask) & APPIDNTFY_MASK_RANDOM_PORT))
#define IS_BASIC_APP(appID)     (((appID) >= APPMNGR_APPID_BASIC_BEGIN) && ((appID) <= APPMNGR_APPID_BASIC_END))
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/
/*!
 *\typedef  APPIDNTFY_APP_INDEX
 *\brief    The prototype of the enum _APPIDNTFY_APP_INDEX
 */
typedef enum _APPIDNTFY_APP_INDEX
{
    APP_ID_UNKNOWN  = (-1),         /*!< δ֪�ĵ�Ӧ�� */
    APP_ID_QQ       = ( 0 ),        /*!< QQ �ͻ��� */
    APP_ID_WEBQQ  = 1,              /*!< Web QQ */
    APP_ID_MSN = 2,                 /*!< MSN �ͻ��� */
    APP_ID_FETION,                  /*!< ���� */
    APP_ID_ALIIM,                   /*!< �������� */
    APP_ID_SKYPE,                   /*!< skype */
    APP_ID_THUNDER,                 /*!< Ѹ�� �ͻ��� */
    APP_ID_BITTORRENT,              /*!< ��������  26Nov10*/
    APP_ID_EMULE,                   /*!< ��¿  26Nov10*/
    APP_ID_QQLIVE = 9,
    APP_ID_PPSTREAM,                /*!< PPTV  26Nov10*/
    APP_ID_PPTV,                    /*!< PPTV  26Nov10*/
    APP_ID_THS,                     /*!< ͬ��˳ */
    APP_ID_DZH,                     /*!< ���ǻ� */
    APP_ID_QIANLONG,                /*!< Ǯ��  26Nov10*/
    APP_ID_ZNZ,
    APP_ID_ZQZX,                    /*!< ֤ȯ֮��  26Nov10*/

    //APP_ID_ZSZQ,                    /*!< ������㷢֤ȯ  26Nov10*/
    APP_ID_SPF = 17,                /* ��ϷС���� */
    APP_ID_QQ_GAME = 18,            /*!< QQ��Ϸ����  26Nov10*/
    APP_ID_XUNLEI_GAME,             /*!< Ѹ����Ϸ  26Nov10*/
    APP_ID_OURGAME,                 /*!<��������  26Nov10*/
    APP_ID_HF_GAME,                 /*!< �Ʒ�ƽ̨  26Nov10*/
    APP_ID_DREAM_GAME,              /*!< �λ�����  26Nov10*/
    APP_ID_WARCRAFT,                /*!< ħ������  26Nov10*/
    APP_ID_KATING,                  /*!< ���ܿ�����  26Nov10*/
    APP_ID_KXFARM,                  /*!< ����ũ��  26Nov10*/
    APP_ID_QQ_FARM,                 /*!< QQũ��  26Nov10*/
    APP_ID_QQ_PARKER,               /*!< QQũ��  26Nov10*/
    APP_ID_QQ_WEBGAME,              /*!< QQ��ҳ��Ϸ  26Nov10*/

    APP_ID_XUNLEIKANKAN,


    APP_ID_TM = 38,                 /*!< ��ѶTM��by Zhang Jian, 22Mar12 */
    APP_ID_YY = 39,
    APP_ID_QQXF = 40,               /*!< QQ����, by Zhang Jian, 27Mar12 */
    APP_ID_FLASHGET,
    APP_ID_VAGAA = 42,              /*!< VAGAA,  by Zhang Jian, 27Mar12 */

    APP_ID_KUAIBO,
    APP_ID_FX,
    APP_ID_PIPITV,
    APP_ID_UUSEE,
    APP_ID_CNTV,

    APP_ID_KUGOU = 48,
    APP_ID_KUWO,
    APP_ID_QQMUSIC,
    APP_ID_QQJT,

    APP_ID_DFCFT = 56,              /*!< �����Ƹ�ͨ��by Zhang Jian, 22Mar12 */

    APP_ID_PROXY = 60,              /*!< ���� */

    APP_ID_YKTD = APPMNGR_APPID_PRI_BEGIN,
    APP_ID_TXVIDEO,
    APP_ID_XLLX,
    APP_ID_IQIYI,
    APP_ID_LETV,
    APP_ID_SOHUVIDEO,
    APP_ID_SIP,
    APP_ID_PPTC,
    APP_ID_H323,
    APP_ID_SMTP,
    APP_ID_POP3,
    APP_ID_HTTPFD,
    APP_ID_FTP,
    APP_ID_PPTP,
    APP_ID_L2TP,
    APP_ID_IPSEC,
    APP_ID_IMAP,

    /* temp for test */
    APP_ID_XL_OTHERS = APPMNGR_APPID_PRI_BEGIN + 100,
    APP_ID_VIDEO_ONLINE,


    APP_ID_CLSF_XL = APPMNGR_APPID_CLSF_BEGIN,
    APP_ID_CLSF_BT,
    APP_ID_CLSF_EMULE,
    APP_ID_CLSF_PPS,
    APP_ID_CLSF_PPTV,
    APP_ID_CLSF_FLASHGET,
    APP_ID_CLSF_XF,
    APP_ID_CLSF_QQMUSIC,
    APP_ID_CLSF_KUGOU,
    APP_ID_CLSF_VOICE,
    APP_ID_CLSF_FLASHP2P,

    APP_ID_QQ_PRIVATE = APPMNGR_APPID_SPECIAL_BEGIN,                /*!< ��ȨQQ���� */
    APP_ID_QQ_CHECKING,             /*!< ����֮��QQ���봦��δ֪״̬����Ҫ��һ��ƥ���ʱ��ſ��ж��Ƿ�Ϊ��Ȩ���� */
    APP_ID_SKYPE_CHECKING,                   /*!< skype */

    APP_ID_HTTP   = APPMNGR_APPID_BASIC_BEGIN,
    APP_ID_HTTP_POST,
    APP_ID_HTTPS,
    APP_ID_MMS,
    APP_ID_RSTP,
    APP_ID_DNS
}APPIDNTFY_APP_INDEX;

/*  by jyc, 24Dec10 */
/*!
 *\typedef  APPIDNTFY_AGENT_INDEX
 *\brief    The prototype of the enum _APPIDNTFY_AGENT_INDEX
 */
typedef enum _APPIDNTFY_PROXY_INDEX
{
    PROXY_ID_CHECKING  = ( -2 ),        /*!< ��ʾ�в�ȷ���������  */
    PROXY_ID_UNKNOWN = ( -1 ),          /*!< ����Ҫ�ô��� */
    PROXY_ID_HTTP       = ( 1 ),        /*!< HTTP���� */
    PROXY_ID_HTTP_CONNECT,              /*!< HTTP���Ӵ���Э����˿ڵ�ַ֮�󣬺������ĸ�����Ӧ��ʶ����ͬ */
    PROXY_ID_SOCK4,                 /*!< SOCK4 */
    PROXY_ID_SOCK5_TCP,                 /*!< SOCK5 */
    PROXY_ID_SOCK5_UDP,                 /*!< SOCK5 */
    PROXY_ID_MAX                        /*!< ����ĸ��� ��ֵ����ܳ��� (APPIDNTFY_APP_MAX_COUNT)*/
}APPIDNTFY_PROXY_INDEX;

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/



#endif  /* __APPIDENTIFY_ID_H__ */
