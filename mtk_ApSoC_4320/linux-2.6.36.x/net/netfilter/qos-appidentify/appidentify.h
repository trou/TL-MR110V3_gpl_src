/*! Copyright(c) 2008-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     appidentify.h
 *\brief
 *\details
 *
 *\author   Yan Wei
 *\version  0.0.1
 *\date     27Sep13
 *
 *\warning
 *
 *\history \arg 0.0.1, 27Sep13, Yan Wei, Create the file.
 */
#ifndef __APPIDENTIFY_H__
#define __APPIDENTIFY_H__
/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_app.h>
#include <linux/skbuff.h>

#include "appidentify_id.h"
#include "appidentify_rules.h"
#include "appidentify_node.h"
#include "appidentify_utils.h"

/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
extern int appidntf_debug;

#define     APPIDNTF_ERROR(fmt, args...)  printk("ERROR[%s:%d] "fmt, __FUNCTION__, __LINE__, ##args)

#define     APPIDNTF_DEBUG(fmt, args...)                                    \
            do                                                              \
            {                                                               \
                if (1 == appidntf_debug)                                    \
                {                                                           \
                    printk("DEBUG[%s:%d] "fmt, __FUNCTION__, __LINE__, ##args);  \
                }                                                           \
            }while(0)

typedef int (*FP_HANDLE)(struct sk_buff *, struct nf_conntrack_app *,
                           void *, unsigned char *, unsigned int);

/*!
*\struct  _APPIDNTFY_PKT_TUPLE
*\brief   The tuple with four element.
*\details elements:source ip\source port\dest ip\dest port.
*/
typedef struct _APPIDNTFY_PKT_TUPLE
{
    unsigned int   srcip;                  /*! ԴIP */
    unsigned short  srcport;                /*! Դ�˿� */
    unsigned int   dstip;                  /*! Ŀ��IP */
    unsigned short  dstport;                /*! Ŀ�Ķ˿� */
}APPIDNTFY_PKT_TUPLE;

/*!
*\typedef FP_HANDLE_INFO
*\brief   Hard code application struct.
*/
typedef struct _FP_HANDLE_INFO
{
    int                     appId;               /*!< application ID */
    APPIDNTFY_PKT_TUPLE     tuple;               /*!< 4-tuple */
    int                     proto;               /*!< protocol */
    FP_HANDLE               hard_code_ptr[IP_CT_DIR_MAX];       /*!< hard code method */
} FP_HANDLE_INFO;

/*!
*\typedef   APPIDNTFY_FEATURE
*\brief ���ӵ�����������Ϣ��
*/
typedef struct _APPIDNTFY_FEATURE
{
    int enable;         /*! ���������Ƿ���Ч  */
    int pkt_start;      /*! ��������ʼ�İ�, ��ֵ��Ϊ-1ʱ����ʾ������������м�ĳ��
                        ��pkt_end��ʾ���ȣ����ݰ���  */
    int pkt_end;        /*! ����������İ�, ����pkt_start��Ϊ-1ʱ����ʾ���������
                        ���м�ĳ�Σ�pkt_end��ʾ���ȣ����ݰ��� */
    unsigned short packetLen;      /*! �����ص���С����,��ȷ����ʱ��,����Ϊ0 */
    unsigned short inspLen;    /* new add for  */

    int (*fpHandle)       (struct sk_buff *, struct nf_conntrack_app *,
                           void *, unsigned char *, unsigned int);   /*!< �����봦���� */
    int (*hardCodeHandle) (struct sk_buff *, struct nf_conntrack_app *,
                           void *, unsigned char *, unsigned int);    /*!< Ӳ������������ reserved */
    void                    *pDpiCode;
}APPIDNTFY_FEATURE;

/*!
*\struct  _APPIDNTFY_KER_RULE
*\brief   Application define by four elements.
*\details
*/
typedef struct _APPIDNTFY_KER_RULE
{
    int                         appId;                  /*!< ����,���õ�ֵ��Ҫ����ENUM_APP_ID�еĶ��� */
    int                         protocol;               /*!< ���ݰ���Э�� */
    APPIDNTFY_PKT_TUPLE         tuple;                  /*!< ��Ԫ����Ϣ */
    unsigned short              mask;                   /*!< ��Ч������ */
    unsigned short              count;                  /*!< ��Ч�ĸ��� */
    APPIDNTFY_NODE              hashNode[APPIDNTFY_TUPLE_INDEX_MAX];/*!< ��ϣ�б�Ľڵ�ָ�� */
    APPIDNTFY_FEATURE           feature[IP_CT_DIR_MAX];    /*!< ���������������  */
}APPIDNTFY_KER_RULE;
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/
int  appidentify_dpi_init(void);
void appidentify_dpi_fini(void);



#endif  /* __APPIDENTIFY_H__ */
