/*! Copyright(c) 2008-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     appidentify_match_rules.c
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
/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
#include <linux/types.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netlink.h>
#include <linux/pcre/pcre.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/netfilter/nf_conntrack_app.h>

#include "appidentify.h"
#include "appidentify_id.h"
#include "appidentify_log.h"
#include "appidentify_rules.h"
#include "appidentify_match_rules.h"
#include "appidentify_hash_table.h"
#include "appidentify_proxy.h"

#include "appprio.h"
/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
#define ENABLE_APPIDNTFY_MODULE   (1)
#define MATCH_RULE_DEEP_DEBUG   APPIDNTF_DEBUG
#define DPI_MATCH_DEBUG(FLAG_NUM)           \
        do                                  \
        {                                   \
            if (g_debug_##FLAG_NUM)           \
            {                               \
                goto appidentify_out;       \
            }                               \
        }while(0)

extern unsigned short g_isAppidentifyInit;
extern unsigned short g_appidentifyCfgLock;
extern unsigned short g_appidentifyHookLock;
int g_enableDpi = TRUE;

int g_debug_0 = FALSE;
int g_debug_1 = FALSE;
int g_debug_2 = FALSE;
int g_debug_3 = FALSE;
int g_debug_4 = FALSE;
int g_debug_5 = FALSE;
int g_debug_6 = FALSE;
int g_debug_7 = FALSE;
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/
extern const int   APPIDNTFY_PROXY_RULE_COUNT;
extern APPIDNTFY_PROXY   appidentify_proxy_detector[];
extern APPIDNTFY_HEAD      (*hash_sub_tables)[APPIDNTFY_TUPLE_INDEX_MAX][APPIDNTFY_HASH_TABLE_LEN];
/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/
static void app_normal_id_set(short *appId, short value);
static short app_normal_id_get(short appId);
static void app_basic_id_value_set(short *appId, short value);
static void app_basic_id_flag_set(short *appId, short value);
static short app_basic_id_flag_get(short appId);
static short app_basic_id_flag_get(short appId);
static int is_app_basic_id_valid(short appId);
static int is_app_normal_id_valid(short appId);
static short app_basic_id_value_get(short appId);
/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/
unsigned short      g_isAppidentifyProxyInit         = TRUE;
unsigned short      g_isAppidentifyBasicInit         = TRUE;
unsigned short      g_isAppidentifyRandomInit        = TRUE;

APP_ID_OP_FUNC appBasicIdOpFunc =
{
    &app_basic_id_value_set,
    &app_basic_id_value_get,
    &app_basic_id_flag_set,
    &app_basic_id_flag_get,
    &is_app_basic_id_valid,
};

APP_ID_OP_FUNC appNormalIdOpFunc =
{
    &app_normal_id_set,
    &app_normal_id_get,
    &app_normal_id_set,
    &app_normal_id_get,
    &is_app_normal_id_valid,
};

static APP_ID_OP_FUNC *appIdOpFunc = &appNormalIdOpFunc;
/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/
static void app_normal_id_set(short *appId, short value)
{
    APP_NORMAL_ID_SET(*appId, value);
}

static short app_normal_id_get(short appId)
{
    return APP_NORMAL_ID_GET(appId);
}

static void app_basic_id_value_set(short *appId, short value)
{
    APP_BASIC_ID_VALUE_SET(*appId, value);
}

static short app_basic_id_value_get(short appId)
{
    return APP_BASIC_ID_VALUE_GET(appId);
}

static void app_basic_id_flag_set(short *appId, short value)
{
    APP_BASIC_ID_FLAG_SET(*appId, value);
}

static short app_basic_id_flag_get(short appId)
{
    return APP_BASIC_ID_FLAG_GET(appId);
}

static int is_app_basic_id_valid(short appId)
{
    APPIDNTF_DEBUG("\r\n");
    return ((APP_BASIC_ID_VALUE_GET(appId) >= APPMNGR_APPID_BASIC_BEGIN)
               && (APP_BASIC_ID_VALUE_GET(appId) <= APPMNGR_APPID_BASIC_END));
}

static int is_app_normal_id_valid(short appId)
{
    return ((APP_NORMAL_ID_GET(appId) >= APPMNGR_APPID_NORMAL_BEGIN)
    && (APP_NORMAL_ID_GET(appId) <= APPMNGR_APPID_NORMAL_END));

}

unsigned short l_matchTuplelWithMask(APPIDNTFY_PKT_TUPLE *t1, APPIDNTFY_PKT_TUPLE *t2,
    unsigned short mask)
{
    if (((mask & APPIDNTFY_MASK_SRC_IP) && (t1->srcip != t2->srcip))
        || ((mask & APPIDNTFY_MASK_SRC_PORT) && (t1->srcport != t2->srcport))
        || ((mask & APPIDNTFY_MASK_DST_IP) && (t1->dstip != t2->dstip))
        || ((mask & APPIDNTFY_MASK_DST_PORT) && (t1->dstport != t2->dstport)))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

static unsigned int l_matchDeepInspect(APPIDNTFY_KER_RULE *pEntry, struct sk_buff *skb,
                                       struct nf_conntrack_app *appinfo,
                                       int pktDir, void *cookie,
                                       unsigned char *data, unsigned int datalen)
{
    int iRet        = APP_ID_UNKNOWN;
    int off = 0;
    short appId;
    short appIdOri;
    short appIdReply;
    struct nf_conntrack_appidntfy *flag[IP_CT_DIR_MAX];
    struct iphdr      *iph;
    struct nf_conn    *ct;
    enum ip_conntrack_info ctinfo;
    struct nf_conn_counter *counter;
    struct nf_conntrack_app_ext *appidntify_ext;

    APPIDNTF_DEBUG("in\r\n");
    iph = ip_hdr(skb);
    if (NULL == iph || NULL == skb)
    {
        return APPIDNTFY_DI_UNKNOWN;
    }

    ct = nf_ct_get(skb, &ctinfo);
    flag[pktDir] = &appinfo->appidntfy_flag[pktDir];
    flag[1 - pktDir] = &appinfo->appidntfy_flag[1 -pktDir];
    if ((NULL == pEntry) || (NULL == ct))
    {
        return APPIDNTFY_DI_UNKNOWN;
    }

    counter = nf_conn_acct_find(ct);
    if (NULL == counter)
    {
        APPIDNTF_ERROR("counter null.\r\n");
        return APPIDNTFY_DI_UNKNOWN;
    }

    /* if cookie is null, means application dist .by jyc, 30Nov10 */
    if (NULL == cookie)
    {
        cookie = pEntry;
    }

    appidntify_ext = (struct nf_conntrack_app_ext *)appinfo->appidntfy_ext;
    if (NULL == appidntify_ext)
    {
        APPIDNTF_ERROR("appidntify_ext null.\r\n");
        return APPIDNTFY_DI_UNKNOWN;
    }
    MATCH_RULE_DEEP_DEBUG("Entry->appId = %d, pktDir %s, feature enable ORI %d, RLY %d, appid = 0x%x, appidReply = 0x%x, appinfo->proxy_id_index = %d\r\n",
                          pEntry->appId, pktDir == IP_CT_DIR_ORIGINAL ? "ORIGINAL" : "REPLY",
                          pEntry->feature[pktDir].enable, pEntry->feature[1 - pktDir].enable,
                          appinfo->appidntfy_flag[0].app_id_index, appinfo->appidntfy_flag[1].app_id_index,
                          appidntify_ext->proxy_id_index);

    /*!
    *   ������������ϲ�û����Ӧ�Ĺ�����Ϣ,����Ҫ���䷵��
    *
    */
    if (FALSE == pEntry->feature[pktDir].enable)
    {
        /*!
        *   �����һ������Ҳ��disable�Ļ�,����Ա��Ӧ���Ѿ�ʶ�������.
        *
        */

        if (FALSE == pEntry->feature[1 - pktDir].enable)
        {
            appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[pktDir].app_id_index), APP_ID_UNKNOWN);
            appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[1 - pktDir].app_id_index), APP_ID_UNKNOWN);
            /* ct->appidntfy_flag[pktDir].app_id_index = APP_ID_UNKNOWN; */
#if 0
            MATCH_RULE_DEEP_DEBUG("APPIDNTFY_DI_KNOWN \r\n@2INC  [%d] COUNT = %d, pkt->counter = %llu\r\n",
            pktDir,
            0,
            counter[pktDir].packets);
#endif
            return APPIDNTFY_DI_KNOWN;
        }
        else
        {
            /*!
            *   ��ʾ��ǰ��������ݰ���������ѭ,��Ҫ������������ݰ���ʶ����.
            *
            */
            /* MATCH_RULE_DEEP_DEBUG("#7 only this way disable\r\n"); */
            /* MATCH_RULE_DEEP_DEBUG("#9 other way index: %d\r\n", ct->appidntfy_flag[1-pktDir].app_id_index); */

            appId = appinfo->appidntfy_flag[1 - pktDir].app_id_index;

            /* ��ʶ�������Ӧ�ã�����ڸ�4λ����ʾʶ����ɡ�����Ӧ�õ�ʶ������У���Ȼֻ�ǿ�ǰ12λ���� */
            if (appIdOpFunc->is_app_id_valid(appId))
            {
                /*!
                *   ˵���Է��Ѿ�ʶ��ɹ���,
                *
                */
                MATCH_RULE_DEEP_DEBUG("#11 The another way is known! and Confirm it is known,  pIpHeader->id = %x\r\n",
                                      iph->id);
                appIdOpFunc->app_id_value_set(&(appinfo->appidntfy_flag[pktDir].app_id_index),
                                              appinfo->appidntfy_flag[1 - pktDir].app_id_index);

                return APPIDNTFY_DI_KNOWN;
            }
            else
            {
                /*!
                *   ����Է�û��ʶ��ɹ������ʾ�Է����ڼ���У���ô��������Ҳ���ڼ���С�
                *
                */
                MATCH_RULE_DEEP_DEBUG("#12 The another way is unknown! and Confirm it is unknown,  pIpHeader->id = %x\r\n",
                                       iph->id);
                return APPIDNTFY_DI_DISABLE;
            }
        }
    }

    /*!
    *   ��ʼ��������������ϵİ������������ļ��.
    *
    */
    /* ����Ǵ������ݴ�������������Ӧ�ñ��������������� by jyc, 10Nov10 */
#if APPIDNTFY_SUPPORT_PROXY
    if (IS_PROXY_ID_VALID(appidntify_ext->proxy_id_index))
    {
        off = appidentify_proxy_detector[appidntify_ext->proxy_id_index].offset;
        APPIDNTF_DEBUG("@5 ## off = %d! appidentify_proxy_detector[%d] = 0x%p\r\n",
                       off, appidntify_ext->proxy_id_index, &appidentify_proxy_detector[appidntify_ext->proxy_id_index]);
    }
#endif

    /*!
    *   ʶ�����λ�ñȽϡ�
    */
    if (pEntry->feature[pktDir].pkt_end > 0)
    {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
        if (counter[pktDir].packets > pEntry->feature[pktDir].pkt_end + off)
#else
        if (counter[pktDir].packets.counter > pEntry->feature[pktDir].pkt_end + off)
#endif
        {
			#if 0
            APPIDNTF_DEBUG("@4 ## OVER THE MAX POS! FINISH: UNKNOWN %llu/%d,  pIpHeader->id = %x!\r\n",
                counter[pktDir].packets,
                pEntry->feature[pktDir].pkt_end,
                iph->id);
			#endif
            return APPIDNTFY_DI_OVER;
        }
    }

    /*!
    *   ��pkt->start <0��ʱ�򣬱���ֻ���Ľ���λ�á�by jyc.    *  [4/29/2010]
    */
    if (pEntry->feature[pktDir].pkt_start > -1)
    {
        /*!
         *   δ����������İ���λ�á�
         */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
	if (counter[pktDir].packets < pEntry->feature[pktDir].pkt_start)
#else
        if (counter[pktDir].packets.counter < pEntry->feature[pktDir].pkt_start)
#endif
        {
			#if 0
            APPIDNTF_DEBUG("#1 Not Reach %llu < %d appid = %d  pIpHeader->id = %x\r\n",
                           counter[pktDir].packets, pEntry->feature[pktDir].pkt_start, pEntry->appId,  iph->id);
			#endif
			return APPIDNTFY_DI_NOT_REACH;
        }
    }

    /*!
    *   ����������⺯����
    *
    */

    if ( pEntry->feature[pktDir].fpHandle ||
         pEntry->feature[pktDir].hardCodeHandle)
    {
        if (NULL != pEntry->feature[pktDir].fpHandle)
        {
            /* ���ص�Ϊ�����ж����ID�� */
            //APPIDNTF_DEBUG("\r\n");
            iRet = pEntry->feature[pktDir].fpHandle(skb, appinfo, cookie, data, datalen);
            //APPIDNTF_DEBUG("iRet %d.\r\n", iRet);
        }

        if (NULL != pEntry->feature[pktDir].hardCodeHandle)
        {
            /* ��ν��������ʽ�������Ӳ���뺯������ */            
			APPIDNTF_DEBUG("hardCodeHandle!\r\n");
            iRet = pEntry->feature[pktDir].hardCodeHandle(skb, appinfo, cookie, data, datalen);
        }

        if ( APP_ID_UNKNOWN != iRet )
        {

            /*!
            *   ʶ��ɹ�,�����ټ���ʶ��.
            *
            *  [4/26/2010]
            */
			#if 0
            APPID_LOG(APPID_DPI, "match success [%d] appId = %d, pkt->count = %llu, RET = %d, ipid = %x\n",
                      pktDir, pEntry->appId, counter[pktDir].packets, iRet, iph->id);
			#endif
            /* ����ʶ��Ľ������Ϊһ��Ӧ�õĽ������ */
            /* app_id_value_set���Ա�֤�Ѿ���õĻ���Ӧ�ò������� by jyc, 19Jan11 */
            appIdOpFunc->app_id_value_set(&(appinfo->appidntfy_flag[pktDir].app_id_index), iRet);

            APPIDNTF_DEBUG("l_matchDeepInspect:iRet = %d,ct->proxyid = %d, pktDir = %d, app_id_ori = %x app_id_rply = %x id = %x\n\r",
                           iRet,
                           appidntify_ext->proxy_id_index,
                           pktDir,
                           appinfo->appidntfy_flag[pktDir].app_id_index,
                           appinfo->appidntfy_flag[1-pktDir].app_id_index,
                           iph->id);

            if ( pEntry->feature[1 - pktDir].enable )
            {

                /*!
                *   ˫�򷽿����ʶ��Ĺ���
                *
                */
                appIdOri = appIdOpFunc->app_id_flag_get(appinfo->appidntfy_flag[pktDir].app_id_index);
                appIdReply = appIdOpFunc->app_id_flag_get(appinfo->appidntfy_flag[1- pktDir].app_id_index);

                APPIDNTF_DEBUG("appId ori = %d, appId Reply = %d\n\r", appIdOri, appIdReply);

                if (appIdReply  ==  appIdOpFunc->app_id_flag_get(APP_ID_CHECKING))
                {
                    /* ����ʶ�� */

                }
                else if (appIdReply  == appIdOpFunc->app_id_flag_get(APP_ID_UNKNOWN))
                {
                    /*!
                    *   �Է�ΪUNKNOWN
                    *
                    */

                    appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[pktDir].app_id_index), APP_ID_UNKNOWN);

                }
                else if (appIdOri != appIdReply)
                {

                    /*!
                    *   ���ߵ�ID��һ��
                    *
                    */

                    appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[pktDir].app_id_index), APP_ID_UNKNOWN);
                    appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[1-pktDir].app_id_index), APP_ID_UNKNOWN);

                    /* ct->appidntfy_flag[pktDir].app_id_index = ct->appidntfy_flag[1 - pktDir].app_id_index; */
                }
            }
            else
            {
                /*!
                *   ��������ʶ��Ĺ���, disable�����ֵ��enable���������.
                *
                *  [5/6/2010]
                */
                /* ct->appidntfy_flag[1 - pktDir] = ct->appidntfy_flag[pktDir]; */
                appIdOpFunc->app_id_flag_set(&(appinfo->appidntfy_flag[1-pktDir].app_id_index),
                                             appinfo->appidntfy_flag[pktDir].app_id_index);

            }
            return APPIDNTFY_DI_KNOWN;
        }
        else
        {
            /*!
            *   ˵����Ԫ����Ȼƥ���ˣ����������������ȴʶ��ʧ��
            *  ��������������Ԫ��ƥ�䡣
            *
            *  [5/7/2010]
            */

            MATCH_RULE_DEEP_DEBUG("#2 Detect Unknown,  pIpHeader->id = %x\r\n",  iph->id);

            return APPIDNTFY_DI_UNKNOWN;
        }
    }
    else
    {
        /*!
        *   ��������ʶ��,���ʾʶ�������.��¼ʶ��Ľ��,��Ϊ�޵ڼ���������������Ϣ,��,
        *   ��Ϊ��ʱ,��ǰ����Ѿ���������.
        *
        *  [4/27/2010]
        */
        MATCH_RULE_DEEP_DEBUG("#19 known way index: %d,  pIpHeader->id = %x\r\n",
                              appinfo->appidntfy_flag[1 - pktDir].app_id_index,  iph->id);
        return APPIDNTFY_DI_KNOWN;
    }
}


#define MATCH_RULE_DEBUG    APPIDNTF_DEBUG
#define MATCH_RULE_DEBUG_EX APPIDNTF_DEBUG
static unsigned int l_matchRules(struct sk_buff *skb,
                                 void *rule, APPIDNTFY_PKT_TUPLE *pTuple,
                                struct nf_conntrack_app *appinfo, int pktDir,
                                 unsigned short bFastPath, unsigned char *data, unsigned int datalen)
{
    APPIDNTFY_NODE       *pList               = NULL;
    APPIDNTFY_KER_RULE   *pEntry              = NULL;
    int                 iContinue           = 1;
    unsigned int        iRet                = APP_ID_UNKNOWN;
    unsigned int        iLastRet            = APPIDNTFY_DI_MAX;
    int                 iOnceForFastPath    = 0;
    unsigned short      bRandomPort         = FALSE;
    unsigned short      bBasicApp           = FALSE;
    APPIDNTFY_HEAD        *pListHeader        = NULL;
    int                 index = 0;

    short               appId;
    struct iphdr        *iph;
    struct nf_conn      *ct;
    enum ip_conntrack_info ctinfo;

    APPIDNTF_DEBUG("in\r\n");
    if (NULL == rule || NULL == skb)
    {
        return -1;
    }

    iph = ip_hdr(skb);
    ct  = nf_ct_get(skb, &ctinfo);
    if (NULL == iph || NULL == ct)
    {
        return -1;
    }
    /*!
    *   Ĭ���Ǽ���ƥ���,����������ȼ��,����Ϊ0,��ʾ���������������ͻ�����ƥ��.
    *
    */
    iContinue = 1;

    if (bFastPath)
    {
        /*!
        *   ���ٶ�λ�Ĺ��򲻰���ͷ���.
        *
        */
        iOnceForFastPath = 0;
        pList = (APPIDNTFY_NODE *)rule;
    }
    else
    {
        iOnceForFastPath = 1;
        pListHeader = (APPIDNTFY_HEAD *)rule;
        pList = hlist_entry(pListHeader->head.first, APPIDNTFY_NODE, node);
    }


    while (pList)
    {
        pEntry = (APPIDNTFY_KER_RULE *)(pList->parent);
        /*
        ����pEntry��Ϊ��
        assert(pEntry!=IP_NULL);
        */
        if (NULL != pEntry)
        {
            if(IS_BASIC_APP(pEntry->appId))
            {
                MATCH_RULE_DEBUG("Entry get Basic App id = 0x%x app_id_index = 0x%x, app_id_reply = 0x%x\r\n",
                                 pEntry->appId, appinfo->appidntfy_flag[pktDir].app_id_index,
                                 appinfo->appidntfy_flag[1-pktDir].app_id_index);

                /* ����Ѿ�ʶ�������Ӧ�ã����ü���ƥ�����Ӧ�� */
                if (is_app_basic_id_valid(appinfo->appidntfy_flag[pktDir].app_id_index))
                {
                    APPIDNTF_ERROR("Not suppose here!!!Already Matched basic app id = %x, header id = 0x%x\n\r",
                                   pEntry->appId, iph->id);
                    goto match_rule_exit;
                }

                bBasicApp = TRUE;
            }
            else
            {
                bBasicApp = FALSE;
            }


            if (IS_RANDOM_PORT_RULE(pEntry->mask))
            {
                bRandomPort = TRUE;
            }
            else
            {
                bRandomPort = FALSE;
            }

            if (l_matchTuplelWithMask(&pEntry->tuple, pTuple, pEntry->mask))
            {
                 APPIDNTF_DEBUG("l_matchTuplelWithMask OK!header id = 0x%x, appid = 0x%x, appidReply = 0x%x\n\r ",
                               iph->id, appinfo->appidntfy_flag[0].app_id_index, appinfo->appidntfy_flag[1].app_id_index);

                /* ���ڲ����˿ںͻ���Ӧ����˵�����ܼ�¼��ƥ��Ĺ��򡣽��в����˿ڼ��֮�󣬻���Ҫ�����̶��˿ڹ���ƥ�䡣
                   ������޷�ƥ��Ӧ�õ������Ӧ����Ƿ񽫲����˿ڻ��߻���Ӧ�õĹ���ŵ�fast entry�ϡ�by jyc, 06Jan11 */
                if (TRUE != bRandomPort && TRUE != bBasicApp)
                {
                    /*!
                    *   ��Ԫ��ƥ��ɹ�,��������ת����һ���������ƥ��.
                    *
                    */
                    APPIDNTF_DEBUG("\r\n");
                    iContinue = 0;

                    if (iOnceForFastPath == 1)
                    {
                        /*!
                        *   ��¼��һ����ƥ��Ĺ���ĵ�ַ.[�ǿ��ٶ�λ�������ʹ��.], ��������ٹ�ϣ������.
                        *
                        */
                        appinfo->appidntfy_fast_entry = ( void* )pList;
                        iOnceForFastPath = 0;
                    }
                }

                /*!
                *   ������ȼ��:��ȼ����,�����Ƚ������������ļ��,�ٽ���������ļ��.
                *
                *  [5/13/2010]
                */

                iRet = l_matchDeepInspect(pEntry, skb, appinfo, pktDir, NULL, data, datalen);

                index++;
                if (iLastRet == APPIDNTFY_DI_MAX)
                {
                    iLastRet = iRet;
                }

                /*!
                *   ����״̬ת���Ĺ���
                *   �������APPIDNTFY_DI_NOT_REACH,�����ձ��� APPIDNTFY_DI_NOT_REACH
                *   �������APPIDNTFY_DI_UNKNOWN,������APPIDNTFY_DI_NOT_REACH,����APPIDNTFY_DI_NOT_REACH
                *
                *
                */

                switch (iRet)
                {
                case  APPIDNTFY_DI_KNOWN:
                    if ((TRUE == bBasicApp))
                    {
                        appId = appinfo->appidntfy_flag[pktDir].app_id_index;

                        APPIDNTF_DEBUG("Matched: Basic appId = 0x%x, header id = 0x%x\n\r ",appId,iph->id );
                        if(!is_app_basic_id_valid(appId))
                        {
                            APPIDNTF_ERROR("Should not be here!Basic app break!! pktDir = %d, appid = %x\n\r",
                                            pktDir, appinfo->appidntfy_flag[pktDir].app_id_index);
                            break;
                        }
                    }

                    /* ��������˿�û��ʶ�������������ƥ��ͬ����� */
                    if (((TRUE == bRandomPort) &&
                         APP_NORMAL_ID_GET(appinfo->appidntfy_flag[pktDir].app_id_index) > APPMNGR_APPID_SPECIAL_END))
                    {

                        APPIDNTF_DEBUG("##1 All -> KNOWN. proto = %d, appId = %x,basic id = %x\r\n",
                                       ct->tuplehash[pktDir].tuple.dst.protonum,
                                       appinfo->appidntfy_flag[pktDir].app_id_index,
                                       APP_BASIC_ID_VALUE_GET(appinfo->appidntfy_flag[pktDir].app_id_index));

                        break;
                    }

                    APPIDNTF_DEBUG("##2 All -> KNOWN. proto = %d, pktDir:%d, appId = %d,appIdRly = %d,index = %d\r\n",
                                   ct->tuplehash[pktDir].tuple.dst.protonum, pktDir,
                                   APP_NORMAL_ID_GET(appinfo->appidntfy_flag[pktDir].app_id_index),
                                   APP_NORMAL_ID_GET(appinfo->appidntfy_flag[1-pktDir].app_id_index), index);
                    iContinue = 0;
#if 1   /* appprio not in temp */
                    if (!APPPRIO_FLAG_IS_SET(appinfo->appprio_flag, APPPRIO_FLAG_PORTDEF))
                    {
                        APPPRIO_FLAG_CLEAR(appinfo->appprio_flag, APPPRIO_FLAG_PRI_SET);
                        APPPRIO_FLAG_SET(appinfo->appprio_flag, APPPRIO_FLAG_DPI);
                    }
#endif
                   /*! �ѳɹ�ʶ��,��ʾ����Ҫ����ƥ�� */
                    goto match_rule_exit;

                case APPIDNTFY_DI_NOT_REACH:
                    /*! ��ʾδ����������İ�����  */
                    /*MATCH_RULE_DEBUG("##2 Not reach\r\n");*/
                    if (iLastRet != APPIDNTFY_DI_KNOWN)
                    {
                        iLastRet = APPIDNTFY_DI_NOT_REACH;
                    }
                    /*MATCH_RULE_DEBUG("##3 All but KNOWN -> NOT_REACH\r\n");*/
                    break;
                case  APPIDNTFY_DI_UNKNOWN:
                    if (iLastRet == APPIDNTFY_DI_OVER || iLastRet == APPIDNTFY_DI_DISABLE)
                    {
                        iLastRet = APPIDNTFY_DI_UNKNOWN;
                    }

                    MATCH_RULE_DEBUG("##4 OVER DISABLE -> UNKNOWN header id = 0x%x\n\r ", iph->id);
                    break;
                case APPIDNTFY_DI_OVER:
                    if (iLastRet == APPIDNTFY_DI_DISABLE)
                    {
                        iLastRet = APPIDNTFY_DI_OVER;
                    }
                    MATCH_RULE_DEBUG("##5DISABLE -> OVER header id = 0x%x\n\r ", iph->id);
                    break;
                case APPIDNTFY_DI_DISABLE:
                    /*! ��������״̬����  */
                    break;
                default:
                    break;
                }
            }
        }
        else
        {
            APPIDNTF_ERROR("pEntry is NULL\r\n");
            break;
        }

        if (pList->node.next)
        {
            pList = hlist_entry(pList->node.next, APPIDNTFY_NODE, node);
        }
        else
        {
            pList = NULL;
        }
    }

    APPIDNTF_DEBUG("\r\n");
    /*!
    *   ��������ܵ���������,˵����Ԫ�����ƥ����,�������벻ƥ��.����Ҫ����ͳ������1
    *
    */

    /*!
    *   ������еĹ�����OVER����UNKNOWN,��ô��ʱ�����ж�������ΪUNKNOWN
    *
    */
    switch (iLastRet)
    {
    case APPIDNTFY_DI_NOT_REACH:
    case APPIDNTFY_DI_UNKNOWN:
        {
            /*!
            *   ��ʾ̽����Ȼδ�������,��Ȼ��Ҫ���
            *
            */

            appIdOpFunc->app_id_flag_set(&appinfo->appidntfy_flag[pktDir].app_id_index, APP_ID_CHECKING);
            MATCH_RULE_DEBUG("appId = 0x%x, header id = 0x%x\n\r ",appinfo->appidntfy_flag[pktDir].app_id_index,iph->id);
            /* APP_BASIC_ID_FLAG_SET(, APP_BASIC_ID_CHECKING);   */

        }
        break;
    case APPIDNTFY_DI_DISABLE:
    case APPIDNTFY_DI_OVER:
        {
            MATCH_RULE_DEBUG("##7 at last : ALL IS DISABLE OR OVER, AND SET THIS WAY UNKNOWN\r\n");
            MATCH_RULE_DEBUG("DI Over before: appId = %x, pIpHeader->id = %x\n\r",
                             appinfo->appidntfy_flag[pktDir].app_id_index, iph->id);

            MATCH_RULE_DEBUG("##1 Finally set it unknown!header id = 0x%x\r\n", iph->id);
            appIdOpFunc->app_id_flag_set(&appinfo->appidntfy_flag[pktDir].app_id_index, APP_ID_UNKNOWN);
        }

        break;
    default:
        MATCH_RULE_DEBUG("##8 UNKNOWN RESULT %x\r\n", iLastRet);
        break;
    }

match_rule_exit:
	APPIDNTF_DEBUG("DPI match: match result id = %d, %d, return = %d\r\n", appinfo->appidntfy_flag[pktDir].app_id_index, appinfo->appidntfy_flag[pktDir].app_id_index & 0x0FFF, iContinue);
    return iContinue;
}

/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/
void appidentify_proxy_hook(struct sk_buff *skb,
                        struct nf_conntrack_app *appinfo,
                        unsigned int dir,
                        void *tuple,
                        unsigned char *data,
                        unsigned int  datalen)
{
    int i;
    int proto;
    int appIdOri;
    int appIdRpl;
    struct iphdr      *iph;
    struct nf_conntrack_app_ext *appidntify_ext;

    APPIDNTF_DEBUG("in\r\n");
    iph = ip_hdr(skb);
    proto = iph->protocol;

    appIdOri = appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index;
    appIdRpl = appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index;

    appidntify_ext = (struct nf_conntrack_app_ext *)appinfo->appidntfy_ext;
    if (NULL == appidntify_ext)
    {
        APPIDNTF_ERROR("appidntify_ext null.\r\n");
        return;
    }

    if (PROXY_ID_CHECKING != appidntify_ext->proxy_id_index)
    {
        return;
    }

    for (i = 0;i < APPIDNTFY_PROXY_RULE_COUNT;i++)
    {
        if (0 == appidentify_proxy_detector[i].name[0])
        {
            APPIDNTF_DEBUG("\r\n");
            break;
        }

        /*!
        ���һ������û�з�����Ԫ�飬��ô�ͻᱻ��ΪUNKOWN��������Ҫ�ȶ�����м�鿴�Ƿ����
        ���д���ʶ��
        */
        if (appidentify_proxy_detector[i].rule.protocol == proto)
        {
            int ret;

            APPIDNTF_PROXY_DEBUG("ready to proxy: name = %s, ct->proxy_id = %x, dir = %d, appIDori = %x, appIDRply = %x\r\n",
                                appidentify_proxy_detector[i].name,
                                appidntify_ext->proxy_id_index, dir, appIdOri, appIdRpl);

            /* ��ʼ���Ա���Խ���ʶ�� */
            APP_NORMAL_ID_SET(appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index, APP_NORMAL_ID_CHECKING);
            appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index = appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index;
            APPIDNTF_DEBUG("\r\n");
            ret = l_matchDeepInspect(&appidentify_proxy_detector[i].rule, skb, appinfo, dir, tuple, data, datalen);

            /* �ָ�ԭ����ֵ */
            appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index = appIdOri;
            appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index = appIdRpl;

            if (APPIDNTFY_DI_KNOWN == ret)
            {
                APPIDNTF_PROXY_DEBUG("hit appidentify_proxy_detector name = %s,  ct->proxy_id = %d\r\n",
                                     appidentify_proxy_detector[i].name,  appidntify_ext->proxy_id_index);

                /*! ��l_matchDeepInspect�б���Ϊproxy,����ָ�Ϊ��ʶ��״̬ */
                APP_NORMAL_ID_SET(appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index,APP_NORMAL_ID_CHECKING);
                appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index = appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index;
            }
            else if ((APPIDNTFY_DI_OVER == ret))
            {
                appidntify_ext->proxy_id_index = PROXY_ID_UNKNOWN;
            }
        }

        if (IS_PROXY_ID_VALID(appidntify_ext->proxy_id_index))
        {
            if (appidentify_proxy_detector[i].adjust_payload)
            {
                appidentify_proxy_detector[i].adjust_payload(skb, data);
            }

            APPIDNTF_DEBUG("\r\n");
            /* �Ѿ�ʶ�����������Ҫ�ٱ��������������� */
            break;
        }
    }

    APPIDNTF_DEBUG("\r\n");
    return;
}

unsigned int appidentify_match_hook(unsigned int hook,
                 struct sk_buff *skb,
                 const struct net_device *in,
                 const struct net_device *out,
                 int (*okfn)(struct sk_buff *))
{
#if ENABLE_APPIDNTFY_MODULE

    int                 iSubTable                               = 0;
    int                 iProtocol                               = 0;
    unsigned int        packetDirection                         = IP_CT_DIR_MAX;
    APPIDNTFY_PKT_TUPLE   pktTuple                              = {0};
//    APPIDNTFY_PKT_TUPLE   pktTupleCookie                        = {0};
    struct nf_conn      *ct                                     = NULL;
    APPIDNTFY_HEAD       *listHeader[APPIDNTFY_TUPLE_INDEX_MAX] = {NULL};
    /* �Ƿ��в����˿ڵĹ��� */
    int                 bRandomPort                             = FALSE;
    unsigned char       *data                                   = NULL;
    int                 datalen;
    enum ip_conntrack_info ctinfo;
    struct nf_conntrack_app *appinfo;
    struct nf_conntrack_app_ext *appidntify_ext;
    struct nf_conn_counter *ctCounter                           = NULL;	
		
    if (!g_enableDpi)
    {
        return NF_ACCEPT;
    }
    if (!g_isAppidentifyInit)
    {
        return NF_ACCEPT;
    }
	
    ct = nf_ct_get(skb, &ctinfo);
    if (NULL == ct)    {		
		
        return NF_ACCEPT;
    }

    appinfo = nf_ct_get_app(ct);
    if(NULL == appinfo)    {
		
        return NF_ACCEPT;
    }

    if (APPPRIO_FLAG_IS_SET(appinfo->appprio_flag, APPPRIO_FLAG_TOFROM_ROUTER) ||
        APPPRIO_FLAG_IS_SET(appinfo->appprio_flag, APPPRIO_FLAG_UPNP))    {
		
        return NF_ACCEPT;
    }
		
    ctCounter = nf_conn_acct_find(ct);
    if (NULL == ctCounter)
    {
		/* printk("DPI match: no acct info #2\r\n"); */
        return NF_ACCEPT;
    }

    appidntify_ext = (struct nf_conntrack_app_ext *)appinfo->appidntfy_ext;
    if (NULL == appidntify_ext)
    {
		printk("DPI match: no ext info #3\r\n");
        return APPIDNTFY_DI_UNKNOWN;
    }

    if(g_appidentifyCfgLock)
    {
        APPIDNTF_ERROR("Database lock!Close the dist engine!\n\r");
        return NF_ACCEPT;
    }

    g_appidentifyHookLock = TRUE;
    packetDirection = CTINFO2DIR(ctinfo);
	
	APPIDNTF_DEBUG("DPI match: appid %d, %d\r\n", appinfo->appidntfy_flag[packetDirection].app_id_index, appinfo->appidntfy_flag[packetDirection].app_id_index & 0x0FFF);
	
	/* add proxy support check by wl, 04Nov15*/
    if ((APP_BASIC_ID_FLAG_GET(appinfo->appidntfy_flag[packetDirection].app_id_index) != APP_BASIC_ID_CHECKING)
        && ((APP_NORMAL_ID_GET(appinfo->appidntfy_flag[packetDirection].app_id_index) != APP_NORMAL_ID_CHECKING))
        && ( ! APPIDNTFY_SUPPORT_PROXY || (PROXY_ID_CHECKING != appidntify_ext->proxy_id_index) ) ) 
    {
        goto appidentify_out;
    }
	
    /*!
    *   Э��
    *
    *  [4/27/2010]
    */
    iProtocol = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum;
    if (IPPROTO_TCP == iProtocol)
    {
        iSubTable = APPIDNTFY_TCP_SUBTABLE;
    }
    else if (IPPROTO_UDP == iProtocol)
    {
        iSubTable = APPIDNTFY_UDP_SUBTABLE;
    }
    else
    {
        goto appidentify_out;
    }

    /* ��pkt->startָ��ָ��tcp/udp���� */
    if (appidentify_locate_payload(skb, &data, &datalen))
    {
        return NF_ACCEPT;
    }

#if 0
    APPID_LOG(APPID_DPI, "PROTO: %s, ORIGINAL: src: %08x:%d, dst: %08x:%d, REPLY: src: %08x:%d, dst: %08x:%d, pkt len %d, data %08x.\r\n",
              IPPROTO_TCP == iProtocol ? "TCP" : "UDP",
              ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
              ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
              ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip,
              ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all,
              ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
              ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all,
              ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
              ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all,
              datalen,
              data != NULL ? *((unsigned int *)data) : 0x12345678);
#endif

#if APPIDNTFY_SUPPORT_PROXY
    if (TRUE == g_isAppidentifyProxyInit)
    {
        /* ���д����ʶ�� by jyc, 08Nov10 */
        APPIDNTF_DEBUG("\r\n");
        appidentify_proxy_hook(skb, appinfo, packetDirection, &pktTupleCookie, data, datalen);
    }
#endif


    /*!
    *   ��ȡ��Ԫ�����Ϣ.[�����ֽ���]
    *
    */
    pktTuple.srcip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
    pktTuple.dstip = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip;
    pktTuple.srcport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all;
    pktTuple.dstport = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all;

#if 0
    APPIDNTF_DEBUG("ORIGINAL: src: %08x:%d, dst: %08x:%d, REPLY: src: %08x:%d, dst: %08x:%d.\r\n",
                   ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip,
                   ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all,
                   pktTuple.dstip,
                   pktTuple.dstport,
                   ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip,
                   ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all,
                   ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip,
                   ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all);
#endif

    if (TRUE == g_isAppidentifyBasicInit)
    {
        if ((APP_BASIC_ID_FLAG_GET(appinfo->appidntfy_flag[packetDirection].app_id_index) == APP_BASIC_ID_CHECKING))
        {
            listHeader[APPIDNTFY_BASIC_APP] = &hash_sub_tables[iSubTable][APPIDNTFY_BASIC_APP][0];
            if(listHeader[APPIDNTFY_BASIC_APP]->head.first)
            {
				APPIDNTF_DEBUG("DPI match: to match rules for basic app..\r\n");
                appIdOpFunc = &appBasicIdOpFunc;
                if (!l_matchRules(skb, listHeader[APPIDNTFY_BASIC_APP], &pktTuple, appinfo,
                    packetDirection, FALSE, data, datalen))
                {
                    /* ���۽����Σ�����Ҫ��������ʶ�� */
                    /* goto appidentify_out; */
                }
                appIdOpFunc = &appNormalIdOpFunc;
            }
            else
            {
				APPIDNTF_DEBUG("DPI match: no match rules..\r\n");
                APP_BASIC_ID_FLAG_SET(appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index, APP_BASIC_ID_UNKNOWN);
                APP_BASIC_ID_FLAG_SET(appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index, APP_BASIC_ID_UNKNOWN);
            }
        }
    }

    /*!
    *  ������Ϣ���ж�
    *
    *   �ж��Ƿ��Ѿ�ʶ�����
    *  appidentify_flag �ĸ�16λ��¼ʶ��Ĵ�������16λ��¼ʶ��Ľ����
    *  [4/29/2010]
    */

    /*!
    *   ˵���Ѿ������Ƚ��ˣ���鿴�ȽϵĽ����
    *
    */
    /* app_id_index�������ӽ���ʱ��ʼ�� */
    if ((APP_NORMAL_ID_GET(appinfo->appidntfy_flag[packetDirection].app_id_index) != APP_NORMAL_ID_CHECKING))
    {
        APPIDNTF_DEBUG("app_id_index normal id %x\r\n", APP_NORMAL_ID_GET(appinfo->appidntfy_flag[packetDirection].app_id_index));
        goto appidentify_out;
    }

    if (TRUE == g_isAppidentifyRandomInit)
    {
        /* ����ÿһ��δʶ������ӣ�����Ҫ�����˿�ƥ�䣬���Թ��򲢲���¼��fast entry.
           ���ڲ����˿ڵ�ƥ�䣬Ҫ����fast_entry֮ǰ */
        /* same as basic app just use one hash node */
        listHeader[APPIDNTFY_RANDOM_PORT] = &hash_sub_tables[iSubTable][APPIDNTFY_RANDOM_PORT][0];

        if (listHeader[APPIDNTFY_RANDOM_PORT]->head.first)
        {
			APPIDNTF_DEBUG("DPI match: to match rules for random port..\r\n");
            bRandomPort = TRUE;
            if ( !l_matchRules(skb, listHeader[APPIDNTFY_RANDOM_PORT], &pktTuple, appinfo,
                packetDirection, FALSE, data, datalen))
            {
                goto appidentify_out;
            }
        }
    }

    /*!
    *   ���CT����Ϣ,����CT����Ϣ,���ٵؽ������ƥ����б�
    *   �������˴����ƥ�����,�������ٽ��к����ƥ�����.
    *
    */
    if (NULL != appinfo->appidntfy_fast_entry)
    {
#if APPIDNTFY_SUPPORT_PROXY
        /* ���Ѿ���ʶΪ���������ڿ���ʶ��·�������滻��fast entry��tuple. by jyc, 10Nov10 */
        if (IS_PROXY_ID_VALID(appidntify_ext->proxy_id_index))
        {
            APPIDNTFY_KER_RULE *rule = ((APPIDNTFY_NODE *)appinfo->appidntfy_fast_entry)->parent;
            APPIDNTF_DEBUG("revise pktTuple by fast,  rule->tuple.dstport = %d\r\n", rule->tuple.dstport);
            pktTuple = rule->tuple;
        }
#endif /*! APPIDNTFY_SUPPORT_PROXY */
        APPIDNTF_DEBUG("\r\n");
		APPIDNTF_DEBUG("DPI match: to match rules for fast entry..\r\n");
        l_matchRules(skb, (APPIDNTFY_NODE *)appinfo->appidntfy_fast_entry, &pktTuple, appinfo,
            packetDirection, TRUE, data, datalen);

        goto appidentify_out;
    }

#if APPIDNTFY_SUPPORT_PROXY
    /* �Ѿ�ʶ��ɴ�������Ҫ����Ӧ��ʶ�𣬽�tuple�滻�ɴ�������ȡ������tuple */
    if (IS_PROXY_ID_VALID(appidntify_ext->proxy_id_index))
    {
        APPIDNTF_DEBUG("revise pktTuple, pktTupleCookie = %d\r\n", pktTupleCookie.dstport);
        appidentify_proxy_tuple(&pktTuple, pktTupleCookie);
    }
#endif /*! APPIDNTFY_SUPPORT_PROXY */

    APPIDNTF_DEBUG("dst port hash %08x, pkt tuple:protocol %s src: %08x:%d, dst %08x:%d.\r\n",
                   HASH_KEY_PORT(pktTuple.dstport),
                   iSubTable == 0 ? "TCP" : "UDP",
                   pktTuple.srcip, pktTuple.srcport, pktTuple.dstip, pktTuple.dstport);
    /*!
    *   Э���������ж����֮��.���濪ʼ������Ԫ��Ĺ�ϣֵ����
    *  ����λ���ӱ���Ӧ���ĸ���ϣ��.
    *
    */
    listHeader[APPIDNTFY_SRC_IP]
    = &hash_sub_tables[iSubTable][APPIDNTFY_SRC_IP][HASH_KEY_IP(pktTuple.srcip)];

    listHeader[APPIDNTFY_SRC_PORT]
    = &hash_sub_tables[iSubTable][APPIDNTFY_SRC_PORT][HASH_KEY_PORT(pktTuple.srcport)];

    listHeader[APPIDNTFY_DST_IP]
    = &hash_sub_tables[iSubTable][APPIDNTFY_DST_IP][HASH_KEY_IP(pktTuple.dstip)];

    listHeader[APPIDNTFY_DST_PORT]
    = &hash_sub_tables[iSubTable][APPIDNTFY_DST_PORT][HASH_KEY_PORT(pktTuple.dstport)];

    /*!
    *   ���ݸ�����Ԫ�ؽ���ϸ��ƥ��Ĵ���.
    *
    */
    if (listHeader[APPIDNTFY_DST_PORT]->head.first)
    {
        APPIDNTF_DEBUG("\r\n");
		APPIDNTF_DEBUG("DPI match: to match rules for dst port..\r\n");
        if (!l_matchRules(skb, listHeader[APPIDNTFY_DST_PORT], &pktTuple, appinfo,
            packetDirection, FALSE, data, datalen))
        {
            goto appidentify_out;
        }
    }

    if (listHeader[APPIDNTFY_SRC_PORT]->head.first)
    {
        APPIDNTF_DEBUG("\r\n");
		APPIDNTF_DEBUG("DPI match: to match rules for src port..\r\n");
        if (!l_matchRules(skb, listHeader[APPIDNTFY_SRC_PORT], &pktTuple, appinfo,
            packetDirection, FALSE, data, datalen))
        {
            goto appidentify_out;
        }
    }

    if (listHeader[APPIDNTFY_DST_IP]->head.first)
    {
        APPIDNTF_DEBUG("\r\n");
		APPIDNTF_DEBUG("DPI match: to match rules for dst ip..\r\n");
        if (!l_matchRules(skb, listHeader[APPIDNTFY_DST_IP], &pktTuple, appinfo,
            packetDirection, FALSE, data, datalen))
        {
            goto appidentify_out;
        }
    }

    if (listHeader[APPIDNTFY_SRC_IP]->head.first)
    {
        APPIDNTF_DEBUG("\r\n");
		APPIDNTF_DEBUG("DPI match: to match rules for src ip..\r\n");
        if (!l_matchRules(skb, listHeader[APPIDNTFY_SRC_IP], &pktTuple, appinfo,
            packetDirection, FALSE, data, datalen))
        {
            goto appidentify_out;
        }
    }

    /*!
    *   �����ƥ���κι���,�򽫴����ӱ��ΪUNKNOWN
    *
    *  [5/13/2010]
    */

    APPID_LOG(APPID_DPI, "All match failed and set it unknown, app_id_index = %x\n",
              appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index);
	
	APPIDNTF_DEBUG("DPI match: All match failed and set it unknown, app_id_index = %x\n",
			  appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index);

    if (FALSE == bRandomPort)
    {
        APP_NORMAL_ID_SET(appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index, APP_NORMAL_ID_UNKNOWN);
        APP_NORMAL_ID_SET(appinfo->appidntfy_flag[IP_CT_DIR_REPLY].app_id_index, APP_NORMAL_ID_UNKNOWN);
    }

    APPIDNTF_DEBUG("app_id_index = %x\r\n", appinfo->appidntfy_flag[IP_CT_DIR_ORIGINAL].app_id_index);


appidentify_out:
    g_appidentifyHookLock = FALSE;

#endif

    return NF_ACCEPT;
}
/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/
