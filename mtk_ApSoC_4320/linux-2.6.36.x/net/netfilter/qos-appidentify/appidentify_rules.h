/*! Copyright(c) 2008-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     appidentify_rules.h
 *\brief
 *\details
 *
 *\author   Yan Wei
 *\version  0.0.1
 *\date     27Sep13
 *
 *\warning
 *
 *\history \arg 0.0.1, 26Sep13, Yan Wei, Create the file.
 */
#ifndef __APPIDENTIFY_RULE_H__
#define __APPIDENTIFY_RULE_H__
/**************************************************************************************************/
/*                                      CONFIGURATIONS                                            */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      INCLUDE_FILES                                             */
/**************************************************************************************************/
/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/
#define APPIDNTFY_MASK_NONE               0X0000              /*!  ������Ч  */
#define APPIDNTFY_MASK_SRC_IP             0X0001              /*!  ԴIP  */
#define APPIDNTFY_MASK_SRC_PORT           0X0002              /*!  Դ�˿�  */
#define APPIDNTFY_MASK_DST_IP             0X0004              /*!  Ŀ��IP  */
#define APPIDNTFY_MASK_DST_PORT           0X0008              /*!  Ŀ�Ķ˿�  */
#define APPIDNTFY_MASK_RANDOM_PORT        0X0010              /*!  �����˿�  */
#define APPIDNTFY_MASK_BASIC_APP          0x0020              /*!  ����Ӧ��  */
#define APPIDNTFY_MASK_ALL                0X000F              /*!  ������Ч  */


/* HTTP 80port search feature */
#define HTTP_HEADER_END_STR             "\r\n\r\n"
#define HTTP_PAYLOAD_SEARCH_OFFSET_L    116
#define HTTP_PAYLOAD_SEARCH_OFFSET_S    40
/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/
/*!
*\typedef   APPIDNTFY_TUPLE_INDEX
*\brief ��Ԫ�������
*/
typedef enum _APPIDNTFY_TUPLE_INDEX
{
    APPIDNTFY_SRC_IP  = 0,
    APPIDNTFY_SRC_PORT,
    APPIDNTFY_DST_IP,
    APPIDNTFY_DST_PORT,
    APPIDNTFY_RANDOM_PORT,
    APPIDNTFY_BASIC_APP,
    APPIDNTFY_TUPLE_INDEX_MAX
} APPIDNTFY_TUPLE_INDEX;

/*!
*\typedef   APPIDNTFY_SUBTABLE_INDEX
*\brief ��Э��ȷ���Ķ�Ԫ��
*/
typedef enum _APPIDNTFY_SUBTABLE_INDEX
{
    APPIDNTFY_TCP_SUBTABLE    = 0,
    APPIDNTFY_UDP_SUBTABLE,
    APPIDNTFY_SUBTABLE_MAX
} APPIDNTFY_SUBTABLE_INDEX;

/*!
 *\typedef  APPMNGR_APPID_AREA
 *\brief    ����Ӧ��ID��ʹ������
 */
typedef enum _APPMNGR_APPID_AREA
{
    APPMNGR_APPID_VOID          = -1,
    APPMNGR_APPID_NORMAL_BEGIN  = 0,        /* ��ͨӦ�õ� ID��Χ 0-889 */
    APPMNGR_APPID_NORMAL_END    = 3999,      /* ��ͨӦ�õ��յ� */

    APPMNGR_APPID_AUTO_BEGIN    = 2000,
    APPMNGR_APPID_AUTO_END      = 2255,      /* �÷�Χ�� ID ���������Զ����䣬��ռ�� */

    APPMNGR_APPID_PRI_BEGIN     = 3000,
    APPMNGR_APPID_CLSF_BEGIN    = 3500,

    APPMNGR_PROXY_NONE          = 4000,      /* �ָ���: ��ȡ�����ID��,���ϴ�ֵ,�ɻ�ȡ��Ӧ�Ĳ���. */
    APPMNGR_PROXY_BEGIN         = 4001,      /* ������� */
    APPMNGR_PROXY_END           = 4020,      /* �����յ�:��16�� */

    APPMNGR_APPID_SPECIAL_NONE  = 4020,      /* �ָ���: ����Ӧ�û�����ȫ��Ϊ0,��ʶ���ڲ�ʹ��. */
    APPMNGR_APPID_SPECIAL_BEGIN = 4021,      /* ����Ӧ�� 908-1007, ��100�� */
    APPMNGR_APPID_SPECIAL_END   = 4070,      /* 4021-4070 50�� */

    APPMNGR_APPID_BASIC_NONE    = 4070,     /* �ָ���: ��ȡ����4λ֮��,���ϴ�ֵ�ɵõ�����Ӧ�õ�ID�������ΪAPPMNGR_APPID_BASIC_NONE�����ʾ�޻���Ӧ�� */
    APPMNGR_APPID_BASIC_BEGIN   = 4071,     /* ����Ӧ�õ� ID��Χ 4071-4085, ��15�� */
    APPMNGR_APPID_BASIC_END     = 4083,

}APPMNGR_APPID_AREA;

typedef struct _APP_ID_OP_FUNC
{
    void   (*app_id_value_set)(short *appId, short value);
    short   (*app_id_value_get)(short appId);
    void   (*app_id_flag_set)(short *appId, short value);
    short  (*app_id_flag_get)(short appId);
    int   (*is_app_id_valid)(short appId);
}APP_ID_OP_FUNC;

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      FUNCTIONS                                                 */
/**************************************************************************************************/




#endif  /* __APPIDENTIFY_RULE_H__ */
