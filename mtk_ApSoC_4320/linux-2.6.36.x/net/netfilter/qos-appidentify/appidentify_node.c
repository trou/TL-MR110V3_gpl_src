/*! Copyright(c) 2008-2013 Shenzhen TP-LINK Technologies Co.Ltd.
 *
 *\file     appidentify_node.c
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
#include "appidentify_node.h"
/**************************************************************************************************/
/*                                      DEFINES                                                   */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      TYPES                                                     */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      EXTERN_PROTOTYPES                                         */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      LOCAL_PROTOTYPES                                          */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      VARIABLES                                                 */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      LOCAL_FUNCTIONS                                           */
/**************************************************************************************************/

/**************************************************************************************************/
/*                                      PUBLIC_FUNCTIONS                                          */
/**************************************************************************************************/
int hlist_insert_tail(struct hlist_head *head, struct hlist_node *node)
{
    struct hlist_node *pos = NULL;

    if (NULL == head || NULL == node)
    {
        return -1;
    }

    if (NULL == head->first)
    {
        hlist_add_head(node, head);
    }
    else
    {
        hlist_for_each(pos, head)
        {
            if (NULL == pos->next)
            {
                break;
            }
        }
        hlist_add_after(pos, node);
    }

    return 0;
}
/**************************************************************************************************/
/*                                      GLOBAL_FUNCTIONS                                          */
/**************************************************************************************************/
