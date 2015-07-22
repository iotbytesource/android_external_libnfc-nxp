/*
 * Copyright (C) 2011 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*!
* =========================================================================== *
*                                                                             *
*                                                                             *
* \file  secDnldNfc.h                                                          *
* \brief Download Mgmt Header for the Generic Download Management.            *
*                                                                             *
*                                                                             *
*                                                                             *
* $Date: Tue Dec 20 2011$                                           *
* $Author: yjsung $                                                         *
* $Revision: 1.0 $                                                           *
* $Aliases:  $                    
*                                                                             *
* =========================================================================== *
*/


#ifndef SECDNLDNFC_H
#define SECDNLDNFC_H

/*
################################################################################
***************************** Header File Inclusion ****************************
################################################################################
*/
#include <phNfcStatus.h>
#include <phOsalNfc.h>

/*
################################################################################
****************************** Macro Definitions *******************************
################################################################################
*/
#define MAX_THREAD_INSTANCES 3
#define PTHREAD_STACK_SIZE (1024 * 1024) /* 1 MB */
#define snfc_os_free(x) phOsalNfc_FreeMemory(x)
#define snfc_os_malloc(x) phOsalNfc_GetMemory(x)

/*
################################################################################
********************* Callback Function Type Definition ************************
################################################################################
*/

/**
* F/W Donwload Status Notification Callback
*
* This callback notifies the result of F/W donwload
*
* \param [in] pContext    Context for the Callback Function
* \parma [out] status   F/W Download Success/Fail Result
*/
typedef void (*pSecDnldNfc_Resp_CB_t)(void *pContext, NFCSTATUS status);
typedef void * (*pSecDnldNfc_thread_handler_t) (void * pParam);

/*
################################################################################
******************** Enumeration and Structure Definition **********************
################################################################################
*/


/*
################################################################################
*********************** Function Prototype Declaration *************************
################################################################################
*/

/**
 * Start Firmware download
 *
 * @param pContext context is provided by upper layer.
 * @param rspCb callback function to register, it will be notified the result of firmware download through this callback
 *
 * @return NFCSTATUS: NFCSTATUS_PENDING - Success to create thread that does firmware download
 *                 
 */
NFCSTATUS secDnldNfc_StartThread(void *pContext, pSecDnldNfc_Resp_CB_t rspCb);

#endif /* SECDNLDNFC_H */

