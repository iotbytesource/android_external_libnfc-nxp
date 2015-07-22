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
* \file  secDnldNfc.c                                                          *
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



/*
################################################################################
***************************** Header File Inclusion ****************************
################################################################################
*/
#include <fcntl.h>
#include <pthread.h>
#include <utils/Log.h>
#include <secDnldNfc.h>
#include <phDal4Nfc_i2c.h>

/*
################################################################################
****************************** Macro Definitions *******************************
################################################################################
*/

#define SNFC_DNLD_TRACE
//#define SNFC_DNLD_LOW_LEVEL_TRACE

#if defined(SNFC_DNLD_TRACE) && defined (DEBUG)
extern char phOsalNfc_DbgTraceBuffer[];

#define MAX_TRACE_BUFFER    0x0410
#define Trace_buffer    phOsalNfc_DbgTraceBuffer
#define SNFC_DNLD_PRINT( str )  phOsalNfc_DbgString(str)
#define SNFC_DNLD_DEBUG(str, arg) \
    {                                               \
        snprintf(Trace_buffer,MAX_TRACE_BUFFER,str,arg);    \
        phOsalNfc_DbgString(Trace_buffer);              \
    }
#define SNFC_DNLD_PRINT_BUFFER(msg,buf,len)              \
    {                                               \
        snprintf(Trace_buffer,MAX_TRACE_BUFFER,"\n\t %s:",msg); \
        phOsalNfc_DbgString(Trace_buffer);              \
        phOsalNfc_DbgTrace(buf,len);                \
        phOsalNfc_DbgString("\r");                  \
    }
#define SNFC_DNLD_ERR_PRINT(...) LOGE(__VA_ARGS__)
#else
#define SNFC_DNLD_PRINT( str )
#define SNFC_DNLD_DEBUG(str, arg)
#define SNFC_DNLD_PRINT_BUFFER(msg,buf,len)
#define SNFC_DNLD_ERR_PRINT(...) ((void *) 0)
#endif

#define BOOTLOADER_VER_1_0_CMD (0xD4)
#define BOOTLOADER_VER_1_0_RESP (0xD5)
#define BOOTLOADER_VER_2_0_CMD (0xF4)
#define BOOTLOADER_VER_2_0_RESP (0xF5)

#define MAKE_WORD(lsb, msb) \
  (unsigned short)(\
    ((lsb))|\
    ((msb) << 8)  \
  )

/* Maxium buffer size to send */
#define SENDBUF_MAX 0xff 
/* Maxium buffer size to read */
#define REVBUF_MAX 0xff

/* Single data block length to download the Firmware */
#define DNLD_SBLOCK_LEN 0x80U

/*
################################################################################
******************** Enumeration and Structure Definition **********************
################################################################################
*/
typedef struct secDnldNfc_sContext
{
    pthread_t thread_id;

    /** \internal Pointer to the upper layer notification callback function */
    pSecDnldNfc_Resp_CB_t p_upper_notify;
    /** \internal Pointer to the upper layer context */
    void *p_upper_context;

    /** \internal Single Data Block to download the Firmware */
    uint8_t dnld_data[SENDBUF_MAX];

    /** \internal Response Data to process the response */
    uint8_t dnld_resp[REVBUF_MAX];

    /** \internal Record type of Firmware Hex Data */
    uint8_t record_type;
#define EXTENDED_LINEAR_ADDRESS_RECORD 0x04
#define DATA_RECORD 0x00

    /** \internal Length of Firmware Hex Data to send */
    uint8_t fw_len;

    /** \internal Address of the Firmware header section of the Firmware */
    uint32_t fw_hdr_addr;
    /** \internal Address of the Firmware header section offset of the Firmware */
    uint32_t fw_hdr_addr_offset;

    /** \internal Firmware Download Command regarding to Bootlader version */
    uint8_t bl_cmd;
    /** \internal Firmware Download Command Response length regarding to Bootlader version */
    uint8_t bl_resp_len;

    uint32_t dnld_start_addr;
    uint32_t dnld_current_addr;
}secDnldNfc_sContext_t;


/*
################################################################################
******************** Global and Static Variables Definition ********************
################################################################################
*/
/* firmware data getting from f/w library */
extern const uint8_t *snfc_fw_version;
extern int snfc_fw_line;
extern const uint8_t (*snfc_fw_data)[SNFC_FW_HEX_ROW];

static secDnldNfc_sContext_t secDnldContext;

/*
*************************** Static Function Declaration **************************
*/


/*
*************************** Function Definitions **************************
*/
static
void
secDnldNfc_Init_Structure(
    void *context,
    pSecDnldNfc_Resp_CB_t notify
)
{
    memset(&secDnldContext, 0, sizeof(secDnldContext));
    secDnldContext.thread_id = (pthread_t)NULL;
    secDnldContext.p_upper_context = context;
    secDnldContext.p_upper_notify = notify;
}

static
int
secDnldNfc_Send(
    uint8_t *buf,
    unsigned int len
)
{
    /* TODO: support UART */
    //usleep(10000); // delay 10ms
    return phDal4Nfc_i2c_write (buf, len);
}

static
int
secDnldNfc_Read(
    uint8_t *buf,
    unsigned int len
)
{
    /* TODO: support UART */

    return phDal4Nfc_i2c_read (buf, len);
}

static
bool_t
secDnldNfc_Exchange(
    uint8_t *send_data,
    uint8_t *recv_data,
    uint8_t checksum_flag
)
{
    int i;
    uint8_t checksum_data = 0;
    
    uint8_t sendbuf_len = send_data[0];
    uint8_t recvbuf_len = recv_data[0];

#ifdef SNFC_DNLD_LOW_LEVEL_TRACE
    SNFC_DNLD_PRINT_BUFFER("FW SEND DATA", &send_data[1], sendbuf_len);
#endif    

    if (secDnldNfc_Send(&send_data[1], sendbuf_len) > 0)
    {
        if (secDnldNfc_Read(&recv_data[1], recvbuf_len) < 0)
            return FALSE;

#ifdef SNFC_DNLD_LOW_LEVEL_TRACE
        SNFC_DNLD_PRINT_BUFFER("FW RECV DATA", &recv_data[1], recvbuf_len);
#endif

        //checksum
        if (checksum_flag == TRUE)
        {
            for (i = 1; i < sendbuf_len; i++)
                checksum_data += send_data[i];

            if (checksum_data != recv_data[4])
            {
                SNFC_DNLD_ERR_PRINT("Checksum Error");
                return FALSE;
            }
        }
    }
    else
        return FALSE;

    return TRUE;


}

int secDnldNfc_Thread (void *pArg)
{
    long i = 0;
    NFCSTATUS result = NFCSTATUS_FAILED;
    
    uint8_t fw_len_offset = 0;
    uint8_t cumulative_fw_len = 0;

    uint8_t dnld_start_flag = 0;

    long dnld_cur_index = 0;
    long dnld_max_index = snfc_fw_line;

    uint8_t pre_dnld_progress = 0;
    uint8_t cur_dnld_progress = 0;
    
    secDnldContext.dnld_start_addr = 0x1000;
    secDnldContext.bl_cmd = BOOTLOADER_VER_2_0_CMD;

    /* Test to Uart implement */
    result = NFCSTATUS_SUCCESS;
    goto fail;
    /* -----------------------*/

    /* Stage0 - open I2C */
    if (phDal4Nfc_i2c_is_opened () != 1)
    {
        SNFC_DNLD_ERR_PRINT("I2C open Failed");
        goto fail;
    }

    /* Stage 1 - check boot mode ( CMD: D4/F4 B4 04 00 ) */
    SNFC_DNLD_PRINT ("Check Boot Mode.");
    secDnldContext.dnld_data[0] = 0x04;
    secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
    secDnldContext.dnld_data[2] = 0xB4;
    secDnldContext.dnld_data[3] = 0x04;
    secDnldContext.dnld_data[4] = 0x00;

    secDnldContext.dnld_resp[0] = 0x04;

    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE) == FALSE)
    {
        SNFC_DNLD_ERR_PRINT ("ERROR : Check Boot Mode");
        goto fail;
    }

    if (secDnldContext.dnld_resp[1] == BOOTLOADER_VER_2_0_RESP)
    {
        secDnldContext.bl_cmd = BOOTLOADER_VER_2_0_CMD;
        secDnldContext.bl_resp_len = 0x01;

        if (secDnldContext.dnld_resp[2] == 0xAB)
        {
            SNFC_DNLD_PRINT("Resp - New Bootloader");
        }
        else if (secDnldContext.dnld_resp[2] == 0xFF)
        {
            SNFC_DNLD_PRINT("Resp - Force Download New Bootloader");
        }
    }
    else if (secDnldContext.dnld_resp[1] == BOOTLOADER_VER_1_0_RESP)
    {
        //bootlaoder version 1.0
        secDnldContext.bl_cmd = BOOTLOADER_VER_1_0_CMD;
        secDnldContext.bl_resp_len = 0x04;

        SNFC_DNLD_PRINT("Resp - Old Bootloader");
    }

    /* Stage 2 - chip erase ( CMD: D4/F4 FE 04 00 ) */
    SNFC_DNLD_PRINT ("Chip Erase.");
    secDnldContext.dnld_data[0] = 0x04;
    secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
    secDnldContext.dnld_data[2] = 0xFE;
    secDnldContext.dnld_data[3] = 0x04;
    secDnldContext.dnld_data[4] = 0x00;

    secDnldContext.dnld_resp[0] = 0x04;

    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, TRUE) == FALSE)
    {
        SNFC_DNLD_PRINT("ERROR: Chip Erase.");
        goto fail;
    }

    /* Stage 3 - transfer firmware data(hex data) to NFC chip  */
    secDnldContext.dnld_current_addr = secDnldContext.dnld_start_addr;
    for (i = 0; i < dnld_max_index; i++)
    {
        secDnldContext.fw_len = snfc_fw_data[i][0];
        secDnldContext.record_type = snfc_fw_data[i][3];
        secDnldContext.fw_hdr_addr = secDnldContext.fw_hdr_addr_offset + MAKE_WORD(snfc_fw_data[i][2], snfc_fw_data[i][1]);

        if (secDnldContext.record_type == EXTENDED_LINEAR_ADDRESS_RECORD)
        {
            secDnldContext.fw_hdr_addr_offset = ((unsigned int) snfc_fw_data[i][5]) << 16;
        }
        else if (secDnldContext.record_type == DATA_RECORD)
        {
            if (secDnldContext.fw_hdr_addr < secDnldContext.dnld_start_addr)
            {
                secDnldContext.dnld_data[0] = secDnldContext.fw_len + 8;
                secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
                secDnldContext.dnld_data[2] = 0xF2;
                secDnldContext.dnld_data[3] = secDnldContext.fw_len + 8;

                secDnldContext.dnld_resp[0] = 0x04;
                memcpy(&secDnldContext.dnld_data[4], &snfc_fw_data[i][0], secDnldContext.fw_len + 5);

                if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE) == FALSE)
                {
                    SNFC_DNLD_ERR_PRINT("FW Download Failed");
                    goto fail;
                }
            }
            else
            {
                if (dnld_start_flag == 0)
                {
                    dnld_start_flag = 1;
                    
                    secDnldContext.dnld_data[0] = 0x07;
                    secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
                    secDnldContext.dnld_data[2] = 0xC0;
                    secDnldContext.dnld_data[3] = 0x07;
                    secDnldContext.dnld_data[4] = 0x00; //start address is 00 00 10 00
                    secDnldContext.dnld_data[5] = 0x00;
                    secDnldContext.dnld_data[6] = 0x10;
                    secDnldContext.dnld_data[7] = 0x00;

                    secDnldContext.dnld_resp[0] = 0x04;
                    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, TRUE) == FALSE)
                    {
                        SNFC_DNLD_ERR_PRINT("FW Download Failed");
                        goto fail;
                    }
                }

                memcpy(&secDnldContext.dnld_data[2 + fw_len_offset], &snfc_fw_data[i][4], secDnldContext.fw_len);
                cumulative_fw_len = cumulative_fw_len + secDnldContext.fw_len;
                fw_len_offset = fw_len_offset + secDnldContext.fw_len;

                if (cumulative_fw_len == ((uint8_t)DNLD_SBLOCK_LEN))
                {
                    secDnldContext.dnld_data[0] = cumulative_fw_len + 1; //send byte
                    secDnldContext.dnld_data[1] = cumulative_fw_len;
                    secDnldContext.dnld_resp[0] = secDnldContext.bl_resp_len;

                    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE) == FALSE)
                    {
                        SNFC_DNLD_ERR_PRINT("FW Download Failed");
                        goto fail;
                    }

                    secDnldContext.dnld_current_addr = secDnldContext.dnld_current_addr + cumulative_fw_len;
                    fw_len_offset = 0;
                    cumulative_fw_len = 0;

                }

            }
        }
#ifdef SNFC_DNLD_TRACE
        cur_dnld_progress = (dnld_cur_index * 100) / dnld_max_index;

        if (pre_dnld_progress != cur_dnld_progress)
        {
            SNFC_DNLD_DEBUG( "Downloading - %d %%", cur_dnld_progress);
            pre_dnld_progress = cur_dnld_progress;
        }
#endif
        dnld_cur_index++;

    }

    SNFC_DNLD_PRINT( "Downloading - 100 %%");

    secDnldContext.dnld_data[0] = cumulative_fw_len + 1; //send bytes length
    secDnldContext.dnld_data[1] = cumulative_fw_len;

    secDnldContext.dnld_resp[0] = 0x04;
    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE) == FALSE)
    {
        SNFC_DNLD_ERR_PRINT("FW Download Failed");
        goto fail;
    }

    SNFC_DNLD_PRINT("FW CMD : D4/F4 CE 04 00");
    secDnldContext.dnld_data[0] = 0x04;
    secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
    secDnldContext.dnld_data[2] = 0xCE;
    secDnldContext.dnld_data[3] = 0x04;
    secDnldContext.dnld_data[4] = 0x00;

    secDnldContext.dnld_resp[0] = 0x04;
    if (secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE) == FALSE)
    {
        SNFC_DNLD_ERR_PRINT("ERROR - FW CMD : D4/F4 CE 04 00");
        goto fail;
    }

    SNFC_DNLD_PRINT("FW CMD : D4/F4 F4 04 00");
    secDnldContext.dnld_data[0] = 0X04;
    secDnldContext.dnld_data[1] = secDnldContext.bl_cmd;
    secDnldContext.dnld_data[2] = 0xF4;
    secDnldContext.dnld_data[3] = 0x04;
    secDnldContext.dnld_data[4] = 0x00;

    secDnldContext.dnld_resp[0] = 0x04;
    secDnldNfc_Exchange(secDnldContext.dnld_data, secDnldContext.dnld_resp, FALSE);

    SNFC_DNLD_PRINT("\nComplete Firmware Download.\n");
    result = NFCSTATUS_SUCCESS;

fail:
    /* notify firmware download result to upper layer */
    secDnldContext.p_upper_notify(secDnldContext.p_upper_context, result);
    pthread_exit(0);
    return 0;
}

NFCSTATUS secDnldNfc_StartThread (
    void *pContext,
    pSecDnldNfc_Resp_CB_t rspCb
)
{
    NFCSTATUS ret = NFCSTATUS_FAILED;

#ifndef SNFC_FW_DOWNLOAD

    return NFCSTATUS_FEATURE_NOT_SUPPORTED;
#endif

    secDnldNfc_Init_Structure(pContext, rspCb);

    ret = pthread_create(&secDnldContext.thread_id, NULL, (pSecDnldNfc_thread_handler_t)secDnldNfc_Thread, (void *)"fw_dnld_thread");

    if (ret != 0)
        return (PHNFCSTVAL(CID_NFC_DNLD, NFCSTATUS_FAILED));

    return NFCSTATUS_PENDING;

}
