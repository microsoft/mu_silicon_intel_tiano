/** @file
  The definition for VTD Log.

  Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __VTD_LOG_PROTOCOL_H__
#define __VTD_LOG_PROTOCOL_H__

#include <Guid/VtdLogDataHob.h>

#define EDKII_VTD_LOG_PROTOCOL_GUID \
    { \
      0x1e271819, 0xa3ca, 0x481f, { 0xbd, 0xff, 0x92, 0x78, 0x2f, 0x9a, 0x99, 0x3c } \
    }

typedef struct _EDKII_VTD_LOG_PROTOCOL  EDKII_VTD_LOG_PROTOCOL;

#define EDKII_VTD_LOG_PROTOCOL_REVISION 0x00010000

/**
  Callback function of each VTd log event.
  @param[in]  Context               Event context
  @param[in]  Header                Event header

  @retval     UINT32                Number of events
**/
typedef
VOID
(EFIAPI *EDKII_VTD_LOG_HANDLE_EVENT) (
  IN  VOID                          *Context,
  IN  VTDLOG_EVENT_HEADER           *Header
  );

/**
  Get the VTd log events.
  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback function for each VTd log event

  @retval         UINT32            Number of events
**/
typedef
UINT64
(EFIAPI *EDKII_VTD_LOG_GET_EVENTS) (
  IN      VOID                          *Context,
  IN OUT  EDKII_VTD_LOG_HANDLE_EVENT    CallbackHandle
  );

struct _EDKII_VTD_LOG_PROTOCOL {
  UINT64                                Revision;
  EDKII_VTD_LOG_GET_EVENTS              GetEvents;
};

extern EFI_GUID gEdkiiVTdLogProtocolGuid;

#endif

