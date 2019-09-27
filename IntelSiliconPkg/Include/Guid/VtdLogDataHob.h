/** @file
  The definition for VTD Log Data Hob.

  Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/


#ifndef _VTD_LOG_DATA_HOB_H_
#define _VTD_LOG_DATA_HOB_H_

#include <IndustryStandard/Vtd.h>

#define VTDLOG_LOG_TYPE(_id_) ((UINT64) 1 << (_id_))

typedef enum {
  VTDLOG_PEI_BASIC                          = 0, // Start ID for PEI basic log
  VTDLOG_PEI_PRE_MEM_DMA_PROTECT            = 1, // PRE-MEM phase
  VTDLOG_PEI_PMR_LOW_MEMORY_RANGE           = 2,
  VTDLOG_PEI_PMR_HIGH_MEMORY_RANGE          = 3,
  VTDLOG_PEI_PROTECT_MEMORY_RANGE           = 4,
  VTDLOG_PEI_POST_MEM_ENABLE_DMA_PROTECT    = 5,
  VTDLOG_PEI_POST_MEM_DISABLE_DMA_PROTECT   = 6,
  VTDLOG_PEI_QUEUED_INVALIDATION            = 7,
  VTDLOG_PEI_REGISTER                       = 8,
  VTDLOG_PEI_VTD_ERROR                      = 9,

  VTDLOG_PEI_ADVANCED                       = 16, // Start ID for PEI advanced log
  VTDLOG_PEI_PPI_ALLOC_BUFFER               = 17,
  VTDLOG_PEI_PPI_MAP                        = 18,

  VTDLOG_DXE_BASIC                          = 24, // Start ID for DXE basic log
  VTDLOG_DXE_DMAR_TABLE                     = 25,
  VTDLOG_DXE_SETUP_VTD                      = 26,
  VTDLOG_DXE_PCI_DEVICE                     = 27,
  VTDLOG_DXE_REGISTER                       = 28,
  VTDLOG_DXE_ENABLE_DMAR                    = 29,
  VTDLOG_DXE_DISABLE_DMAR                   = 30,
  VTDLOG_DXE_DISABLE_PMR                    = 31,
  VTDLOG_DXE_INSTALL_IOMMU_PROTOCOL         = 32,
  VTDLOG_DXE_QUEUED_INVALIDATION            = 33,  

  VTDLOG_DXE_ADVANCED                       = 44, // Start ID for DXE advanced log
  VTDLOG_DXE_IOMMU_ALLOC_BUFFER             = 45,
  VTDLOG_DXE_IOMMU_FREE_BUFFER              = 46,
  VTDLOG_DXE_IOMMU_MAP                      = 47,
  VTDLOG_DXE_IOMMU_UNMAP                    = 48,
  VTDLOG_DXE_IOMMU_SET_ATTRIBUTE            = 49,
  VTDLOG_DXE_ROOT_TABLE                     = 50,
} VTDLOG_EVENT_TYPE;

#define VTD_LOG_PEI_PRE_MEM_BAR_MAX         64

//
// Code of VTDLOG_PEI_BASIC / VTDLOG_DXE_BASIC
//
#define VTD_LOG_ERROR_BUFFER_FULL           (1<<0)

//
// Code of VTDLOG_PEI_PRE_MEM_DMA_PROTECT_MODE
//
#define VTD_LOG_PEI_PRE_MEM_NOT_USED        0
#define VTD_LOG_PEI_PRE_MEM_DISABLE         1
#define VTD_LOG_PEI_PRE_MEM_ADM             2
#define VTD_LOG_PEI_PRE_MEM_TE              3
#define VTD_LOG_PEI_PRE_MEM_PMR             4

//
// Code of VTDLOG_PEI_QUEUED_INVALIDATION
//
#define VTD_LOG_QI_DISABLE                  0
#define VTD_LOG_QI_ENABLE                   1
#define VTD_LOG_QI_ERROR_OUT_OF_RESOURCES   2

//
// Code of VTDLOG_PEI_VTD_ERROR
//
#define VTD_LOG_PEI_VTD_ERROR_PPI_ALLOC     1
#define VTD_LOG_PEI_VTD_ERROR_PPI_MAP       2

// Code of VTDLOG_PEI_REGISTER / VTDLOG_DXE_REGISTER
#define VTDLOG_REGISTER_ALL                 0
#define VTDLOG_REGISTER_THIN                1
#define VTDLOG_REGISTER_QI                  2

#pragma pack(1)

//
// Item head
//
typedef struct {
  UINT32                DataSize;
  UINT64                LogType;
  UINT64                Timestamp;
}VTDLOG_EVENT_HEADER;

//
// Struct for type = VTDLOG_PEI_REGISTER
//                   VTDLOG_DXE_REGISTER
//                   VTDLOG_DXE_DMAR_TABLE
//                   VTDLOG_DXE_IOMMU_SET_ATTRIBUTE
//                   VTDLOG_DXE_PCI_DEVICE
//                   VTDLOG_DXE_ROOT_TABLE
//
typedef struct {
  VTDLOG_EVENT_HEADER   Header;
  UINT64                Param;
  UINT8                 Data[1];
} VTDLOG_EVENT_CONTEXT;

//
// Struct for rest of the types
//
typedef struct {
  VTDLOG_EVENT_HEADER   Header;
  UINT64                Data1;
  UINT64                Data2;
}VTDLOG_EVENT_2PARAM;

//
// Struct for VTd log event
//
typedef union{
  VTDLOG_EVENT_HEADER   EventHeader;
  VTDLOG_EVENT_2PARAM   CommenEvent;
  VTDLOG_EVENT_CONTEXT  ContextEvent;
} VTDLOG_EVENT;

//
// Information for PEI pre-memory phase
//
typedef struct {
  UINT8                 Mode;
  UINT8                 Status;
  UINT32                BarAddress;
} VTDLOG_PEI_PRE_MEM_INFO;

//
// Buffer struct for PEI phase
//
typedef struct {
  UINT8                     VtdLogPeiError;
  VTDLOG_PEI_PRE_MEM_INFO   PreMemInfo[VTD_LOG_PEI_PRE_MEM_BAR_MAX];
  UINT32                    PostMemBufferUsed;
  UINT64                    PostMemBuffer;
} VTDLOG_PEI_BUFFER_HOB;

#pragma pack()

#endif // _VTD_LOG_DATA_HOB_H_

