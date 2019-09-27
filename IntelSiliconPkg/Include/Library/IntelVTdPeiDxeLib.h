/** @file
  Intel VTd library definitions.

  Copyright (c) 2023 Intel Corporation. All rights reserved. <BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#ifndef _INTEL_VTD_PEI_DXE_LIB_H_
#define _INTEL_VTD_PEI_DXE_LIB_H_

//
// Include files
//
#include <Uefi/UefiBaseType.h>
#include <Library/DebugLib.h>
#include <Protocol/VtdLog.h>
#include <Protocol/PlatformVtdPolicy.h>

#if defined (EXT_CALLBACK)
  #define _VTDLIB_DEBUG(PrintLevel, ...)                                        \
    do {                                                                        \
      VtdLogEventCallback (Context, CallbackHandle, PrintLevel, ##__VA_ARGS__); \
    } while (FALSE)
  #define VTDLIB_DEBUG(Expression) _VTDLIB_DEBUG Expression
#else
  #define VTDLIB_DEBUG(Expression) DEBUG(Expression)
#endif

#pragma pack(1)

typedef struct {
  UINT8                            DeviceType;
  VTD_SOURCE_ID                    PciSourceId;
  EDKII_PLATFORM_VTD_PCI_DEVICE_ID PciDeviceId;
  // for statistic analysis
  UINT64                           AccessCount;
} PCI_DEVICE_DATA;

typedef struct {
  BOOLEAN                          IncludeAllFlag;
  UINT16                           Segment;
  UINT32                           PciDeviceDataMaxNumber;
  UINT32                           PciDeviceDataNumber;
  PCI_DEVICE_DATA                  PciDeviceData[1];
} PCI_DEVICE_INFORMATION;

typedef struct {
  UINT64                           Uint64Lo;
  UINT64                           Uint64Hi;
}VTD_UINT128;

typedef struct {
  UINT64                           BaseAddress;
  UINT32                           VerReg;
  UINT64                           CapReg;
  UINT64                           EcapReg;
  UINT32                           GstsReg;
  UINT64                           RtaddrReg;
  UINT64                           CcmdReg;
  UINT32                           FstsReg;
  UINT32                           FectlReg;
  UINT32                           FedataReg;
  UINT32                           FeaddrReg;
  UINT32                           FeuaddrReg;
  UINT64                           IqercdReg;
  UINT64                           IvaReg;
  UINT64                           IotlbReg;
  UINT16                           FrcdRegNum;  // Number of FRCD Registers
  VTD_UINT128                      FrcdReg[1];
} VTD_REGESTER_INFO;

typedef struct {
  UINT64                           BaseAddress;
  UINT32                           FstsReg;
  UINT64                           IqercdReg;
} VTD_REGESTER_QI_INFO;

typedef struct {
  UINT64                           BaseAddress;
  UINT32                           GstsReg;
  UINT64                           RtaddrReg;
  UINT32                           FstsReg;
  UINT32                           FectlReg;
  UINT64                           IqercdReg;
  UINT16                           FrcdRegNum;  // Number of FRCD Registers
  VTD_UINT128                      FrcdReg[1];
} VTD_REGESTER_THIN_INFO;

typedef struct {
  VTD_SOURCE_ID                    SourceId;
  EFI_PHYSICAL_ADDRESS             DeviceAddress;
  UINT64                           Length;
  UINT64                           IoMmuAccess;
  EFI_STATUS                       Status;
} VTD_PROTOCOL_SET_ATTRIBUTE;

typedef struct {
  UINT64                           BaseAddress;
  UINT64                           TableAddress;
  BOOLEAN                          Is5LevelPaging;
} VTD_ROOT_TABLE_INFO;

#pragma pack()

/**
  @brief This callback function is to handle the Vtd log strings.

  [Consumption]
    Dump VTd log

  @param[in]  Context               Context
  @param[in]  ErrorLevel            The error level of the debug message.
  @param[in]  Buffer                Event string
**/
typedef
VOID
(EFIAPI *EDKII_VTD_LIB_STRING_CB) (
  IN  VOID                          *Context,
  IN  UINTN                         ErrorLevel,
  IN  CHAR8                         *Buffer
  );

/**
  @brief This function is to dump DMAR ACPI table.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event Context
  @param[in out]  CallbackHandle    Callback Handler
  @param[in]      Dmar              DMAR ACPI table
**/
VOID
VtdLibDumpAcpiDmar (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     EFI_ACPI_DMAR_HEADER       *Dmar
  );

/**
  @brief This function is to dump DRHD DMAR ACPI table.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event Context
  @param[in out]  CallbackHandle    Callback Handler
  @param[in]      Dmar              DMAR ACPI table
**/
VOID
VtdLibDumpAcpiDmarDrhd (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     EFI_ACPI_DMAR_HEADER       *Dmar
  );

/**
  @brief This function is to dump the PCI device information of the VTd engine.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event Context
  @param[in out]  CallbackHandle    Callback Handler
  @param[in]      PciDeviceInfo     PCI device information
**/
VOID
VtdLibDumpPciDeviceInfo (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     PCI_DEVICE_INFORMATION     *PciDeviceInfo
  );

/**
  @brief This function is to dump DMAR context entry table.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback handler
  @param[in]      RootEntry         DMAR root entry.
  @param[in]      Is5LevelPaging    If it is the 5 level paging.
**/
VOID
VtdLibDumpDmarContextEntryTable (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     VTD_ROOT_ENTRY             *RootEntry,
  IN     BOOLEAN                    Is5LevelPaging
  );

/**
  @brief This function is to dump DMAR extended context entry table.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback handler
  @param[in]      ExtRootEntry      DMAR extended root entry.
  @param[in]      Is5LevelPaging    If it is the 5 level paging.
**/
VOID
VtdLibDumpDmarExtContextEntryTable (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     VTD_EXT_ROOT_ENTRY         *ExtRootEntry,
  IN     BOOLEAN                    Is5LevelPaging
  );

/**
  @brief This function is to dump VTd registers.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback handler
  @param[in]      VtdRegInfo        Registers Information
**/
VOID
VtdLibDumpVtdRegsAll (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     VTD_REGESTER_INFO          *VtdRegInfo
  );

/**
  @brief This function is to dump VTd registers.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback handler
  @param[in]      VtdRegInfo        Registers Information
**/
VOID
VtdLibDumpVtdRegsThin (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     VTD_REGESTER_THIN_INFO     *VtdRegInfo
  );

/**
  @brief This function is to decode log event context.

  [Consumption]
    Dump VTd log

  @param[in]      Context           Event context
  @param[in out]  CallbackHandle    Callback handler
  @param[in]      Event             Event struct

  @retval         TRUE              Decode event success
  @retval         FALSE             Unknown event
**/
BOOLEAN
VtdLibDecodeEvent (
  IN     VOID                       *Context,
  IN OUT EDKII_VTD_LIB_STRING_CB    CallbackHandle,
  IN     VTDLOG_EVENT               *Event
  );

/**
 @brief Pre-boot DMA protection End Process

             +----------------------+
             |  OnExitBootServices  |
             +----------------------+
                        ||
                        \/
+-------------------------------------------------+
|               Flush Write Buffer                |
|            VtdLibFlushWriteBuffer ()            |
+-------------------------------------------------+
                        ||
                        \/
+-------------------------------------------------+
|            Invalidate Context Cache             |
|   VtdLibSubmitQueuedInvalidationDescriptor ()   |
+-------------------------------------------------+
                        ||
                        \/
+-------------------------------------------------+
|                 Invalidate IOTLB                |
|   VtdLibSubmitQueuedInvalidationDescriptor ()   |
+-------------------------------------------------+
                        ||
                        \/
+-------------------------------------------------+
|                 Disable DMAR                    |
|              VtdLibDisableDmar ()               |
+-------------------------------------------------+
                        ||
                        \/
+-------------------------------------------------+
|      Disable Queued Invalidation interface      |
|   VtdLibDisableQueuedInvalidationInterface ()   |
+-------------------------------------------------+

**/

/**
  @brief This function is to flush VTd engine write buffer.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.
**/
VOID
VtdLibFlushWriteBuffer (
  IN UINTN                      VtdUnitBaseAddress
  );

/**
  @brief This function is to clear Global Command Register Bits.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.
  @param[in] BitMask                Bit mask.
**/
VOID
VtdLibClearGlobalCommandRegisterBits (
  IN UINTN                      VtdUnitBaseAddress,
  IN UINT32                     BitMask
  );

/**
  @brief This function is to set VTd Global Command Register Bits.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.
  @param[in] BitMask                Bit mask.
**/
VOID
VtdLibSetGlobalCommandRegisterBits (
  IN UINTN                      VtdUnitBaseAddress,
  IN UINT32                     BitMask
  );

/**
  @brief This function is to disable DMAR.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.

  @retval EFI_SUCCESS               DMAR translation is disabled.
**/
EFI_STATUS
VtdLibDisableDmar (
  IN UINTN                      VtdUnitBaseAddress
  );

/**
  @brief This function is to disable PMR.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.

  @retval EFI_SUCCESS               PMR is disabled.
  @retval EFI_UNSUPPORTED           PMR is not supported.
  @retval EFI_NOT_STARTED           PMR was not enabled.
**/
EFI_STATUS
VtdLibDisablePmr (
  IN UINTN                      VtdUnitBaseAddress
  );

/**
  @brief This function is to disable queued invalidation interface

  [Introduction]
    Disable queued invalidation interface.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.
**/
VOID
VtdLibDisableQueuedInvalidationInterface (
  IN UINTN                      VtdUnitBaseAddress
  );

/**
  @brief This function is to submit a queued invalidation descriptor

  [Introduction]
    Submit the queued invalidation descriptor to the remapping
    hardware unit and wait for its completion.

  [Consumption]
    Operate VTd engine

  @param[in] VtdUnitBaseAddress     The base address of the VTd engine.
  @param[in] Desc                   The invalidate descriptor
  @param[in] ClearFaultBits         TRUE  - This API will clear the queued invalidation fault bits if any.
                                    FALSE - The caller need to check and clear the queued invalidation fault bits.

  @retval EFI_SUCCESS               The operation was successful.
  @retval RETURN_DEVICE_ERROR       A fault is detected.
  @retval EFI_INVALID_PARAMETER     Parameter is invalid.
  @retval EFI_DEVICE_ERROR          Detect fault, need to clear fault bits if ClearFaultBits is FALSE
**/
EFI_STATUS
VtdLibSubmitQueuedInvalidationDescriptor (
  IN UINTN                      VtdUnitBaseAddress,
  IN VOID                       *Desc,
  IN BOOLEAN                    ClearFaultBits
  );

#endif
