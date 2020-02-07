/** @file
  Source code file for Platform Init PEI module

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __SHADOW_MICROCODE_PEI_H__
#define __SHADOW_MICROCODE_PEI_H__


#include <PiPei.h>
#include <Ppi/ShadowMicrocode.h>
#include <Library/PeiServicesLib.h>
#include <Library/HobLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <IndustryStandard/FirmwareInterfaceTable.h>
#include <Register/Intel/Microcode.h>
#include <Register/Intel/Cpuid.h>
#include <Guid/MicrocodeShadowInfoHob.h>
//
// Data structure for microcode patch information
//
typedef struct {
  UINTN    Address;
  UINTN    Size;
} MICROCODE_PATCH_INFO;

/**
  Shadow microcode update patches to memory.

  The function is used for shadowing microcode update patches to a continuous memory.
  It shall allocate memory buffer and only shadow the microcode patches for those
  processors specified by CpuData array. The checksum verification may be skiped in
  this function so the caller must perform checksum verification before using the
  microcode patches in returned memory buffer.

  @param[in]  This                 The PPI instance pointer.
  @param[in]  CpuDataCount         Number of elements in CpuData array.
  @param[in]  CpuInfo              A pointer to an array of EDKII_PEI_CPU_ID_INFO
                                   structures.
  @param[out] BufferSize           Pointer to receive the total size of Buffer.
  @param[out] Buffer               Pointer to receive address of allocated memory
                                   with microcode patches data in it.

  @retval EFI_SUCCESS              The microcode has been shadowed to memory.
  @retval EFI_OUT_OF_RESOURCES     The operation fails due to lack of resources.

**/
EFI_STATUS
ShadowMicrocode (
  IN  EDKII_PEI_SHADOW_MICROCODE_PPI        *This,
  IN  UINTN                                 CpuCount,
  IN  EDKII_PEI_CPU_ID_INFO                 *CpuInfo,
  OUT UINTN                                 *BufferSize,
  OUT VOID                                  **Buffer
  );

#endif
