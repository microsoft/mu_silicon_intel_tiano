/** @file

  Copyright (c) 2023, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PciSegmentLib.h>
#include <IndustryStandard/Vtd.h>
#include <IndustryStandard/Pci.h>
#include <Protocol/IoMmu.h>
#include <Ppi/VtdInfo.h>
#include <Guid/VtdLogDataHob.h>
#include "IntelVTdCorePei.h"

/**
  Parse DMAR DRHD table.

  @param[in]  AcpiDmarTable     DMAR ACPI table
  @param[in]  Callback          Callback function for handle DRHD
  @param[in]  Context           Callback function Context

  @return the VTd engine number.

**/
UINTN
ParseDmarAcpiTableDrhd (
  IN EFI_ACPI_DMAR_HEADER               *AcpiDmarTable,
  IN PROCESS_DRHD_CALLBACK_FUNC         Callback,
  IN VOID                               *Context
  )
{
  EFI_ACPI_DMAR_STRUCTURE_HEADER        *DmarHeader;
  UINTN                                 VtdIndex;

  VtdIndex = 0;
  DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *) ((UINTN) (AcpiDmarTable + 1));

  while ((UINTN) DmarHeader < (UINTN) AcpiDmarTable + AcpiDmarTable->Header.Length) {
    switch (DmarHeader->Type) {
    case EFI_ACPI_DMAR_TYPE_DRHD:
      if (Callback != NULL) {
        Callback (Context, VtdIndex, (EFI_ACPI_DMAR_DRHD_HEADER *) DmarHeader);
      }
      VtdIndex++;
      break;
    default:
      break;
    }
    DmarHeader = (EFI_ACPI_DMAR_STRUCTURE_HEADER *) ((UINTN) DmarHeader + DmarHeader->Length);
  }

  return VtdIndex;
}

