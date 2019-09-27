/** @file

  Copyright (c) 2017 - 2023, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "DmaProtection.h"

/**
  Create extended context entry.

  @param[in]  VtdIndex  The index of the VTd engine.

  @retval EFI_SUCCESS          The extended context entry is created.
  @retval EFI_OUT_OF_RESOURCE  No enough resource to create extended context entry.
**/
EFI_STATUS
CreateExtContextEntry (
  IN UINTN  VtdIndex
  )
{
  UINTN                  Index;
  VOID                   *Buffer;
  UINTN                  RootPages;
  UINTN                  ContextPages;
  VTD_EXT_ROOT_ENTRY     *ExtRootEntry;
  VTD_EXT_CONTEXT_ENTRY  *ExtContextEntryTable;
  VTD_EXT_CONTEXT_ENTRY  *ExtContextEntry;
  VTD_SOURCE_ID          *PciSourceId;
  VTD_SOURCE_ID          SourceId;
  UINTN                  MaxBusNumber;
  UINTN                  EntryTablePages;

  MaxBusNumber = 0;
  for (Index = 0; Index < mVtdUnitInformation[VtdIndex].PciDeviceInfo->PciDeviceDataNumber; Index++) {
    PciSourceId = &mVtdUnitInformation[VtdIndex].PciDeviceInfo->PciDeviceData[Index].PciSourceId;
    if (PciSourceId->Bits.Bus > MaxBusNumber) {
      MaxBusNumber = PciSourceId->Bits.Bus;
    }
  }
  DEBUG ((DEBUG_INFO,"  MaxBusNumber - 0x%x\n", MaxBusNumber));

  RootPages = EFI_SIZE_TO_PAGES (sizeof (VTD_EXT_ROOT_ENTRY) * VTD_ROOT_ENTRY_NUMBER);
  ContextPages = EFI_SIZE_TO_PAGES (sizeof (VTD_EXT_CONTEXT_ENTRY) * VTD_CONTEXT_ENTRY_NUMBER);
  EntryTablePages = RootPages + ContextPages * (MaxBusNumber + 1);
  Buffer = AllocateZeroPages (EntryTablePages);
  if (Buffer == NULL) {
    DEBUG ((DEBUG_INFO,"Could not Alloc Root Entry Table.. \n"));
    return EFI_OUT_OF_RESOURCES;
  }
  mVtdUnitInformation[VtdIndex].ExtRootEntryTable = (VTD_EXT_ROOT_ENTRY *)Buffer;
  Buffer = (UINT8 *)Buffer + EFI_PAGES_TO_SIZE (RootPages);

  for (Index = 0; Index < mVtdUnitInformation[VtdIndex].PciDeviceInfo->PciDeviceDataNumber; Index++) {
    PciSourceId = &mVtdUnitInformation[VtdIndex].PciDeviceInfo->PciDeviceData[Index].PciSourceId;

    SourceId.Bits.Bus = PciSourceId->Bits.Bus;
    SourceId.Bits.Device = PciSourceId->Bits.Device;
    SourceId.Bits.Function = PciSourceId->Bits.Function;

    ExtRootEntry = &mVtdUnitInformation[VtdIndex].ExtRootEntryTable[SourceId.Index.RootIndex];
    if (ExtRootEntry->Bits.LowerPresent == 0) {
      ExtRootEntry->Bits.LowerContextTablePointerLo  = (UINT32) RShiftU64 ((UINT64)(UINTN)Buffer, 12);
      ExtRootEntry->Bits.LowerContextTablePointerHi  = (UINT32) RShiftU64 ((UINT64)(UINTN)Buffer, 32);
      ExtRootEntry->Bits.LowerPresent = 1;
      ExtRootEntry->Bits.UpperContextTablePointerLo  = (UINT32) RShiftU64 ((UINT64)(UINTN)Buffer, 12) + 1;
      ExtRootEntry->Bits.UpperContextTablePointerHi  = (UINT32) RShiftU64 (RShiftU64 ((UINT64)(UINTN)Buffer, 12) + 1, 20);
      ExtRootEntry->Bits.UpperPresent = 1;
      Buffer = (UINT8 *)Buffer + EFI_PAGES_TO_SIZE (ContextPages);
    }

    ExtContextEntryTable = (VTD_EXT_CONTEXT_ENTRY *)(UINTN)VTD_64BITS_ADDRESS(ExtRootEntry->Bits.LowerContextTablePointerLo, ExtRootEntry->Bits.LowerContextTablePointerHi) ;
    ExtContextEntry = &ExtContextEntryTable[SourceId.Index.ContextIndex];
    ExtContextEntry->Bits.TranslationType = 0;
    ExtContextEntry->Bits.FaultProcessingDisable = 0;
    ExtContextEntry->Bits.Present = 0;

    DEBUG ((DEBUG_INFO,"DOMAIN: S%04x, B%02x D%02x F%02x\n", mVtdUnitInformation[VtdIndex].Segment, SourceId.Bits.Bus, SourceId.Bits.Device, SourceId.Bits.Function));

    mVtdUnitInformation[VtdIndex].Is5LevelPaging = FALSE;
    if ((mVtdUnitInformation[VtdIndex].CapReg.Bits.SAGAW & BIT3) != 0) {
      mVtdUnitInformation[VtdIndex].Is5LevelPaging = TRUE;
      if ((mAcpiDmarTable->HostAddressWidth <= 48) &&
          ((mVtdUnitInformation[VtdIndex].CapReg.Bits.SAGAW & BIT2) != 0)) {
        mVtdUnitInformation[VtdIndex].Is5LevelPaging = FALSE;
      }
    } else if ((mVtdUnitInformation[VtdIndex].CapReg.Bits.SAGAW & BIT2) == 0) {
      DEBUG((DEBUG_ERROR, "!!!! Page-table type is not supported on VTD %d !!!!\n", VtdIndex));
      return EFI_UNSUPPORTED;
    }

    if (mVtdUnitInformation[VtdIndex].Is5LevelPaging) {
      ExtContextEntry->Bits.AddressWidth = 0x3;
      DEBUG((DEBUG_INFO, "Using 5-level page-table on VTD %d\n", VtdIndex));
    } else {
      ExtContextEntry->Bits.AddressWidth = 0x2;
      DEBUG((DEBUG_INFO, "Using 4-level page-table on VTD %d\n", VtdIndex));
    }


  }

  FlushPageTableMemory (VtdIndex, (UINTN)mVtdUnitInformation[VtdIndex].ExtRootEntryTable, EFI_PAGES_TO_SIZE(EntryTablePages));

  return EFI_SUCCESS;
}

