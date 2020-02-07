/** @file
  Source code file for Platform Init PEI module

Copyright (c) 2017 - 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "ShadowMicrocodePei.h"

EDKII_PEI_SHADOW_MICROCODE_PPI   mPeiShadowMicrocodePpi = {
  ShadowMicrocode
};


EFI_PEI_PPI_DESCRIPTOR           mPeiShadowMicrocodePpiList[] = {
  {
    EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST,
    &gEdkiiPeiShadowMicrocodePpiGuid,
    &mPeiShadowMicrocodePpi
  }
};

/**
  Determine if a microcode patch matchs the specific processor signature and flag.

  @param[in]  CpuMpData             The pointer to CPU MP Data structure.
  @param[in]  ProcessorSignature    The processor signature field value
                                    supported by a microcode patch.
  @param[in]  ProcessorFlags        The prcessor flags field value supported by
                                    a microcode patch.

  @retval TRUE     The specified microcode patch will be loaded.
  @retval FALSE    The specified microcode patch will not be loaded.
**/
BOOLEAN
IsProcessorMatchedMicrocodePatch (
  IN  UINTN                      CpuCount,
  IN  EDKII_PEI_CPU_ID_INFO      *CpuInfo,
  IN UINT32                      ProcessorSignature,
  IN UINT32                      ProcessorFlags
  )
{
  UINTN          Index;

  for (Index = 0; Index < CpuCount; Index++) {
    if ((ProcessorSignature == CpuInfo[Index].ProcessorSignature) &&
        (ProcessorFlags & (1 << CpuInfo[Index].PlatformId)) != 0) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Check the 'ProcessorSignature' and 'ProcessorFlags' of the microcode
  patch header with the CPUID and PlatformID of the processors within
  system to decide if it will be copied into memory.

  @param[in]  CpuMpData             The pointer to CPU MP Data structure.
  @param[in]  MicrocodeEntryPoint   The pointer to the microcode patch header.

  @retval TRUE     The specified microcode patch need to be loaded.
  @retval FALSE    The specified microcode patch dosen't need to be loaded.
**/
BOOLEAN
IsMicrocodePatchNeedLoad (
  IN  UINTN                      CpuCount,
  IN  EDKII_PEI_CPU_ID_INFO      *CpuInfo,
  CPU_MICROCODE_HEADER           *MicrocodeEntryPoint
  )
{
  BOOLEAN                                NeedLoad;
  UINTN                                  DataSize;
  UINTN                                  TotalSize;
  CPU_MICROCODE_EXTENDED_TABLE_HEADER    *ExtendedTableHeader;
  UINT32                                 ExtendedTableCount;
  CPU_MICROCODE_EXTENDED_TABLE           *ExtendedTable;
  UINTN                                  Index;

  //
  // Check the 'ProcessorSignature' and 'ProcessorFlags' in microcode patch header.
  //
  NeedLoad = IsProcessorMatchedMicrocodePatch (
               CpuCount,
               CpuInfo,
               MicrocodeEntryPoint->ProcessorSignature.Uint32,
               MicrocodeEntryPoint->ProcessorFlags
               );

  //
  // If the Extended Signature Table exists, check if the processor is in the
  // support list
  //
  DataSize  = MicrocodeEntryPoint->DataSize;
  TotalSize = (DataSize == 0) ? 2048 : MicrocodeEntryPoint->TotalSize;
  if ((!NeedLoad) && (DataSize != 0) &&
      (TotalSize - DataSize > sizeof (CPU_MICROCODE_HEADER) +
                              sizeof (CPU_MICROCODE_EXTENDED_TABLE_HEADER))) {
    ExtendedTableHeader = (CPU_MICROCODE_EXTENDED_TABLE_HEADER *) ((UINT8 *) (MicrocodeEntryPoint)
                            + DataSize + sizeof (CPU_MICROCODE_HEADER));
    ExtendedTableCount  = ExtendedTableHeader->ExtendedSignatureCount;
    ExtendedTable       = (CPU_MICROCODE_EXTENDED_TABLE *) (ExtendedTableHeader + 1);

    for (Index = 0; Index < ExtendedTableCount; Index ++) {
      //
      // Check the 'ProcessorSignature' and 'ProcessorFlag' of the Extended
      // Signature Table entry with the CPUID and PlatformID of the processors
      // within system to decide if it will be copied into memory
      //
      NeedLoad = IsProcessorMatchedMicrocodePatch (
                   CpuCount,
                   CpuInfo,
                   ExtendedTable->ProcessorSignature.Uint32,
                   ExtendedTable->ProcessorFlag
                   );
      if (NeedLoad) {
        break;
      }
      ExtendedTable ++;
    }
  }

  return NeedLoad;
}

/**
  Actual worker function that shadows the required microcode patches into memory.

  @param[in, out]  CpuMpData        The pointer to CPU MP Data structure.
  @param[in]       Patches          The pointer to an array of information on
                                    the microcode patches that will be loaded
                                    into memory.
  @param[in]       PatchCount       The number of microcode patches that will
                                    be loaded into memory.
  @param[in]       TotalLoadSize    The total size of all the microcode patches
                                    to be loaded.
**/
VOID
ShadowMicrocodePatchWorker (
  IN  MICROCODE_PATCH_INFO       *Patches,
  IN  UINTN                      PatchCount,
  IN  UINTN                      TotalLoadSize,
  OUT UINTN                      *BufferSize,
  OUT VOID                       **Buffer
  )
{
  UINTN                              Index;
  VOID                               *MicrocodePatchInRam;
  UINT8                              *Walker;
  EDKII_MICROCODE_SHADOW_INFO_HOB    *MicrocodeShadowHob;
  UINTN                              HobDataLength;
  UINT64                             *MicrocodeAddrInMemory;
  UINT64                             *MicrocodeAddrInFlash;

  ASSERT ((Patches != NULL) && (PatchCount != 0));

  //
  // Init microcode shadow info HOB content.
  //
  HobDataLength = sizeof (EDKII_MICROCODE_SHADOW_INFO_HOB) +
                  sizeof (UINT64) * PatchCount * 2;
  MicrocodeShadowHob  = AllocatePool (HobDataLength);
  if (MicrocodeShadowHob == NULL) {
    ASSERT (FALSE);
    return;
  }
  MicrocodeShadowHob->MicrocodeCount = PatchCount;
  CopyGuid (
    &MicrocodeShadowHob->StorageType,
    &gEdkiiMicrocodeStorageTypeFlashGuid
    );
  MicrocodeAddrInMemory = (UINT64 *) (MicrocodeShadowHob + 1);
  MicrocodeAddrInFlash  = MicrocodeAddrInMemory + PatchCount;

  //
  // Allocate memory for microcode shadow operation.
  //
  MicrocodePatchInRam = AllocatePages (EFI_SIZE_TO_PAGES (TotalLoadSize));
  if (MicrocodePatchInRam == NULL) {
    ASSERT (FALSE);
    return;
  }

  //
  // Shadow all the required microcode patches into memory
  //
  for (Walker = MicrocodePatchInRam, Index = 0; Index < PatchCount; Index++) {
    CopyMem (
      Walker,
      (VOID *) Patches[Index].Address,
      Patches[Index].Size
      );
    MicrocodeAddrInMemory[Index] = (UINT64) Walker;
    MicrocodeAddrInFlash[Index]  = (UINT64) Patches[Index].Address;
    Walker += Patches[Index].Size;
  }
  
  //
  // Update the microcode patch related fields in CpuMpData
  //
  *Buffer     = (VOID *) (UINTN) MicrocodePatchInRam;
  *BufferSize = TotalLoadSize;

  BuildGuidDataHob (
    &gEdkiiMicrocodeShadowInfoHobGuid,
    MicrocodeShadowHob,
    HobDataLength
    );

  DEBUG ((
    DEBUG_INFO,
    "%a: Required microcode patches have been loaded at 0x%lx, with size 0x%lx.\n",
    __FUNCTION__, *Buffer, *BufferSize
    ));

  return;
}

/**
  Shadow the required microcode patches data into memory according to FIT microcode entry.

  @param[in, out]  CpuMpData    The pointer to CPU MP Data structure.

  @return EFI_SUCCESS           Microcode patch is shadowed into memory.
  @return EFI_UNSUPPORTED       FIT based microcode shadowing is not supported.
  @return EFI_OUT_OF_RESOURCES  No enough memory resource.
  @return EFI_NOT_FOUND         There is something wrong in FIT microcode entry.

**/
EFI_STATUS
ShadowMicrocodePatchByFit (
  IN  UINTN                                 CpuCount,
  IN  EDKII_PEI_CPU_ID_INFO                 *CpuInfo,
  OUT UINTN                                 *BufferSize,
  OUT VOID                                  **Buffer
  )
{
  UINT64                            FitPointer;
  FIRMWARE_INTERFACE_TABLE_ENTRY    *FitEntry;
  UINT32                            EntryNum;
  UINT32                            Index;
  MICROCODE_PATCH_INFO              *PatchInfoBuffer;
  UINTN                             MaxPatchNumber;
  CPU_MICROCODE_HEADER              *MicrocodeEntryPoint;
  UINTN                             PatchCount;
  UINTN                             TotalSize;
  UINTN                             TotalLoadSize;

  FitPointer = *(UINT64 *) (UINTN) FIT_POINTER_ADDRESS;
  if ((FitPointer == 0) ||
      (FitPointer == 0xFFFFFFFFFFFFFFFF) ||
      (FitPointer == 0xEEEEEEEEEEEEEEEE)) {
    //
    // No FIT table.
    //
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }
  FitEntry = (FIRMWARE_INTERFACE_TABLE_ENTRY *) (UINTN) FitPointer;
  if ((FitEntry[0].Type != FIT_TYPE_00_HEADER) ||
      (FitEntry[0].Address != FIT_TYPE_00_SIGNATURE)) {
    //
    // Invalid FIT table, treat it as no FIT table.
    //
    ASSERT (FALSE);
    return EFI_NOT_FOUND;
  }

  EntryNum = *(UINT32 *)(&FitEntry[0].Size[0]) & 0xFFFFFF;

  //
  // Calculate microcode entry number
  //
  MaxPatchNumber = 0;
  for (Index = 0; Index < EntryNum; Index++) {
    if (FitEntry[Index].Type == FIT_TYPE_01_MICROCODE) {
      MaxPatchNumber++;
    }
  }
  if (MaxPatchNumber == 0) {
    return EFI_NOT_FOUND;
  }

  PatchInfoBuffer = AllocatePool (MaxPatchNumber * sizeof (MICROCODE_PATCH_INFO));
  if (PatchInfoBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Fill up microcode patch info buffer according to FIT table.
  //
  PatchCount = 0;
  TotalLoadSize = 0;
  for (Index = 0; Index < EntryNum; Index++) {
    if (FitEntry[Index].Type == FIT_TYPE_01_MICROCODE) {
      MicrocodeEntryPoint = (CPU_MICROCODE_HEADER *) (UINTN) FitEntry[Index].Address;
      TotalSize = (MicrocodeEntryPoint->DataSize == 0) ? 2048 : MicrocodeEntryPoint->TotalSize;
      if (IsMicrocodePatchNeedLoad (CpuCount, CpuInfo, MicrocodeEntryPoint)) {
        PatchInfoBuffer[PatchCount].Address     = (UINTN) MicrocodeEntryPoint;
        PatchInfoBuffer[PatchCount].Size        = TotalSize;
        TotalLoadSize += TotalSize;
        PatchCount++;
      }
    }
  }

  if (PatchCount != 0) {
    DEBUG ((
      DEBUG_INFO,
      "%a: 0x%x microcode patches will be loaded into memory, with size 0x%x.\n",
      __FUNCTION__, PatchCount, TotalLoadSize
      ));

    ShadowMicrocodePatchWorker (PatchInfoBuffer, PatchCount, TotalLoadSize, BufferSize, Buffer);
  }

  FreePool (PatchInfoBuffer);
  return EFI_SUCCESS;
}


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
  )
{
  if (BufferSize == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  return ShadowMicrocodePatchByFit (CpuCount, CpuInfo, BufferSize, Buffer);
}


/**
  Platform Init PEI module entry point

  @param[in]  FileHandle           Not used.
  @param[in]  PeiServices          General purpose services available to every PEIM.

  @retval     EFI_SUCCESS          The function completes successfully
  @retval     EFI_OUT_OF_RESOURCES Insufficient resources to create database
**/
EFI_STATUS
EFIAPI
ShadowMicrocodePeimInit (
  IN       EFI_PEI_FILE_HANDLE  FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  EFI_STATUS                       Status;

  //
  // Install EDKII Shadow Microcode PPI
  //
  Status = PeiServicesInstallPpi(mPeiShadowMicrocodePpiList);
  ASSERT_EFI_ERROR (Status);
  
  return Status;
}
