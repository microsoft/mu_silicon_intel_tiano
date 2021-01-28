/** @file
Library interface to retrieve structured records from Intel's FIT
Reference:
https://edc.intel.com/content/www/us/en/design/products-and-solutions/software-and-services/firmware-and-bios/firmware-interface-table/1.2/

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/


#ifndef _FIT_QUERY_LIB_H_
#define _FIT_QUERY_LIB_H_

#include <IndustryStandard/FirmwareInterfaceTable.h>  // IntelSiliconPkg

#pragma pack(push, 1)
typedef struct _FIT_QUERY_RESULT {
    UINT64      BaseAddress;
    UINT32      Size;
} FIT_QUERY_RESULT;
#pragma pack(pop)

typedef UINT8                           FIT_ENTRY_TYPE;
#define FIT_TYPE_PLAT_MIN               (FIT_ENTRY_TYPE)(0x30)
#define FIT_TYPE_PLAT_MAX               (FIT_ENTRY_TYPE)(0x70)

#define GET_SIZE_FROM_FIT_ENTRY(FitEntry) \
    ((*((UINT32*)(&FitEntry.Size))) & 0x00FFFFFF)

/**
  This helper will walk the FIT and locate a record.

  @param[in]  RecordType    The type identifier of the record.
  @param[in]  RecordIndex   For records that allow multiple entries, this is the entry
                            being requested. 0-based.
  @param[out] Result        Pointer to the FIT_QUERY_RESULT output structure.

  @retval     EFI_SUCCESS             Record was returned.
  @retval     EFI_INVALID_PARAMETER   RecordType does not match a known record.
  @retval     EFI_INVALID_PARAMETER   Return pointer parameter is NULL.
  @retval     EFI_COMPROMISED_DATA    Could not locate the FIT at all.
  @retval     EFI_NOT_FOUND           A matching record could not be found.

**/
EFI_STATUS
EFIAPI
GetFitRecord (
  IN UINT8                  RecordType,
  IN UINT16                 RecordIndex,
  OUT FIT_QUERY_RESULT      *Result
  );

#endif // _FIT_QUERY_LIB_H_
