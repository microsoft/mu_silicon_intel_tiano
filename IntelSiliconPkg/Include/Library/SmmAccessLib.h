/** @file
  Header file for SMM Access Driver.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#ifndef _SMM_ACCESS_LIB_H_
#define _SMM_ACCESS_LIB_H_

/**
  This function is to install an SMM Access PPI
  - <b>Introduction</b> \n
    A module to install a PPI for controlling SMM mode memory access basically for S3 resume usage.

  - @result
    Publish _PEI_MM_ACCESS_PPI.

    @retval EFI_SUCCESS           - Ppi successfully started and installed.
    @retval EFI_NOT_FOUND         - Ppi can't be found.
    @retval EFI_OUT_OF_RESOURCES  - Ppi does not have enough resources to initialize the driver.
**/
EFI_STATUS
EFIAPI
PeiInstallSmmAccessPpi (
  VOID
  );
#endif
