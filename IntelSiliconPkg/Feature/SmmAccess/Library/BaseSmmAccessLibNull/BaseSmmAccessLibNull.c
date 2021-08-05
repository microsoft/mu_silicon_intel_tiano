/** @file
  A NULL library instance of SmmAccessLib.

  Copyright (c) 2019 - 2020, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

// MU_CHANGE - WHOLE FILE - TCBZ3540

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/SmmAccessLib.h>

/**
  This function is to install an SMM Access PPI

  @retval EFI_SUCCESS           - Ppi successfully started and installed.
  @retval EFI_NOT_FOUND         - Ppi can't be found.
  @retval EFI_OUT_OF_RESOURCES  - Ppi does not have enough resources to initialize the driver.
  @retval EFI_UNSUPPORTED       - The PPI was not installed and installation is unsupported in
                                  this instance of function implementation.

**/
EFI_STATUS
EFIAPI
PeiInstallSmmAccessPpi (
  VOID
  )
{
  ASSERT (FALSE);
  return EFI_UNSUPPORTED;
}
