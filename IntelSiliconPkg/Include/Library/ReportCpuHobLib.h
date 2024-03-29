/** @file

  Report CPU HOB library

  This library report the CPU HOB with Physical Address bits.

Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _REPORT_CPU_HOB_LIB_H_
#define _REPORT_CPU_HOB_LIB_H_

#include <BaseTypes.h>

/**
  Build a HOB for the CPU.
**/
VOID
EFIAPI
ReportCpuHob (
  VOID
  );

#endif
