## @file
# This package provides common open source Intel silicon modules.
#
# Copyright (c) 2017 - 2021, Intel Corporation. All rights reserved.<BR>
# Copyright (c) Microsoft Corporation.<BR>
#
#    SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  PLATFORM_NAME                  = IntelSiliconPkg
  PLATFORM_GUID                  = 9B96228E-1155-4967-8E16-D0ED8E1B4297
  PLATFORM_VERSION               = 0.1
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/IntelSiliconPkg
  SUPPORTED_ARCHITECTURES        = IA32|X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

!include MdePkg/MdeLibs.dsc.inc

[LibraryClasses]
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  ReportStatusCodeLib|MdePkg/Library/BaseReportStatusCodeLibNull/BaseReportStatusCodeLibNull.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  PciSegmentLib|MdePkg/Library/BasePciSegmentLibPci/BasePciSegmentLibPci.inf
  PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  UefiDecompressLib|MdePkg/Library/BaseUefiDecompressLib/BaseUefiDecompressLib.inf
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  SerialPortLib|MdePkg/Library/BaseSerialPortLibNull/BaseSerialPortLibNull.inf
  CacheMaintenanceLib|MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib.inf
  MicrocodeFlashAccessLib|IntelSiliconPkg/Feature/Capsule/Library/MicrocodeFlashAccessLibNull/MicrocodeFlashAccessLibNull.inf
  PeiGetVtdPmrAlignmentLib|IntelSiliconPkg/Library/PeiGetVtdPmrAlignmentLib/PeiGetVtdPmrAlignmentLib.inf
  TpmMeasurementLib|MdeModulePkg/Library/TpmMeasurementLibNull/TpmMeasurementLibNull.inf
  MicrocodeLib|UefiCpuPkg/Library/MicrocodeLib/MicrocodeLib.inf
  SafeIntLib|MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  SpiFlashCommonLib|IntelSiliconPkg/Library/SpiFlashCommonLibNull/SpiFlashCommonLibNull.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  VariableFlashInfoLib|MdeModulePkg/Library/BaseVariableFlashInfoLib/BaseVariableFlashInfoLib.inf
  IntelVTdPeiDxeLib|IntelSiliconPkg/Library/IntelVTdPeiDxeLib/IntelVTdPeiDxeLib.inf
  NULL|MdePkg/Library/StackCheckLibNull/StackCheckLibNull.inf # MU_CHANGE: /GS and -fstack-protector support

[LibraryClasses.common.PEIM]
  PeimEntryPoint|MdePkg/Library/PeimEntryPoint/PeimEntryPoint.inf
  PeiServicesTablePointerLib|MdePkg/Library/PeiServicesTablePointerLib/PeiServicesTablePointerLib.inf
  PeiServicesLib|MdePkg/Library/PeiServicesLib/PeiServicesLib.inf

  MemoryAllocationLib|MdePkg/Library/PeiMemoryAllocationLib/PeiMemoryAllocationLib.inf
  HobLib|MdePkg/Library/PeiHobLib/PeiHobLib.inf

[LibraryClasses.common.DXE_DRIVER]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf

  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf

[LibraryClasses.common.DXE_SMM_DRIVER]
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  MemoryAllocationLib|MdePkg/Library/SmmMemoryAllocationLib/SmmMemoryAllocationLib.inf
  MmServicesTableLib|MdePkg/Library/MmServicesTableLib/MmServicesTableLib.inf
  SmmServicesTableLib|MdePkg/Library/SmmServicesTableLib/SmmServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

[LibraryClasses.common.MM_STANDALONE]
  HobLib|StandaloneMmPkg/Library/StandaloneMmHobLib/StandaloneMmHobLib.inf
  MemoryAllocationLib|StandaloneMmPkg/Library/StandaloneMmMemoryAllocationLib/StandaloneMmMemoryAllocationLib.inf
  MmServicesTableLib|MdePkg/Library/StandaloneMmServicesTableLib/StandaloneMmServicesTableLib.inf
  StandaloneMmDriverEntryPoint|MdePkg/Library/StandaloneMmDriverEntryPoint/StandaloneMmDriverEntryPoint.inf

###################################################################################################
#
# Components Section - list of the modules and components that will be processed by compilation
#                      tools and the EDK II tools to generate PE32/PE32+/Coff image files.
#
# Note: The EDK II DSC file is not used to specify how compiled binary images get placed
#       into firmware volume images. This section is just a list of modules to compile from
#       source into UEFI-compliant binaries.
#       It is the FDF file that contains information on combining binary files into firmware
#       volume images, whose concept is beyond UEFI and is described in PI specification.
#       Binary modules do not need to be listed in this section, as they should be
#       specified in the FDF file. For example: Shell binary (Shell_Full.efi), FAT binary (Fat.efi),
#       Logo (Logo.bmp), and etc.
#       There may also be modules listed in this section that are not required in the FDF file,
#       When a module listed here is excluded from FDF file, then UEFI-compliant binary will be
#       generated for it, but the binary will not be put into any firmware volume.
#
###################################################################################################

[Components]
  IntelSiliconPkg/Library/DxeSmbiosDataHobLib/DxeSmbiosDataHobLib.inf
  IntelSiliconPkg/Feature/PcieSecurity/IntelPciDeviceSecurityDxe/IntelPciDeviceSecurityDxe.inf
  IntelSiliconPkg/Feature/PcieSecurity/SamplePlatformDevicePolicyDxe/SamplePlatformDevicePolicyDxe.inf
  IntelSiliconPkg/Feature/Flash/SpiFvbService/SpiFvbServiceSmm.inf
  IntelSiliconPkg/Feature/Flash/SpiFvbService/SpiFvbServiceStandaloneMm.inf
  IntelSiliconPkg/Feature/VTd/IntelVTdDxe/IntelVTdDxe.inf
  IntelSiliconPkg/Feature/VTd/IntelVTdDmarPei/IntelVTdDmarPei.inf
  IntelSiliconPkg/Feature/VTd/IntelVTdPmrPei/IntelVTdPmrPei.inf
  IntelSiliconPkg/Feature/VTd/PlatformVTdSampleDxe/PlatformVTdSampleDxe.inf
  IntelSiliconPkg/Feature/VTd/PlatformVTdInfoSamplePei/PlatformVTdInfoSamplePei.inf
  IntelSiliconPkg/Feature/Capsule/MicrocodeUpdateDxe/MicrocodeUpdateDxe.inf
  IntelSiliconPkg/Feature/Capsule/Library/MicrocodeFlashAccessLibNull/MicrocodeFlashAccessLibNull.inf
  IntelSiliconPkg/Feature/ShadowMicrocode/ShadowMicrocodePei.inf
  IntelSiliconPkg/Library/PeiDxeSmmBootMediaLib/PeiFirmwareBootMediaLib.inf
  IntelSiliconPkg/Library/PeiDxeSmmBootMediaLib/DxeSmmFirmwareBootMediaLib.inf
  IntelSiliconPkg/Library/DxeAslUpdateLib/DxeAslUpdateLib.inf
  IntelSiliconPkg/Library/ReportCpuHobLib/ReportCpuHobLib.inf
  IntelSiliconPkg/Library/SpiFlashCommonLibNull/SpiFlashCommonLibNull.inf
  IntelSiliconPkg/Library/SmmSpiFlashCommonLib/SmmSpiFlashCommonLib.inf

  # MU_CHANGE [BEGIN]
  IntelSiliconPkg/Feature/VTd/IntelVTdCoreDxe/IntelVTdCoreDxe.inf
  IntelSiliconPkg/Feature/VTd/IntelVTdCorePei/IntelVTdCorePei.inf
  IntelSiliconPkg/Library/IntelVTdPeiDxeLib/IntelVTdPeiDxeLib.inf
  IntelSiliconPkg/Library/IntelVTdPeiDxeLib/IntelVTdPeiDxeLibExt.inf

  IntelSiliconPkg/Feature/SmmAccess/Library/BaseSmmAccessLibNull/BaseSmmAccessLibNull.inf   # MU_CHANGE - TCBZ3540
  IntelSiliconPkg/Feature/SmmAccess/Library/PeiSmmAccessLib/PeiSmmAccessLib.inf
  IntelSiliconPkg/Feature/SmmAccess/Library/PeiSmmAccessLibSmramc/PeiSmmAccessLib.inf
  IntelSiliconPkg/Feature/SmmAccess/SmmAccessDxe/SmmAccess.inf
  IntelSiliconPkg/Feature/SmmControl/Library/PeiSmmControlLib/PeiSmmControlLib.inf
  IntelSiliconPkg/Library/PeiGetVtdPmrAlignmentLib/PeiGetVtdPmrAlignmentLib.inf
  IntelSiliconPkg/Library/BaseFitQueryLib/BaseFitQueryLib.inf
  # MU_CHANGE [END]

[BuildOptions]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES

