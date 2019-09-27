/** @file
  TCG Device Event data structure
Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent
**/


#ifndef __TCG_EVENT_DATA_H__
#define __TCG_EVENT_DATA_H__

#include <IndustryStandard/Spdm.h>

#pragma pack(1)

// -------------------------------------------
// TCG Measurement for SPDM Device Measurement
// -------------------------------------------

//
// Device Firmware Component (including immutable ROM or mutable firmware)
//
#define EDKII_DEVICE_MEASUREMENT_COMPONENT_PCR_INDEX        2
#define EDKII_DEVICE_MEASUREMENT_COMPONENT_EVENT_TYPE       0x800000E1
//
// Device Firmware Configuration (including hardware configuration or firmware configuration)
//
#define EDKII_DEVICE_MEASUREMENT_CONFIGURATION_PCR_INDEX    4
#define EDKII_DEVICE_MEASUREMENT_CONFIGURATION_EVENT_TYPE   0x800000E2

//
// Device Firmware Measurement Measurement Data
// The measurement data is the device firmware measurement.
//
// In order to support crypto agile, the firmware will hash the DeviceMeasurement again.
// As such the device measurement algo might be different with host firmware measurement algo.
//

//
// Device Firmware Measurement Event Data
//
#define EDKII_DEVICE_SECURITY_EVENT_DATA_SIGNATURE "SPDM Device Sec\0"
#define EDKII_DEVICE_SECURITY_EVENT_DATA_VERSION  0

//
// Device Type
// 0x03 ~ 0xDF reserved by TCG.
// 0xE0 ~ 0xFF reserved by OEM.
//
#define EDKII_DEVICE_SECURITY_EVENT_DATA_DEVICE_TYPE_NULL  0
#define EDKII_DEVICE_SECURITY_EVENT_DATA_DEVICE_TYPE_PCI   1
#define EDKII_DEVICE_SECURITY_EVENT_DATA_DEVICE_TYPE_USB   2

//
// Device Firmware Measurement Event Data Common Part
// The device specific part should follow this data structure.
//
typedef struct {
  //
  // It must be EDKII_DEVICE_SECURITY_EVENT_DATA_SIGNATURE.
  //
  UINT8                          Signature[16];
  //
  // It must be EDKII_DEVICE_SECURITY_EVENT_DATA_VERSION.
  //
  UINT16                         Version;
  //
  // The length of whole data structure, including Device Context.
  //
  UINT16                         Length;
  //
  // The SpdmHashAlgo
  //
  UINT32                         SpdmHashAlgo;
  //
  // The type of device. This field is to determine the Device Context followed by.
  //
  UINT32                         DeviceType;
  //
  // The SPDM measurement block.
  //
//SPDM_MEASUREMENT_BLOCK         SpdmMeasurementBlock;
} EDKII_DEVICE_SECURITY_EVENT_DATA_HEADER;

//
// PCI device specific context
//
#define EDKII_DEVICE_SECURITY_EVENT_DATA_PCI_CONTEXT_VERSION  0
typedef struct {
  UINT16  Version;
  UINT16  Length;
  UINT16  VendorId;
  UINT16  DeviceId;
  UINT8   RevisionID;
  UINT8   ClassCode[3];
  UINT16  SubsystemVendorID;
  UINT16  SubsystemID;
} EDKII_DEVICE_SECURITY_EVENT_DATA_PCI_CONTEXT;

#pragma pack()

#endif
