/** @file -- UefiVariablePolicyUnitTest.c
UnitTest for...
Business logic for Variable Policy enforcement.

Copyright (c) Microsoft Corporation.
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include <Library/BaseLib.h>
#include <Library/FitQueryLib.h>

#ifndef INTERNAL_UNIT_TEST
#error Make sure to build thie with INTERNAL_UNIT_TEST enabled! Otherwise, some important tests may be skipped!
#endif


#define UNIT_TEST_NAME        "FIT Query Lib UnitTest"
#define UNIT_TEST_VERSION     "0.9"

///=== TEST DATA ==================================================================================

STATIC UINT8    MalformedFitData[] = {
  0x5F, 0x46, 0x49, 0x54, 0x5F, 0x30, 0x20, 0x20, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x34,
  0x60, 0x00, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
  0x60, 0x00, 0xB0, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
  0x00, 0x00, 0xE4, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
  0x00, 0x00, 0xFB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x07, 0x00,
  0x00, 0x10, 0xE8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x65, 0x03, 0x00, 0x00, 0x00, 0x01, 0x0B, 0x00,
  0x00, 0x20, 0xE8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x05, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x00,
};

STATIC UINT8    SimpleFitData[] = {
  0x5F, 0x46, 0x49, 0x54, 0x5F, 0x20, 0x20, 0x20, 0x07, 0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x34,
  0x60, 0x00, 0xB8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
  0x60, 0x00, 0xB0, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
  0x00, 0x00, 0xE4, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
  0x00, 0x00, 0xFB, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x07, 0x00,
  0x00, 0x10, 0xE8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x65, 0x03, 0x00, 0x00, 0x00, 0x01, 0x0B, 0x00,
  0x00, 0x20, 0xE8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x05, 0x00, 0x00, 0x00, 0x01, 0x0C, 0x00,
};

///=== HELPER FUNCTIONS ===========================================================================


///=== TEST CASES =================================================================================


///=== INTERNAL PROTOTYPES ========================================================================

EFI_STATUS
InternalGetFitRecord (
  IN CONST FIRMWARE_INTERFACE_TABLE_ENTRY   *FitBase,
  IN UINT8                                  RecordType,
  IN UINT16                                 RecordIndex,
  OUT FIT_QUERY_RESULT                      *Result
  );

///===== INTERNAL FUNCTION SUITE ==============================================

/**
  Test Case
*/
UNIT_TEST_STATUS
EFIAPI
ShouldFailIfFitSigIsBad (
  IN UNIT_TEST_CONTEXT      Context
  )
{
  FIT_QUERY_RESULT    QueryResult;

  UT_ASSERT_STATUS_EQUAL (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)MalformedFitData,
      FIT_TYPE_01_MICROCODE,
      1,
      &QueryResult),
    EFI_COMPROMISED_DATA);

  return UNIT_TEST_PASSED;
}

/**
  Test Case
*/
UNIT_TEST_STATUS
EFIAPI
ShouldFailIfTypeIsUnknown (
  IN UNIT_TEST_CONTEXT      Context
  )
{
  FIT_QUERY_RESULT    QueryResult;

  UT_ASSERT_STATUS_EQUAL (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)SimpleFitData,
      0x14,   // Purposely reserved and undefined type.
      1,
      &QueryResult),
    EFI_INVALID_PARAMETER);

  return UNIT_TEST_PASSED;
}

/**
  Test Case
*/
UNIT_TEST_STATUS
EFIAPI
ShouldReturnTheCorrectRecord (
  IN UNIT_TEST_CONTEXT      Context
  )
{
  FIT_QUERY_RESULT    QueryResult;

  UT_ASSERT_NOT_EFI_ERROR (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)SimpleFitData,
      FIT_TYPE_00_HEADER,
      0,
      &QueryResult));

  UT_ASSERT_EQUAL (QueryResult.Size, 0x7);

  return UNIT_TEST_PASSED;
}

/**
  Test Case
*/
UNIT_TEST_STATUS
EFIAPI
ShouldReturnTheSecondRecordForRepeats (
  IN UNIT_TEST_CONTEXT      Context
  )
{
  FIT_QUERY_RESULT    QueryResult;

  UT_ASSERT_NOT_EFI_ERROR (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)SimpleFitData,
      FIT_TYPE_01_MICROCODE,
      0,
      &QueryResult));

  UT_ASSERT_EQUAL (QueryResult.BaseAddress, 0xFFB80060);
  UT_ASSERT_EQUAL (QueryResult.Size, 0x00);

  UT_ASSERT_NOT_EFI_ERROR (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)SimpleFitData,
      FIT_TYPE_01_MICROCODE,
      1,
      &QueryResult));

  UT_ASSERT_EQUAL (QueryResult.BaseAddress, 0xFFB00060);
  UT_ASSERT_EQUAL (QueryResult.Size, 0x00);

  return UNIT_TEST_PASSED;
}

/**
  Test Case
*/
UNIT_TEST_STATUS
EFIAPI
ShouldReturnEfiNotFoundIfMissing (
  IN UNIT_TEST_CONTEXT      Context
  )
{
  FIT_QUERY_RESULT    QueryResult;

  UT_ASSERT_STATUS_EQUAL (
    InternalGetFitRecord (
      (FIRMWARE_INTERFACE_TABLE_ENTRY*)SimpleFitData,
      FIT_TYPE_2F_JMP_DEBUG_POLICY,
      1,
      &QueryResult),
    EFI_NOT_FOUND);

  return UNIT_TEST_PASSED;
}

///=== TEST ENGINE ================================================================================

/**
  SampleUnitTestApp

  @param[in] ImageHandle  The firmware allocated handle for the EFI image.
  @param[in] SystemTable  A pointer to the EFI System Table.

  @retval EFI_SUCCESS     The entry point executed successfully.
  @retval other           Some error occurred when executing this entry point.

**/
int
main (
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework = NULL;
  UNIT_TEST_SUITE_HANDLE      InternalTests;

  DEBUG(( DEBUG_INFO, "%a v%a\n", UNIT_TEST_NAME, UNIT_TEST_VERSION ));

  //
  // Start setting up the test framework for running the tests.
  //
  Status = InitUnitTestFramework( &Framework, UNIT_TEST_NAME, gEfiCallerBaseName, UNIT_TEST_VERSION );
  if (EFI_ERROR( Status ))
  {
    DEBUG((DEBUG_ERROR, "Failed in InitUnitTestFramework. Status = %r\n", Status));
    goto EXIT;
  }


  Status = CreateUnitTestSuite( &InternalTests, Framework, "FIT Query Lib Internal Tests", "FitQuery.Internal", NULL, NULL );
  if (EFI_ERROR( Status ))
  {
    DEBUG((DEBUG_ERROR, "Failed in CreateUnitTestSuite for InternalTests\n"));
    Status = EFI_OUT_OF_RESOURCES;
    goto EXIT;
  }
  AddTestCase( InternalTests,
                "Should fail if the header entry looks bad", "FitQuery.Internal.BadSig",
                ShouldFailIfFitSigIsBad, NULL, NULL, NULL );
  AddTestCase( InternalTests,
                "Should fail if a type is requested that we don't know how to process", "FitQuery.Internal.BadType",
                ShouldFailIfTypeIsUnknown, NULL, NULL, NULL );
  AddTestCase( InternalTests,
                "Should return the correct record, if found", "FitQuery.Internal.FoundRecord",
                ShouldReturnTheCorrectRecord, NULL, NULL, NULL );
  AddTestCase( InternalTests,
                "Should pay attention to the index and return the correct record on repeats", "FitQuery.Internal.MultipleRecords",
                ShouldReturnTheSecondRecordForRepeats, NULL, NULL, NULL );


  //
  // Execute the tests.
  //
  Status = RunAllTestSuites( Framework );

EXIT:
  if (Framework != NULL)
  {
    FreeUnitTestFramework( Framework );
  }

  return Status;
}
