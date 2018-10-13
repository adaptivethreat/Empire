# ***Empire CI Unit Test Framework***

# General Guidelines
  - Before developing tests, review the below style guide, layout description,
        and current tests to get familiar with the standards for testing.
    
  - Unit Test Framwork architecture is as follows:
    - `tests/run_tests.py`
        * this file is the main entry point to run all available test suites; 
         when a new test suite is written, it must be imported and included in 
         here to have its tests discovered and run.
    - `tests/BaseTest.py`
        * The base class for all test cases, should be imported as specified in
         the example test suite, and should rarely need to be modified.
    - `tests/[suite_name]/`
        * Each test suite (an organized collection of related test cases) is 
         contained in a folder with the suite's name.
    - `tests/[suite_name]/__init__.py`
        * Each suite should be its own module, with this file modified to 
         reflect the contained test cases and any other needed module init.
    - `tests/[suite_name]/suite.py`
        * Each suite shall have a single entry point, named `suite.py`, which
         is modified as specified in the example to import and load all written
         test cases.
    - `tests/[suite_name]/[suite_name]_[case_name].py`
        * Each test case shall be contained within a single file named as 
         specified above, and containing the unit tests appropriate for that 
         test case.
    - `tests/[suite_name]/functions.py` (if needed)
        * Some test suites may share the need for certain helper functions. When
         appropriate, contain these helpers in a file named `functions.py` in 
         the test suite's directory.
    
  - When writing unit tests, ensure your test applies directly to the suite and
   case you are including it in (i.e. don't write a test for the API inside the 
   schema suite). Additionally, ensure your test is specific and targeted (i.e. 
   don't write asserts for a Listener instance when you're unit-testing an Agent
   instance.)

  - *Unit* tests must be entirely independent of each other. Do not pass data
   between tests. If database writes occur, ensure the tearDown method clears
   each table written, and this will occur after each unit test is complete.
   Initialize any data needed for multiple tests in the setUp method of the test
   case. Data for one test only should be declared and defined inside that unit
   test.

# Style Guide
  - Lines in any unit test code shall not extend past 80 columns.
  - Test suite names must be simple and lower-case.
  - Test case names must be simple and lower-case.
  - Main test suite file must be named `suite.py`.
  - Test case files must be named `[suite_name]_[case_name].py`, replacing the
   bracketed portions as appropriate.
