# Don't mess with these imports
import unittest
import coverage
import sys
import os
import traceback
sys.path.append('..')
from tests.BaseTest import EmpireTestCase

# import any modules you need for the test case here


class TestNameMySuiteNameMeModel(EmpireTestCase):
    """Describe this test case \n
            can use multiple lines if needed.
    """
    # ------------- #
    #   Coverage    #
    # ------------- #
    _src_coverage = ['*/lib/common/*', '*/lib/common/singlefile.py']
    """indicates path to source file for code coverage calculation, can be 
	either a string or a list of strings, and should use wildcards and file
	extensions."""

    # ------------- #
    #   Test Data   #
    # ------------- #

    # declare any data you might need for this case's unit tests here

    # -------------------- #
    #  Test Env Handling   #
    # -------------------- #
    def setUp(self):
        # Test setup
        pass

    def tearDown(self):
        # Test teardown
        pass

    # -------------------- #
    #  Local Helper Funcs  #
    # -------------------- #
    # Place any helpers specific to this test case here
    # If any helpers should be accessible to multiple cases, place them in a
    #  separate file in this same directory called functions.py

    # ----------- #
    #    Tests    #
    # ----------- #
    def test_1_example_test(self):
        """Brief test description for test 1, REPLACE ME
        """
        self.assertTrue(True)
        self.assertFalse(False)
        self.assertEquals(1, 1, msg="Apparently 1 != 1...")
        self.assertNotEquals(1, 0, msg="Apparently 1 == 0...")
        self.assertIsNone(None, msg="Apparently None is not None...")
        self.assertIsNotNone(object, msg="Apparently object is None...")
        # many other asserts available, look at python unittest docs for
        #	python 2.7, or use vs code's python intellisense :)

    def test_2_example_second_test(self):
        """Brief test description for test 2, REPLACE ME
        """
        # You can even define helpers for specific unit tests if needed
        def raise_valueerror():
            raise ValueError("raise the roof")

        self.assertRaises(ValueError, raise_valueerror)

    # continue to define as many unit tests as needed for this test case


# ---------------------- #
#  Local Helper Classes  #
# ---------------------- #
# Define any local helper classes for your test case here
class TestHelperClass(object):
    """Generic Helper class, REPLACE ME
    """

    def raise_alltheexceptions(self):
        raise Exception("ALL THE EXCEPTIONS!!!")

    def do_something_useful(self):
        return 1 % 1
