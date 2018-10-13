import unittest

# UPDATE THIS LINE WITH YOUR SUITE_CASE & CLASS NAMES
from test_NameMySuite_NameMe import TestNameMySuiteNameMeModel


def suite():
    classes = [
        # TestNameMySuiteNameMeModel,
        # Add Test Case Classes here
    ]
    suites = []
    # UPDATE THIS LINE WITH YOUR TEST CASE CLASS NAME
    for c in classes:
        suites.append(unittest.TestLoader().loadTestsFromTestCase(c))
    # COPY THE ABOVE LINE FOR ALL TEST CASES WRITTEN FOR THIS SUITE
    return unittest.TestSuite(suites)
