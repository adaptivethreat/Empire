import unittest
from test_core_helpers import TestCoreHelpersModel

def suite():
	classes = [
		TestCoreHelpersModel,
		# Add test case models here
	]
	suites = []
	for c in classes:
		suites.append(unittest.TestLoader().loadTestsFromTestCase(c))
	
	return unittest.TestSuite(suites)
