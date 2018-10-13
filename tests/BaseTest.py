import unittest, coverage

class EmpireTestCase(unittest.TestCase):
	"""Base class for Empire unit test cases.
	"""

	_src_coverage = '*'
	"""indicates path to source file for code coverage calculation."""

	_cov_datafile = None

	@classmethod
	def setUpClass(cls):
		cls._cov_datafile = ".coverage.{}".format(cls.__name__)
		
		cls._cov = coverage.coverage(config_file=".coveragerc", 
								data_file=cls._cov_datafile,
								auto_data=True,
								include=cls._src_coverage)
		cls._cov.start()
	
	@classmethod
	def tearDownClass(cls):
		cls._cov.stop()
		try:
			# attempt to load global coverage (broken in vs code)
			cov_data = cls._cov.get_data()
			glob_data = \
				end_data = coverage.CoverageData()
			glob_data.read_file('.coverage.global')

			cov_data.update(glob_data)
			
			cov_data.write_file(cls._cov_datafile)
		except:
			pass
		print ("\n----------------------------------------------------------------------\n"
				"          Code Coverage Report for {}\n".format(cls.__name__) )
		cls._cov.load()
		cls._cov.report(include=cls._src_coverage, show_missing=False)

	def setUp(self):
		"""Setting up unit test environment.
        """
		pass
	
	def tearDown(self):
		"""Tearing down unit test environment.
        """
		pass