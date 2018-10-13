from gevent import monkey
monkey.patch_all()
import unittest
import coverage
import sys

_covGlob = coverage.coverage(config_file=".coveragerc",
                             data_file=".coverage.global", auto_data=True)
_covGlob.start()

coverage.CoverageData().write_file('.coverage')

# Import all suites below
from core import CoreSuite

if __name__ == '__main__':
    suites = [
        CoreSuite(),
        # Add new suites here using identical lines to the above
    ]
    success = True
    failures = []
    for suite in suites:
        _covGlob.save()
        res = unittest.TextTestRunner(verbosity=2).run(suite)
        success = success and res.wasSuccessful()
        failures += res.failures

    _covGlob.stop()
    _covGlob.save()

    if not success:
        print "Failed with {} failures:".format(len(failures))
        for detail in failures:
            print "----------"
            print "  {}".format(detail[1])
            print "----------"
        sys.exit(1)
