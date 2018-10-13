import unittest
import coverage
import sys

sys.path.append('..')
from tests.BaseTest import EmpireTestCase
from lib.common import helpers


class TestCoreHelpersModel(EmpireTestCase):
    _src_coverage = '*/lib/common/helpers.py'

    _conn = None

    def setUp(self):
        """Setup stuff."""
        pass

    def tearDown(self):
        # Test teardown
        pass

    def test_01_validate_ip(self):
        _valid_addrs = [
            "1.2.3.4",
            "::ff"
        ]
        _invalid_addrs = [
            "254.254.254.256",
            "::ff::ff"
        ]
        try:
            for (valid, invalid) in zip(_valid_addrs, _invalid_addrs):
                self.assertTrue(helpers.validate_ip(valid))
                self.assertFalse(helpers.validate_ip(invalid))
        except Exception as e:
            self.fail("TEST ERROR: failed with: {}".format(e))
        finally:
            pass

    def test_02_validate_ntlm(self):
        _valid_ntlm = [
            "0a"*16,
            "de"*16,
            "f5"*16
        ]
        _invalid_ntlm = [
            "0a"*15,
            "0a"*17,
            "fg"*16,
            "gi"*17
        ]
        for (valid, invalid) in zip(_valid_ntlm, _invalid_ntlm):
            self.assertTrue(helpers.validate_ntlm(valid),
                            msg="Valid NTLM {} returned Invalid".format(valid))
            self.assertFalse(helpers.validate_ntlm(
                invalid), msg="Invalid NTLM {} (length {}) returned Valid".format(invalid, len(invalid)))

    def test_03_generate_ip_list(self):
        # IPs in CIDR format to list-ize
        _ip_list_cidr = ",".join([
            "1.1.1.0/31",
            "2.2.2.248/30",
            "2.2.2.256/33"  # intentional bad entry
        ])
        # IPs in range format to list-ize
        _ip_list_range = ",".join([
            "1.1.1.0-1",
            "2.2.2.248-251",
            "3.3.3.256-260"  # intentional bad entry
        ])
        # Resulting list of IPs
        _ip_list_after = [
            "1.1.1.0",
            "1.1.1.1",
            "2.2.2.248",
            "2.2.2.249",
            "2.2.2.250",
            "2.2.2.251"
        ]
        res_list_cidr = helpers.generate_ip_list(_ip_list_cidr)
        res_list_range = helpers.generate_ip_list(_ip_list_range)

        for l in (res_list_cidr, res_list_range):
            self.assertIsNotNone(
                l, msg="generate_ip_list returned none unexpectedly")
            self.assertTrue(len(res_list_cidr) == len(_ip_list_after),
                            msg="generate_ip_list returned list size {} (expected {})".format(len(l), len(_ip_list_after)))
            for v in l:
                self.assertTrue(v in _ip_list_after,
                                msg="IP {} was not expected from generated list".format(v))

    def test_04_random_string(self):
        # modify the below arguments to adjust test precision,
        #	esp if getting a lot of false negatives
        # max number of times to attempt randomization
        _max_attempts = float(8)
        _passing_ratio = .75  # must pass this ratio of successes to pass test

        _lengths = (-1, 3, 5, 10)

        for str_len in _lengths:
            res_list = []
            passing = False
            good = 0
            for _ in range(1, int(_max_attempts)):
                # TODO: unit test charset as well
                res = helpers.random_string(length=str_len)
                if res not in res_list:
                    good += 1
            if good > 0:
                if (good / _max_attempts) > _passing_ratio:
                    passing = True
            self.assertTrue(passing,
                            msg="String randomized ratio {} / {} differed less than {}% ".format(good, _max_attempts, _passing_ratio*100))

    """Not yet implemented.
	def test_05_generate_random_script_var_name(self):
		pass
	"""

    def test_06_randomize_capitalization(self):
        # modify the below arguments to adjust test precision,
        #	esp if getting a lot of false negatives
        # max number of times to attempt randomization
        _max_attempts = float(8)
        _passing_ratio = .5  # must pass this ratio of successes to pass test
        _to_capitalize_short = "ab" * 2
        _to_capitalize_long = "ab" * 16

        for v in (_to_capitalize_short, _to_capitalize_long):
            passing = False
            good = 0
            for _ in range(1, int(_max_attempts)):
                res = helpers.randomize_capitalization(v)
                if res != v:
                    good += 1
            if good > 0:
                if (good / _max_attempts) > _passing_ratio:
                    passing = True
            self.assertTrue(passing,
                            msg="Capitalize random ratio {} / {} differed less than {}% ".format(good, _max_attempts, _passing_ratio*100))

    def test_07_chunks(self):
        from math import ceil

        _splitus = [
            "a"*16,
            "b"*24,
            "c"*30,
            "d"*192
        ]
        _sizes = (0, 1, 2, 5, 10, 15)

        for s in _splitus:
            for sz in _sizes:
                expected = 1
                if sz > 0:
                    expected = ceil(len(str(s)) / float(sz))
                try:
                    res = tuple(helpers.chunks(s, sz))
                    self.assertEquals(len(res), expected,
                                      msg="String '{}' returned {} chunks, should have returned {}"
                                      .format(s, len(res), expected))
                except Exception as e:
                    if sz != 0:
                        self.assertTrue(False, msg="chunks threw {}".format(e))

    """Not yet implemented tests commented below."""
    # def test_08_execute_db_query(self):
    # 	"""def execute_db_query(conn, query, args=None):"""
    # 	pass
    # def test_09_enc_powershell(self):
    # 	"""def enc_powershell(raw):
    # 	"""
    # 	pass
    # def test_10_powershell_launcher(self):
    # 	"""def powershell_launcher(raw, modifiable_launcher):
    # 	"""
    # 	pass
    # def test_11_parse_powershell_script(self):
    # 	"""def parse_powershell_script(data):
    # 	"""
    # 	pass
    # def test_12_strip_powershell_comments(self):
    # 	"""def strip_powershell_comments(data):
    # 	"""
    # 	pass
    # def test_13_get_powerview_psreflect_overhead(self):
    # 	"""def get_powerview_psreflect_overhead(script):
    # 	"""
    # 	pass
    # def test_14_get_dependent_functions(self):
    # 	"""def get_dependent_functions(code, functionNames):
    # 	"""
    # 	pass
    # def test_15_find_all_dependent_functions(self):
    # 	"""def find_all_dependent_functions(functions, functionsToProcess, resultFunctions=[]):
    # 	"""
    # 	pass
    # def test_16_generate_dynamic_powershell_script(self):
    # 	"""def generate_dynamic_powershell_script(script, functionNames):
    # 	"""
    # 	pass

    # def test_17_generate_dynamic_powershell_script(self):
    # 	"""def generate_dynamic_powershell_script(script, functionNames):
    # 	"""
    # 	pass

    # def test_18_parse_credentials(self):
    # 	"""def parse_credentials(data):
    # 	"""
    # 	pass

    # def test_19_parse_mimikatz(self):
    # 	"""def parse_mimikatz(data):
    # 	"""
    # 	pass

    # def test_20_get_config(self):
    # 	"""def get_config(fields, fromFile=False):
    # 	"""
    # 	pass

    # def test_21_get_listener_options(self):
    # 	"""def get_listener_options(listenerName):
    # 	"""
    # 	pass

    # def test_22_get_datetime(self):
    # 	"""def get_datetime():
    # 	"""
    # 	pass

    # def test_23_get_expiry_date(self):
    # 	"""def get_expiry_date(seconds=10000):
    # 	"""
    # 	pass

    # def test_24_utc_to_local(self):
    # 	"""def utc_to_local(utc):
    # 	"""
    # 	pass

    # def test_25_get_file_datetime(self):
    # 	"""def get_file_datetime():
    # 	"""
    # 	pass

    # def test_26_get_file_size(self):
    # 	"""def get_file_size(file):
    # 	"""
    # 	pass

    # def test_27_token_expired(self):
    # 	"""def token_expired(token_expiry_date):
    # 	"""
    # 	pass

    def test_28_lhost(self):
        # """ lhost()"""
        self.assertIsNotNone(helpers.lhost())

    def test_29_color(self):
        # """ color(string, color=None)"""
        _test_colored_strings = [
            '[+] Test success',
            '[*] Test info',
            '[!] Test error'
        ]
        _test_uncolored_strings = [
            'test other format',
            '[[[!!!] Test lots of brackets',
            '[[ more brackets ][]'
        ]
        for (s_color, s_uncolor) in zip(_test_colored_strings, _test_uncolored_strings):
            self.assertTrue('\x1b' in helpers.color(s_color))
            self.assertFalse('\x1b' in helpers.color(s_uncolor))

    # def test_30_unique(self):
    # 	"""def unique(seq, idfun=None):
    # 	"""
    # 	pass

    # def test_31_uniquify_tuples(self):
    # 	"""def uniquify_tuples(tuples):
    # 	"""
    # 	pass

    # def test_32_decode_base64(self):
    # 	"""def decode_base64(data):
    # 	"""
    # 	pass

    # def test_33_encode_base64(self):
    # 	"""def encode_base64(data):
    # 	"""
    # 	pass

    # def test_34_complete_path(self):
    # 	"""def complete_path(text, line, arg=False):
    # 	"""
    # 	pass

    # def test_35_dict_factory(self):
    # 	"""def dict_factory(cursor, row):
    # 	"""
    # 	pass

    # def test_36_get_module_source_files(self):
    # 	"""def get_module_source_files():
    # 	"""
    # 	pass

    # def test_37_obfuscate(self):
    # 	"""def obfuscate(installPath, psScript, obfuscationCommand):
    # 	"""
    # 	pass

    # def test_38_obfuscate_module(self):
    # 	"""def obfuscate_module(moduleSource, obfuscationCommand="", forceReobfuscation=False):
    # 	"""
    # 	pass

    # def test_39_is_obfuscated(self):
    # 	"""def is_obfuscated(moduleSource):
    # 	"""
    # 	pass

    # def test_40_is_powershell_installed(self):
    # 	"""def is_powershell_installed():
    # 	"""
    # 	pass

    # def test_41_get_powershell_name(self):
    # 	"""def get_powershell_name():
    # 	"""
    # 	pass

    # def test_42_convert_obfuscation_command(self):
    # 	"""def convert_obfuscation_command(obfuscate_command):
    # 	"""
    # 	pass

    # def test_43_slackMessage(self):
    # 	"""def slackMessage(slackToken, slackChannel, slackText):
    # 	"""
    # 	pass

    # def test_44_bytesToInt(self):
    # 	"""def bytesToInt(bytes):
    # 	"""
    # 	pass

    # def test_45_add_to_list(self):
    # 	"""def add_to_list(color, ipListString):
    # 	"""
    # 	pass

    # def test_46_delete_list(self):
    # 	"""def delete_list(color):
    # 	"""
    # 	pass

    # def test_47_startWSGIInstance(self):
    # 	"""def startWSGIInstance(app, ip, port, cert, key, **kw):
    # 	"""
    # 	pass

    # def test_48_spawnThread(self):
    # 	"""def spawnThread(target, *args, **kwargs):
    # 	"""
    # 	pass

    # def test_49_isThreadAlive(self):
    # 	"""def isThreadAlive(handle):
    # 	"""
    # 	pass

    # def test_50_dispatch_signal(self):
    # 	"""def dispatch_signal(message, args={}, sender="global", do_print=False):
    # 	"""
    # 	pass
