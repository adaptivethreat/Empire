""" Contains methods to encrypt, obfuscate, minify, etc. source code, either
Python or Powershell, for use in agents, stagers, etc.

In essence: you should be able to put Python or Powershell code strings into
any function in this file, and get back a string which has the same
functionality but different meta-characteristics (no comments, shorter length,
better evasion, etc.)
"""

from pyminifier import token_utils as py_tokenizer
from pyminifier import minification as py_minifier
from pyminifier import obfuscate as py_obfuscator

################################################################################
#
# Python Encryption/Obfuscation/Minification/Etc.
#
################################################################################

class PyminifierOptions(object):
    """
    Irritating options "struct" needed for pyminifier.
    See: https://liftoff.github.io/pyminifier/_modules/pyminifier/minification.html#minify
    """
    tabs = False

def py_minify(code):
    """
    minifies a string (of python code) passed
    see: https://liftoff.github.io/pyminifier/_modules/pyminifier/minification.html#minify
    """
    tokenized = py_tokenizer.listified_tokenizer(code)

    options = PyminifierOptions()
    minified = py_minifier.minify(tokenized, options)
    return minified

# TODO py_obfuscate fails with the following:
#   File "/usr/lib/python2.7/site-packages/pyminifier/obfuscate.py", line 92, in apply_obfuscation
#     tokens, obfuscate_variable, variable, name_generator)
# TypeError: replace_obfuscatables() takes at least 5 arguments (4 given)

# def py_obfuscate(code):
#     py_obfuscator.name_generator = py_obfuscator.obfuscation_machine(identifier_length=1)
#     return py_obfuscator.apply_obfuscation(code)


################################################################################
#
# Powershell Encryption/Obfuscation/Minification/Etc.
#
################################################################################
