#heavily adapated from github.com/operatorequals/httpimport by John Torakis aka operatorequals
'''
Copyright 2017 John Torakis

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import imp
import sys
from System.Net import WebClient

class HttpImporter(object):
    def __init__(self, base_url):
        self.base_url = base_url
    def find_module(self, fullname, path=None):
        try:
            loader = imp.find_module(fullname, path)
            return None
        except ImportError:
            pass
        if fullname.split('.').count(fullname.split('.')[-1]) > 1:
            return None

        return self

    def load_module(self, name):

        imp.acquire_lock()
        if name in sys.modules:
            imp.release_lock()
            return sys.modules[name]

        if name.split('.')[-1] in sys.modules:
            imp.release_lock()
            return sys.modules[name.split('.')[-1]]

        if name in sys.builtin_module_names:
            imp.find_module(name)
            imp.load_module(name)
            imp.release_lock()
            return

        name = name.split('.')[-1]

        #TODO:
        #Dealing with stuff not actually in iPy
        if name == "strop" or name == "_hashlib" or name == "nt" or name == "fcntl" or name == "posix" or name == "org" or name == "termios" or name == "msvcrt" or name == "EasyDialogs" or name == "pwd" or name == "grp":
            return
        module_url = self.base_url + '%s.py' % name.replace('.', '/')
        #TODO:
        #Dealing with weird stuff that happens when packages are needed
        if name == "aliases" or name == "hex_codec":
            module_url = self.base_url + 'encodings/%s.py' % name.replace('.', '/')
        if name == "wintypes" or name == "util" or name == "_endian" or name == "ctypes":
            module_url = self.base_url + 'ctypes/%s.py' % name.replace('.', '/')
        package_url = self.base_url + '%s/__init__.py' % name.replace('.', '/')
        final_url = None
        final_src = None

        wc = WebClient()

        try:
            final_src = wc.DownloadString(module_url)
            final_url = module_url
        except:
            pass
        if final_src is None:
            try:
                final_url = package_url
                package_src = wc.DownloadString(package_url)
                final_src = package_src
            except IOError as e:
                module_src = None
                imp.release_lock()
                return None

        mod = imp.new_module(name)
        mod.__loader__ = self
        mod.__file__ = final_url
        mod.__package__ = name.split('.')[0]
        mod.__path__ = ['/'.join(mod.__file__.split('/')[:-1]) + '/']
        sys.modules[name] = mod
        exec(final_src, mod.__dict__)
        imp.release_lock()
        return mod


def add_remote_repo(base_url):
    importer = HttpImporter(base_url)
    sys.meta_path.insert(0, importer)
    return importer

#This is a hack. Imports built-in modules not present in the standard library
for x in sys.builtin_module_names:
    __import__(x)

