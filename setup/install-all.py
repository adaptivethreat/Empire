import os,platform
from urllib import urlopen

if "Windows" in platform.system():
	ez_file_name = 'install_easy_setup.py'
	m2_file_name = 'M2Crypto-0.21.1.win-amd64-py2.7.exe'
	ansicon_file_name = 'ansicon.exe'
	ansi64_file_name = 'ANSI64.dll'
	ansi32_file_name = 'ANSI32.dll'
	ansilib_path = 'ansicon'

	# install pip
	data = urlopen('http://peak.telecommunity.com/dist/ez_setup.py')
	with open(ez_file_name, 'wb') as f:
		f.write(data.read())
	os.system('python %s' % (os.path.join(os.getcwd(),ez_file_name)))
	os.system('easy_install pip')

	# M2Crypto-0
	data = urlopen('https://github.com/saltstack/salt-windows-install/blob/master/deps/win-amd64-py2.7/M2Crypto-0.21.1.win-amd64-py2.7.exe?raw=true')
	with open(m2_file_name, 'wb') as f:
		f.write(data.read())
	os.system( os.path.join(os.getcwd(),m2_file_name) )
	
	# ansicon libs
	if not os.path.exists(ansilib_path):
		os.mkdir(ansilib_path)
	data = urlopen('https://github.com/asmc/ansicon/releases/download/1.0/ansicon.exe')
	with open(ansilib_path+os.sep+ansicon_file_name, 'wb') as f:
		f.write(data.read())
	
	data = urlopen('https://github.com/asmc/ansicon/releases/download/1.0/ANSI64.dll')
	with open(ansilib_path+os.sep+ansi64_file_name, 'wb') as f:
		f.write(data.read())
	
	data = urlopen('https://github.com/asmc/ansicon/releases/download/1.0/ANSI32.dll')
	with open(ansilib_path+os.sep+ansi32_file_name, 'wb') as f:
		f.write(data.read())
	
	os.unlink( os.path.join(os.getcwd(),ez_file_name) )
	os.unlink( os.path.join(os.getcwd(),m2_file_name) )
else:
	os.system('apt-get install python-pip')	
	# ubuntu 14.04 LTS dependencies
	os.system('apt-get install python-dev')
	os.system('apt-get install python-m2crypto')
	os.system('apt-get install swig')
	os.system('pip install pycrypto')
	
# common dependencies
os.system('pip install pyreadline')
os.system('pip install iptools')
os.system('pip install pydispatcher')

os.system('python %s' % (os.path.join(os.getcwd(),'setup_database.py')))
