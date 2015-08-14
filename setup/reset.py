import os,shutil

Empire_home = os.sep.join(os.path.os.getcwd().split(os.sep)[0:-1])
Empire_db = os.path.join(Empire_home, 'data'+os.sep+'empire.db')
Empire_debug = os.path.join(Empire_home,'empire.debug')
Empire_setup = os.path.join(Empire_home,'setup'+os.sep+'setup_database.py')
Empire_download = os.path.join(Empire_home, 'download')
# reset the database

if os.path.exists(Empire_db):
	os.unlink(Empire_db)
os.system('python %s' % (Empire_setup))

# remove the debug file if it exists
if os.path.exists(Empire_debug):
	os.unlink('python %s' % (Empire_debug))

# remove the download folders
if os.path.exists(Empire_download):
	shutil(Empire_download)