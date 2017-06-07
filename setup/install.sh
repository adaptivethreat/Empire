#!/usr/bin/env bash

function log {
  echo -e '\033[0;32m\n [*] '$1'\n\033[0;30m'
}

function log_error {
  echo -e '\033[0;31m\n [*] '$1'\n\033[0;30m'
}

function handle_os {
  log 'Detecting operating system'
  case "$(uname -s)" in
    Darwin)
      log 'Detected OS X'
      ;;
    Linux)
      version=$( lsb_release -r | grep -oP "[0-9]+" | head -1 )
      case "$(lsb_release -d | grep -q)" in
        Fedora)
          log 'Detected Fedora'
          dnf install -y make g++ python-devel libxml2-devel default-jdk openssl-devel libssl-dev
          ;;
        *)
          log 'Detected Generic Linux'
          apt-get install -y make g++ python-dev libxml2-dev default-jdk libssl-dev
          ;;
      esac
      ;;
    *)
      log_error 'Unknown or unsupported operating system'
      ;;
  esac
}

function maybe_change_directory {
  if [[ "$(pwd)" != *setup ]]
  then
    cd ./setup
  fi
}

function install_virtualenv {
  log 'Setting up Python virtual environment (virtualenv)'
  pip install --upgrade virtualenv
  virtualenv ../empire_virtualenv
  source ../empire_virtualenv/bin/activate
  log 'Installing requirements into virtualenv'
  pip install -r requirements.txt
  log 'Setting up SQLite database'
  ./setup_database.py
  log 'Generating certificate'
  ./cert.sh
}

function install_xar {
  log 'Installing XAR'
  tar -xvf ../data/misc/xar-1.5.2.tar.gz
  (cd xar-1.5.2 && ./configure)
  (cd xar-1.5.2 && make)
  chmod 755 xar-1.5.2/src/xar && cp xar-1.5.2/src/xar ../bin/xar
}

function install_bomutils {
  log 'Installing bomutils'
  git clone https://github.com/hogliux/bomutils.git
  (cd bomutils && make)
  chmod 755 bomutils/build/bin/mkbom && cp bomutils/build/bin/mkbom ../bin/mkbom
}

function create_bin_dir {
  log 'Creating bin directory'
  rm -rf ../bin
  mkdir ../bin  
}

IFS='/' read -a array <<< pwd

maybe_change_directory
handle_os
install_virtualenv
create_bin_dir
install_xar
install_bomutils

cd ..

log 'Setup complete!'
