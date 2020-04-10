#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------------------
# Обновление пользовательских аккаунтов на vpn шлюзе из внутреннего домена на Active Directory
#------------------------------------------------------------------------------------------------

import os, sys, getpass, hashlib
from datetime import datetime
try:
  from pypsrp.client import Client
except ModuleNotFoundError as err:
  print(err)
  sys.exit(1)

config = [] # Список параметров файла конфигурации

#------------------------------------------------------------------------------------------------

# Функция получения значений параметров конфигурации
def get_config(key):
  global config
  result = ''
  if not config:
    # Чтение файла конфигурации
    try:
      if os.path.isfile('/etc/vpnsync/vpnsync.conf'):
        configfile = open('/etc/vpnsync/vpnsync.conf')
      else:
        configfile = open('vpnsync.conf')
    except IOError as error:
      log_write(error)
    else:
      for line in configfile:
        param = line.partition('=')[::2]
        if param[0].strip().isalpha() and param[0].strip().find('#') == -1:
          # Получение параметра
          config.append(param[0].strip())
          config.append(param[1].strip())
  try:
    result = config[config.index(key)+1]
  except ValueError as err:
    log_write('Config parameter '+str(key)+' not found, stoping server')
    exit(1)
  return result

#------------------------------------------------------------------------------------------------

# Функция записи в лог файл
def log_write(message):
  # Подготовка лог файла
  if not os.path.isfile(get_config('Log')):
    logdir = os.path.dirname(get_config('Log'))
    if not os.path.exists(logdir):
      os.makedirs(logdir)
    open(get_config('Log'),'a').close()
  else:
    # Проверка размера лог файла
    log_size = os.path.getsize(get_config('Log'))
    # Если лог файл больще 10М, делаем ротацию
    if log_size > 1024**2*10:
      try:
        os.remove(get_config('Log')+'.old')
      except:
        pass
      os.rename(get_config('Log'), get_config('Log')+'.old')
  # Запись в лог файл
  with open(get_config('Log'),'a') as logfile:
    logfile.write(str(datetime.now()).split('.')[0]+' '+message+'\n')

#------------------------------------------------------------------------------------------------

def run():
  log_write('Sync vpn users...')
  # Проверка существования файла VPNUsersList
  try:
    userslist = open(get_config('VPNUsersList'), 'r').read().split()
  except IOError as err:
    open(get_config('VPNUsersList'), 'w')
    userslist = []
  #
  # Подключение к серверу Active Directory
  client = Client(get_config('ADServer')+"."+get_config('DomainRealm'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
  # Получение списка пользователей и их паролей для тех, у кого поле wwwhomepage начинается с VPNMask
  script = """([adsisearcher]"(objectcategory=user)").FindAll() | where {$_.properties['wwwhomepage'] -like '"""+get_config('VPNMask')+"""*'} | %{ $_.GetDirectoryEntry() } | ForEach-Object {$_.samaccountname, $_.wwwhomepage}"""
  try:
    adusers, streams, had_error = client.execute_ps(script)
  except:
    log_write('[adsisearcher] objectcategory=user powershell error')
  adusers = adusers.splitlines()
  #
  # Добавление и обновление пользователей
  pos = 0
  while pos < len(adusers):
    # Получение исходного пароля пользователя
    password = adusers[pos+1][len(get_config('VPNMask')):]
    if len(password) > 5: # Проверка длины пароля
      # Генерирование соли и пароля пользователя
      sha_salt = os.urandom(10)
      password = sha_salt.hex()+hashlib.pbkdf2_hmac(hash_name='sha256', password=password.encode(), salt = sha_salt, iterations=100).hex()
      try:
        userpos = userslist.index(adusers[pos])
        userslist[userpos+1] = password
        log_write('Updated user '+adusers[pos])
      except ValueError:
        userslist.append(adusers[pos])
        userslist.append(password)
        log_write('Added user '+adusers[pos])
    else:
      # Удаление пользователя и его пароля
      adusers.pop(pos)
      adusers.pop(pos)
    pos = pos + 2
  #
  # Удаление из списка userslist, пользователей более не присутствующих в adusers
  for user in userslist[::2]:
    try:
      adusers.index(user)
    except ValueError:
      pos = userslist.index(user)
      # Удаление пользователя и его пароля
      userslist.pop(pos)
      userslist.pop(pos)
      log_write('Deleted user '+user)
  #

  # Запись в файл VPNUsersList
  with open(get_config('VPNUsersList'), 'w') as result:
    pos = 0
    while pos < len(userslist):
      result.write(userslist[pos]+' '+userslist[pos+1]+'\n')
      pos += 2

#------------------------------------------------------------------------------------------------

# Запуск программы
if __name__ =='__main__':
  run()
