#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------------------
# Обновление пользовательских аккаунтов на vpn шлюзе из внутреннего домена на Active Directory
#------------------------------------------------------------------------------------------------

import os, sys
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
  # Подключение к серверу
  client = Client(get_config('ADServer')+"."+get_config('DomainRealm'), auth="kerberos", ssl=False, username=get_config('ADUserName'), password=get_config('ADUserPassword'))
  # Получение списка vpn пользователей и их паролей
  script = """([adsisearcher]"(objectcategory=user)").FindAll() | where {$_.properties['wwwhomepage'] -like '"""+get_config('VPNMask')+"""*'} | %{ $_.GetDirectoryEntry() } | ForEach-Object {$_.samaccountname, $_.wwwhomepage}"""
  try:
    vpnusers, streams, had_error = client.execute_ps(script)
  except:
    log_write('[adsisearcher] objectcategory=user powershell error')
  print(vpnusers)

#------------------------------------------------------------------------------------------------

# Запуск программы
if __name__ =='__main__':
  run()
