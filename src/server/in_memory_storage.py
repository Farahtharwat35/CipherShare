import time

import time
from threading import Lock

class _SingletonMeta(type):
  _instances = {}
  
  def __call__(cls, *args, **kwargs):
    if cls not in cls._instances:
      instance = super().__call__(*args, **kwargs)
      cls._instances[cls] = instance
    return cls._instances[cls]


class Cache(metaclass=_SingletonMeta):
  _instance = None
  _lock = Lock()

  def __init__(self, ttl=11):
    self.ttl = ttl
    self.cache = {}

  def set(self, key, value):
    self.cache[key] = {'value': value, 'time': time.time()}

  def get(self, key):
    if key in self.cache:
      entry = self.cache[key]
      if time.time() - entry['time'] < self.ttl:
        return entry['value']
      else:
        del self.cache[key]
    return None

  def delete(self, key):
    if key in self.cache:
      del self.cache[key]
    return None

  def refresh(self, key):
    if key in self.cache:
      self.cache[key]['time'] = time.time()
      return True
    return False