import json
import os
from util import user_dir

class SimpleConfig:
  default_options = {"gui": "lite", "proxy": { "mode": "none", "host":"localhost", "port":"8080" },
                    "winpos-qt": [100, 100, 840, 400], "winpos-lite": [4, 25, 351, 149], "history": False }

  def set_key(self, key, value, save = True):
    self.config[key] = value
    if save == True:
      self.save_config()

  def save_config(self):
    f = open(self.config_file_path(), "w+")
    f.write(json.dumps(self.config))

  def load_config(self):
    f = open(self.config_file_path(), "r")
    file_contents = f.read()
    if file_contents:
      user_config = json.loads(file_contents)
      for i in user_config:
          self.config[i] = user_config[i]
    else:
      self.config = self.default_options
      self.save_config()
  
  def config_file_path(self):
    return "%s" % (self.config_folder + "/config.json")

  def __init__(self):
    # Find electrum data folder
    self.config_folder = user_dir()
    self.config = self.default_options
    # Read the file
    if os.path.exists(self.config_file_path()):
      self.load_config()
    self.save_config()
        
