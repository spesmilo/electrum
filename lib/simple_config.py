import json
import os

class SimpleConfig:
  default_options = {"gui": "lite"}

  def save_config(self):
    f = open(self.config_file_path(), "w+")
    f.write(json.dumps(self.config))

  def load_config(self):
    f = open(self.config_file_path(), "r")
    file_contents = f.read()
    if file_contents:
      self.config = json.loads(file_contents)
    else:
      self.config = self.default_options
      self.save_config()
  
  def config_file_path(self):
    return "%s" % (self.config_folder + "/config.json")

  def __init__(self):
    # Find electrum data folder
    if "HOME" in os.environ:
      self.config_folder = os.path.join(os.environ["HOME"], ".electrum")
    elif "LOCALAPPDATA" in os.environ:
      self.config_folder = os.path.join(os.environ["LOCALAPPDATA"], "Electrum")
    elif "APPDATA" in os.environ:
      self.config_folder = os.path.join(os.environ["APPDATA"], "Electrum")
    else:
      raise BaseException("No home directory found in environment variables.")

    # Read the file
    if os.path.exists(self.config_file_path()):
      self.load_config()
    else:
      self.config = self.default_options
      self.save_config()
        
