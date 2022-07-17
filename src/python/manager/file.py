import os

from pathlib import Path
from shutil import rmtree

class FileManager():
  def __init__(self):
    Path(self.base_path).mkdir(parents=True, exist_ok=True)

  @classmethod
  def _rmdir_force(cls, pth):
    for sub in pth.iterdir():
      if sub.is_dir():
        FileManager._rmdir_force(sub)
      else:
        sub.unlink()
    return pth.rmdir()

  def get_file_path(self, path, create=False):
    if path:
      file_path = f"{self.base_path}/{path}"
    else:
      file_path = self.base_path

    if create:
      # Ensure the file path exists
      Path(file_path).mkdir(parents=True, exist_ok=True)

    return file_path

  def write(self, name, value, path=None, kind="wb"):
    file_path = self.get_file_path(path, create=True)

    with open(f"{file_path}/{name}", kind) as f:
      f.write(value)

    return file_path

  def write_bytes(self, name, value, path=None):
    return self.write(name, value, path=path, kind="wb")

  def write_string(self, name, value, path=None):
    return self.write(name, value, path=path, kind="w")

  def read(self, name, path=None, kind="rb"):
    file_path = self.get_file_path(path, create=False)

    with open(f"{file_path}/{name}", kind) as f:
      value = f.read()

    return value

  def read_bytes(self, name, path=None):
    return self.read(name, path=path, kind="rb")

  def read_string(self, name, path=None):
    return self.read(name, path=path, kind="r")

  def exists(self, name, path=None):
    file_path = self.get_file_path(path)
    my_file = Path(f"{file_path}/{name}")

    return my_file.is_file()

  def delete(self, name, path=None):
    file_path = self.get_file_path(path)
    my_file = Path(f"{file_path}/{name}")

    if my_file.is_dir():
      return FileManager._rmdir_force(my_file)
    else:
      return my_file.unlink()




class FileSecretManager(FileManager):
  def __init__(self, app):
    self.base_path = app.config["SECRETS_PATH"]

    super(FileSecretManager, self).__init__()

  def list(self):
    return os.listdir(self.base_path)

  def delete(self, name, path=None):
    dir_path = self.get_file_path(path)

    return rmtree(f"{dir_path}/{name}")

class FileCertificateManager(FileManager):
  def __init__(self, app):
    self.base_path = app.config["CERTS_PATH"]

    super(FileCertificateManager, self).__init__()

  def list(self, path=None):
    dir_path = self.get_file_path(path)

    return os.listdir(dir_path)
