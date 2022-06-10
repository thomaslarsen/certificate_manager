from flask import current_app

from ca import private_key_filename, NotFoundException, InvalidValueException

import json

def _get_role(ca, role):
  if not current_app.secretmanager.exists(private_key_filename, path=ca):
    raise NotFoundException(f"{ca} CA not found")

  if current_app.certmanager.exists(role, path=f"roles/{ca}"):
    return json.loads(current_app.certmanager.read_bytes(role, path=f"roles/{ca}"))
  else:
    raise NotFoundException(f"{role} role not found")




############################
#### API calls
############################
def put_role(ca, role, body):
  try:
    if not current_app.secretmanager.exists(private_key_filename, path=ca):
      raise NotFoundException(f"CA {ca} doesn't exist")

    if current_app.certmanager.exists(role, path=f"roles/{ca}"):
      # Role already exists
      value = {**_get_role(ca, role), **body}
      current_app.certmanager.write_string(role, json.dumps(value), path=f"roles/{ca}")

      return value, 200
    else:
      # Role doesn't exist, so create it
      value = json.dumps(body)
      current_app.certmanager.write_string(role, value, path=f"roles/{ca}")

      return body, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def get_role(ca, role):
  try:
    return _get_role(ca, role), 200
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def list_roles(ca):
  try:
    if not current_app.secretmanager.exists(private_key_filename, path=ca):
      raise NotFoundException(f"CA {ca} doesn't exist")

    return current_app.certmanager.list(path=f"roles/{ca}"), 200
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def delete_role(ca, role):
  try:
    if not current_app.secretmanager.exists(private_key_filename, path=ca):
        raise NotFoundException(f"CA {ca} doesn't exist")

    if not current_app.certmanager.exists(role, path=f"roles/{ca}"):
      raise NotFoundException(f"{role} role not found")

    current_app.certmanager.delete(role, path=f"roles/{ca}"), 200
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400
