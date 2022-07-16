from oscrypto import asymmetric, keys as crypto_keys
from certbuilder import CertificateBuilder, pem_armor_certificate

from asn1crypto import pem, x509
from asn1crypto.csr import CertificationRequest

from flask import current_app

from ca import _construct_subject, _construct_ca_chain, _load_ca, _calc_enddate, encryption_schema, NotFoundException, InvalidValueException
from role import _get_role

def _check_role(ca, role, subject, ttl=None):
  """
  Validate that a certificate subject conforms to the rules of a role

  :return:
    the end date of the certificate
  """
  cert_role = _get_role(ca, role)

  cn = subject["common_name"]

  # Check wildcard
  if cn.startswith("*") and not cert_role["allow_wildcards"]:
    raise InvalidValueException(f"Wildcards not allowed for {role} role")

  # Check the paths
  if cert_role["paths"]:
    found = False
    i = 0

    while not found and i < len(cert_role["paths"]):
      # Check of naked CN
      if cn == cert_role["paths"][i] and not cert_role["allow_naked"]:
        raise InvalidValueException(f"Naked CN {cn} not allowed for {role} role")

      # Check for valid path suffix
      if cn.endswith(cert_role["paths"][i]):
        found = True
        break

      i += 1

    if not found:
      raise InvalidValueException(f"CN {cn} not allowed for {role} role")




############################
#### API calls
############################
def sign(ca, role, body, ttl=None):
  _, _, der_bytes = pem.unarmor(body)
  csr = CertificationRequest.load(der_bytes)

  subject = csr["certification_request_info"]["subject"]

  try:
    signing_ca_certificate, signing_ca_private_key = _load_ca(ca)

    # Create the certificate
    builder = CertificateBuilder(
        subject,
        csr["certification_request_info"]["subject_pk_info"]
    )

    # Check against role
    cert_role = _get_role(ca, role)
    _check_role(ca, role, subject.native)
    builder.end_date = _calc_enddate(ttl, cert_role.get("max_ttl", current_app.config["CERT_MAX_TTL"]), cert_role.get("default_ttl", current_app.config["CERT_DEFAULT_TTL"]))
    builder.issuer = asymmetric.load_certificate(signing_ca_certificate)
    certificate = builder.build(asymmetric.load_private_key(signing_ca_private_key, None))

    # Store the certificate in case it needa to be revoked
    # We store it using the serial number as the filename
    filename = certificate.serial_number
    current_app.certmanager.write_bytes(filename, pem_armor_certificate(certificate))

    return {
      "certificate": pem_armor_certificate(certificate).decode('utf8'),
      "ca_chain": _construct_ca_chain(certificate, ca)
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400

def issue(ca, role, body, ttl=None, alt_domains=None, alt_ips=None):
  try:
    signing_ca_certificate, signing_ca_private_key = _load_ca(ca)

    subject = _construct_subject(body, parent=signing_ca_certificate)

    # Extract parameters
    bit_size = int(body["size"])

    # Generate and save the key and certificate for the root CA
    public_key, private_key = asymmetric.generate_pair(encryption_schema, bit_size=bit_size)

    # Create the certificate
    builder = CertificateBuilder(
        subject,
        public_key
    )

    # Check and add any alt domains and IPs
    if alt_domains:
      for d in alt_domains:
        _check_role(ca, role, {"common_name": d})
      builder.subject_alt_domains = alt_domains
    builder.subject_alt_ips = alt_ips

    # Check against role
    cert_role = _get_role(ca, role)
    _check_role(ca, role, subject)
    builder.end_date = _calc_enddate(ttl, cert_role.get("max_ttl", current_app.config["CERT_MAX_TTL"]), cert_role.get("default_ttl", current_app.config["CERT_DEFAULT_TTL"]))
    builder.issuer = asymmetric.load_certificate(signing_ca_certificate)
    certificate = builder.build(asymmetric.load_private_key(signing_ca_private_key, None))

    # Store the certificate in case it needa to be revoked
    # We store it using the serial number as the filename
    filename = certificate.serial_number
    current_app.certmanager.write_bytes(filename, pem_armor_certificate(certificate))

    return {
      "certificate": pem_armor_certificate(certificate).decode('utf8'),
      "ca_chain": _construct_ca_chain(certificate, ca),
      "private_key": asymmetric.dump_private_key(private_key, None).decode('utf8')
    }, 201
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400


def info(cert):
  try:
    certificate = current_app.certmanager.read_bytes(cert)

    c = crypto_keys.parse_certificate(certificate)

    info = c.subject.native
    info["serial"] = c.serial_number
    # TODO add more details

    return info
  except NotFoundException as e:
    return str(e), 404
  except InvalidValueException as e:
    return str(e), 400
