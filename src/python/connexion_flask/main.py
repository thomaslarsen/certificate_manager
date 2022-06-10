from email.mime import application
import connexion

import os

from manager.file import FileSecretManager
from manager.file import FileCertificateManager

class App:
    def __init__(self, specification_dir='openapi/', spec_filename='openapi.yaml'):
        self.app = connexion.App(__name__, specification_dir=specification_dir)
        self.app.add_api(
            spec_filename,
            arguments={
                'api_host': os.getenv('API_HOST', 'localhost'),
                'service_name': os.getenv('SERVICE_NAME')
            }
        )

        self.application = self.app.app

        # Set configuration
        self.application.config["SECRETS_PATH"] = os.getenv("SECRETS_PATH", "/secrets")
        self.application.config["CERTS_PATH"] = os.getenv("CERTS_PATH", "/certs")
        self.application.config["CA_ROOT_TTL"] = os.getenv("CA_ROOT_TTL", 87600)    # 10 years
        self.application.config["CA_INTERMEDIATE_TTL"] = os.getenv("CA_INTERMEDIATE_TTL", 43800)    # 5 years
        self.application.config["CA_MAX_TTL"] = os.getenv("CA_MAX_TTL", 175200) # 20 years
        self.application.config["CERT_DEFAULT_TTL"] = os.getenv("CERT_DEFAULT_TTL", 720)    # 1 month
        self.application.config["CERT_MAX_TTL"] = os.getenv("CERT_MAX_TTL", 9490)   # 13 months

        # Add objects to the application context
        self.application.secretmanager = FileSecretManager(self.application)
        self.application.certmanager = FileCertificateManager(self.application)

        print(self.application.config)

        # Start the app
        self.app.run(port=os.getenv('API_PORT', 8080))
