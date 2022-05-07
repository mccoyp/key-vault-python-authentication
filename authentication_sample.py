# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
# This script expects that the following environment vars are set, or they can be hardcoded in key_vault_sample_config, these values
# SHOULD NOT be hardcoded in any code derived from this sample:
#
# AZURE_TENANT_ID: with your Azure Active Directory tenant id or domain
# AZURE_CLIENT_ID: with your Azure Active Directory Service Principal AppId
# AZURE_CLIENT_OID: with your Azure Active Directory Service Principle Object ID
# AZURE_CLIENT_SECRET: with your Azure Active Directory Application Key
# AZURE_SUBSCRIPTION_ID: with your Azure Subscription Id
#
# These are read from the environment and exposed through the KeyVaultSampleConfig class. For more information please
# see the implementation in key_vault_sample_config.py

import sys

from azure.identity import DefaultAzureCredential, DeviceCodeCredential
from azure.keyvault.secrets import SecretClient

from key_vault_sample_base import KeyVaultSampleBase, keyvaultsample, run_all_samples


class AuthenticationSample(KeyVaultSampleBase):
    """
    A collection of samples that demonstrate authenticating with the SecretClient and KeyVaultManagementClient 
    """

    @keyvaultsample
    def auth_using_service_principle_credentials(self):
        """
        authenticates to the Azure Key Vault service using AAD service principle credentials 
        """
        # create a vault to validate authentication with the SecretClient
        vault = self.create_vault()

        # create the service principle credentials used to authenticate the client
        credential = DefaultAzureCredential()

        # create the client using the created credentials
        client = SecretClient(vault_url=vault.properties.vault_uri, credential=credential)

        # set and get a secret from the vault to validate the client is authenticated
        print('creating secret...')
        secret = client.set_secret(name='auth-sample-secret', value='client is authenticated to the vault')
        print(secret)

        print('getting secret...')
        secret = client.get_secret(name='auth-sample-secret', version=secret.properties.version)
        print(secret)

    @keyvaultsample
    def auth_user_with_device_code(self):
        """
        authenticates to the Azure Key Vault by interactively authenticating using azure-identity
        """
        # create a vault to validate authentication with the KeyVaultClient
        vault = self.create_vault()

        # create a DeviceCodeCredential that will prompt interactive authentication
        credential = DeviceCodeCredential()

        # create the client using the created credentials
        client = SecretClient(vault_url=vault.properties.vault_uri, credential=credential)

        # set and get a secret from the vault to validate the client is authenticated
        print('creating secret...')
        secret = client.set_secret(name='auth-sample-secret', value='client is authenticated to the vault')
        print(secret)

        print('getting secret...')
        secret = client.get_secret(name='auth-sample-secret', version=secret.properties.version)
        print(secret)


if __name__ == "__main__":
    sys.exit(run_all_samples([AuthenticationSample()]))
