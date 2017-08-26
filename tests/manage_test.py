"""Unit tests for the manage.py CLI script."""
# pylint: disable=protected-access
import base64
import os
import sys
from unittest import mock, TestCase

import boto3
import moto
from pyfakefs import fake_filesystem_unittest

import manage


@mock.patch('sys.stderr', mock.MagicMock())  # pyhcl complains about unused tokens to stderr
class BinaryAlertConfigTest(fake_filesystem_unittest.TestCase):
    """Test management of the underlying BinaryAlert config."""

    def setUp(self):
        self.setUpPyfakefs()

        # pyhcl automatically writes "parsetab.dat"  in its site-package path.
        for path in sys.path:
            if path.endswith('site-packages'):
                self.fs.MakeDirectories(os.path.join(path, 'hcl'))

        # Create variables.tf file.
        self.fs.CreateFile(
            manage.VARIABLES_FILE,
            contents='\n'.join([
                'variable "aws_region" {}',
                'variable "name_prefix" {}',
                'variable "enable_carbon_black_downloader" {}',
                'variable "carbon_black_url" {}',
                'variable "encrypted_carbon_black_api_token" {}'
            ])
        )

        # Create terraform.tfvars file.
        self.fs.CreateFile(
            manage.CONFIG_FILE,
            contents='\n'.join([
                'aws_region = "us-east-1"',
                'name_prefix = "name_prefix"',
                'enable_carbon_black_downloader = 1',
                'carbon_black_url = "https://example.com"',
                'encrypted_carbon_black_api_token = "{}"'.format('A' * 260)
            ])
        )

    def test_property_accesses(self):
        """Access each property in the BinaryAlertConfig."""
        config = manage.BinaryAlertConfig()

        self.assertEqual('us-east-1', config.aws_region)
        self.assertEqual('name_prefix', config.name_prefix)
        self.assertEqual(1, config.enable_carbon_black_downloader)
        self.assertEqual('https://example.com', config.carbon_black_url)
        self.assertEqual('A' * 260, config.encrypted_carbon_black_api_token)
        self.assertEqual('name_prefix_binaryalert_batcher', config.binaryalert_batcher_name)
        self.assertEqual('name.prefix.binaryalert-binaries.us-east-1',
                         config.binaryalert_s3_bucket_name)

    def test_variable_not_defined(self):
        """InvalidConfigError is raised if a variable declaration is missing."""
        with open(manage.CONFIG_FILE, 'w') as config_file:
            config_file.write('aws_region = "us-east-1"\n')

        with self.assertRaises(manage.InvalidConfigError):
            manage.BinaryAlertConfig()

    def test_invalid_aws_region(self):
        """InvalidConfigError raised if AWS region is set incorrectly."""
        config = manage.BinaryAlertConfig()
        with self.assertRaises(manage.InvalidConfigError):
            config.aws_region = 'invalid-region'

    def test_invalid_name_prefix(self):
        """InvalidConfigError raised if name prefix is blank."""
        config = manage.BinaryAlertConfig()
        with self.assertRaises(manage.InvalidConfigError):
            config.name_prefix = ""

    def test_invalid_enable_carbon_black_downloader(self):
        """InvalidConfigError raised if enable_downloader is not an int."""
        config = manage.BinaryAlertConfig()
        with self.assertRaises(manage.InvalidConfigError):
            config.enable_carbon_black_downloader = '1'

    def test_invalid_carbon_black_url(self):
        """InvalidConfigError raised if URL doesn't start with http(s)."""
        config = manage.BinaryAlertConfig()
        with self.assertRaises(manage.InvalidConfigError):
            config.carbon_black_url = 'example.com'

    def test_invalid_encrypted_carbon_black_api_token(self):
        """InvalidConfigError raised if encrypted token is too short."""
        config = manage.BinaryAlertConfig()
        with self.assertRaises(manage.InvalidConfigError):
            config.encrypted_carbon_black_api_token = 'ABCD'


class BinaryAlertConfigEncryptApiTokenTest(TestCase):
    """Tests for _encrypt_cb_api_token with real filesystem."""

    @moto.mock_kms
    @mock.patch('getpass.getpass')
    @mock.patch('manage.print')
    @mock.patch('subprocess.check_call')
    def test_encrypt_cb_api_token(
            self, mock_subprocess: mock.MagicMock, mock_print: mock.MagicMock,
            mock_getpass: mock.MagicMock):
        """Verify that token encryption is done correctly."""
        mock_getpass.return_value = 'abcd' * 10

        config = manage.BinaryAlertConfig()
        config._encrypt_cp_api_token()

        # Verify that the mocks were called as expected.
        mock_getpass.assert_called_once()
        mock_print.assert_has_calls([
            mock.call('Terraforming KMS key...'),
            mock.call('Encrypting API token...')
        ])
        mock_subprocess.assert_called_once()

        # Decrypting the key should result in the original value.
        plaintext_api_key = boto3.client('kms').decrypt(
            CiphertextBlob=base64.b64decode(config.encrypted_carbon_black_api_token)
        )['Plaintext'].decode('ascii')
        self.assertEqual(mock_getpass.return_value, plaintext_api_key)
