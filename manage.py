"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import base64
import getpass
import hashlib
import inspect
import os
import pprint
import re
import subprocess
import time
import unittest
import uuid

import boto3
from boto3.dynamodb.conditions import Attr, Key
import hcl

from lambda_functions.build import build as lambda_build
from rules.update_rules import update_github_rules
from tests import boto3_mocks
from tests.rules.eicar_rule_test import EICAR_STRING

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.join(PROJECT_DIR, 'terraform')
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')
VARIABLES_FILE = os.path.join(TERRAFORM_DIR, 'variables.tf')

# Lambda alias terraform targets, to be updated separately.
LAMBDA_ALIASES_TERRAFORM_TARGETS = [
    '-target=module.binaryalert_{}.aws_lambda_alias.production_alias'.format(name)
    for name in ['analyzer', 'batcher', 'dispatcher', 'downloader']
]

EXPECTED_API_TOKEN_FORMAT = '[a-f0-9]{40}'  # Expected format for a CarbonBlack API token.
CB_TOKEN_VARIABLE_NAME = 'encrypted_carbon_black_api_token'
CB_KMS_ALIAS_TERRAFORM_ID = 'aws_kms_alias.encrypt_credentials_alias'
CB_KEY_ALIAS_NAME = 'alias/{}_binaryalert_carbonblack_credentials'


class ManagerError(Exception):
    """Top-level exception for Manager errors."""
    pass


class InvalidConfigError(ManagerError):
    """BinaryAlert config is not valid."""
    pass


class TestFailureError(ManagerError):
    """Exception raised when a BinaryAlert test fails."""
    pass


class Manager(object):
    """BinaryAlert management utility."""

    def __init__(self):
        self._config = None

    @property
    def commands(self):
        """Return set of available commands."""
        return {'apply', 'analyze_all', 'build', 'deploy', 'live_test', 'update_rules', 'test'}

    @property
    def help(self):
        """Return method docstring for each available command."""
        return '\n'.join(
            # Use the first line of each docstring for the CLI help output.
            '{:<15}{}'.format(command, inspect.getdoc(getattr(self, command)).split('\n')[0])
            for command in sorted(self.commands)
        )

    def _parse_config(self, allow_empty=False):
        """Parse and validate the BinaryAlert terraform.tfvars config file.

        Sets self._config to the parsed configuration dictionary.

        Args:
            allow_empty: [bool] Allow empty configuration variables (e.g. 'name_prefix').
                Used only for unit tests.

        Raises:
            InvalidConfigError: If variables are missing or empty.
        """
        with open(CONFIG_FILE) as f:
            self._config = hcl.load(f)

        with open(VARIABLES_FILE) as f:
            variable_names = hcl.load(f)['variable'].keys()

        # Set of variables names which are allowed to be empty.
        empty_allowlist = {'s3_log_bucket', 's3_log_prefix', 'encrypted_carbon_black_api_token'}
        if not self._config.get('enable_carbon_black_downloader'):
            empty_allowlist.add('carbon_black_url')  # URL can be blank if not using downloader.

        for variable in variable_names:
            # Verify that the variable is defined.
            if variable not in self._config:
                raise InvalidConfigError(
                    'variable "{}" is not defined in {}'.format(variable, CONFIG_FILE)
                )

            # Verify that the variable value is nonempty (if applicable).
            if not allow_empty and variable not in empty_allowlist and self._config[variable] == '':
                raise InvalidConfigError(
                    'variable "{}" must be non-empty in {}'.format(variable, CONFIG_FILE)
                )

    def _save_encrypted_cb_api_token(self):
        """Save an encrypted CarbonBlack API token in the config file.

        Raises:
            InvalidConfigError: If the provided API token does not match the expected format.
        """
        if (not self._config['enable_carbon_black_downloader'] or
                self._config['encrypted_carbon_black_api_token']):
            # Not using the downloader or the token already exists - nothing to do.
            return

        # Request API token using password-style input (will not be displayed on screen).
        api_token = getpass.getpass(
            'Downloader enabled but CarbonBlack API token not found. Please enter it now: ')
        if not re.match(EXPECTED_API_TOKEN_FORMAT, api_token):
            raise InvalidConfigError('"{}..." does not match expected token format {}'.format(
                api_token[:5], EXPECTED_API_TOKEN_FORMAT))

        # We need the KMS key to encrypt the API token.
        # The same key will be used by the downloader to decrypt the API token at runtime.
        print('Terraforming KMS key...')
        os.chdir(TERRAFORM_DIR)
        subprocess.check_call(
            ['terraform', 'apply', '-target={}'.format(CB_KMS_ALIAS_TERRAFORM_ID)]
        )

        print('Encrypting API token...')
        response = boto3.client('kms').encrypt(
            KeyId=CB_KEY_ALIAS_NAME.format(self._config['name_prefix']),
            Plaintext=api_token
        )
        encrypted_api_token = base64.b64encode(response['CiphertextBlob']).decode('utf-8')

        with open(CONFIG_FILE, 'w+') as config_file:
            config = config_file.read()
            config_file.seek(0)
            config_file.write(config.replace(
                'encrypted_carbon_black_api_token = ""',
                'encrypted_carbon_black_api_token = "{}"'.format(encrypted_api_token)
            ))

    def run(self, command):
        """Execute one of the available commands.

        Args:
            command: [String] Command in self.commands.
        """
        self._parse_config(allow_empty=(command == 'test'))
        boto3.setup_default_session(region_name=self._config['aws_region'])

        # Save CarbonBlack API key if applicable.
        if command != 'test':
            self._save_encrypted_cb_api_token()

        getattr(self, command)()  # Command validation already happened in the ArgumentParser.

    @staticmethod
    def apply():
        """Terraform validate and apply any configuration/package changes."""
        # Validate and format the terraform files.
        os.chdir(TERRAFORM_DIR)
        subprocess.check_call(['terraform', 'validate'])
        subprocess.check_call(['terraform', 'fmt'])

        # Setup the backend if needed and reload modules.
        subprocess.check_call(['terraform', 'init'])

        # Apply changes.
        subprocess.check_call(['terraform', 'apply'])

        # A second apply is unfortunately necessary to update the Lambda aliases.
        print('\nRe-applying to update Lambda aliases...')
        subprocess.check_call(
            ['terraform', 'apply', '-refresh=false'] + LAMBDA_ALIASES_TERRAFORM_TARGETS)

    def analyze_all(self):
        """Start a batcher to asynchronously re-analyze the entire S3 bucket."""
        function_name = '{}_binaryalert_batcher'.format(self._config['name_prefix'])

        print('Asynchronously invoking {}...'.format(function_name))
        boto3.client('lambda').invoke(
            FunctionName=function_name,
            InvocationType='Event',  # Asynchronous invocation.
            Qualifier='Production'
        )
        print('Batcher invocation successful!')

    @staticmethod
    def build():
        """Build Lambda packages (saves *.zip files in terraform/)."""
        lambda_build(TERRAFORM_DIR)

    def deploy(self):
        """Deploy BinaryAlert. Equivalent to test + build + apply + analyze_all."""
        self.test()
        self.build()
        self.apply()
        self.analyze_all()

    def live_test(self):
        """Upload an EICAR test file to BinaryAlert which should trigger a YARA match alert.

        Raises:
            TestFailureError: If the live test failed (YARA match not found).
        """
        bucket_name = '{}.binaryalert-binaries.{}'.format(
            self._config['name_prefix'].replace('_', '.'), self._config['aws_region'])
        test_filename = 'eicar_test_{}.txt'.format(uuid.uuid4())
        s3_identifier = 'S3:{}:{}'.format(bucket_name, test_filename)

        print('Uploading EICAR test file {}...'.format(s3_identifier))
        bucket = boto3.resource('s3').Bucket(bucket_name)
        bucket.put_object(
            Body=EICAR_STRING.encode('UTF-8'),
            Key=test_filename,
            Metadata={'observed_path': test_filename}
        )

        table_name = '{}_binaryalert_matches'.format(self._config['name_prefix'])
        print('EICAR test file uploaded! Connecting to table DynamoDB:{}...'.format(table_name))
        table = boto3.resource('dynamodb').Table(table_name)
        eicar_sha256 = hashlib.sha256(EICAR_STRING.encode('UTF-8')).hexdigest()
        dynamo_record_found = False

        for attempt in range(1, 11):
            time.sleep(5)
            print('\t[{}/10] Querying DynamoDB table for the expected YARA match entry...'.format(
                attempt))
            items = table.query(
                Select='ALL_ATTRIBUTES',
                Limit=1,
                ConsistentRead=True,
                ScanIndexForward=False,  # Sort by LambdaVersion descending (e.g. newest first).
                KeyConditionExpression=Key('SHA256').eq(eicar_sha256),
                FilterExpression=Attr('S3Objects').contains(s3_identifier)
            ).get('Items')

            if items:
                print('\nSUCCESS: Expected DynamoDB entry for the EICAR file was found!\n')
                dynamo_record_found = True
                pprint.pprint(items[0])

                print('\nRemoving DynamoDB EICAR entry...')
                lambda_version = items[0]['LambdaVersion']
                table.delete_item(Key={'SHA256': eicar_sha256, 'LambdaVersion': lambda_version})
                break
            elif attempt == 10:
                print('\nFAIL: Expected DynamoDB entry for the EICAR file was *not* found!\n')

        print('Removing EICAR test file from S3...')
        bucket.delete_objects(Delete={'Objects': [{'Key': test_filename}]})

        if dynamo_record_found:
            print('\nLive test succeeded! Verify the alert was sent to your SNS subscription(s).')
        else:
            # TODO: Link to troubleshooting documentation
            raise TestFailureError('\nLive test failed!')

    @staticmethod
    def update_rules():
        """Update YARA rules cloned from other open-source projects."""
        update_github_rules()

    @staticmethod
    @boto3_mocks.restore_http_adapter
    def test():
        """Run unit tests (*_test.py).

        Raises:
            TestFailureError: If any of the unit tests failed.
        """
        suite = unittest.TestLoader().discover(PROJECT_DIR, pattern='*_test.py')
        test_result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not test_result.wasSuccessful():
            raise TestFailureError('Unit tests failed')


def main():
    """Main command dispatcher."""
    manager = Manager()

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', choices=sorted(manager.commands), help=manager.help)
    args = parser.parse_args()

    manager.run(args.command)


if __name__ == '__main__':
    main()
