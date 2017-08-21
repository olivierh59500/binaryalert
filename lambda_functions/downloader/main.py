"""Lambda function - copies a binary from CarbonBlack into the BinaryAlert input S3 bucket."""
# Expects the following environment variables:
#   CARBON_BLACK_URL: URL of the CarbonBlack server.
#   ENCRYPTED_CARBON_BLACK_API_TOKEN: API token, encrypted with KMS.
#   TARGET_S3_BUCKET: Name of the S3 bucket in which to save the copied binary.
import base64
import logging
import os
import shutil
import time
import uuid
import zipfile

import boto3
import cbapi

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

ENCRYPTED_TOKEN = os.environ['ENCRYPTED_CARBON_BLACK_API_TOKEN']
DECRYPTED_TOKEN = boto3.client('kms').decrypt(
    CiphertextBlob=base64.b64decode(ENCRYPTED_TOKEN))['Plaintext']

CARBON_BLACK = cbapi.response.rest_api.CbEnterpriseResponseAPI(
    url=os.environ['CARBON_BLACK_URL'], token=DECRYPTED_TOKEN)
S3_CLIENT = boto3.client('s3')

# Exponential backoff: try up to 4 times, waiting longer each time.
RETRY_SLEEP_SECS = [0, 30, 60, 120]


def _download_from_carbon_black(md5):
    """Download the binary from CarbonBlack into /tmp.

    WARNING: CarbonBlack truncates binaries to 25MB. The MD5 will cover the entire file, but only
    the first 25MB of the binary will be downloaded.

    Args:
        md5: [string] MD5 of the binary to download.

    Returns:
        [string tuple] (Local /tmp download path, Path where the binary was discovered)
    """
    # Get the CarbonBlack binary.
    binary = CARBON_BLACK.select(cbapi.response.models.Binary, md5)

    # Download to /tmp (if it wasn't already downloaded by a previous attempt).
    download_path = '/tmp/cb-{}'.format(md5)
    if not os.path.exists(download_path):
        with binary.file as cb_file, open(download_path, 'wb') as target_file:
            shutil.copyfileobj(cb_file, target_file)

    observed = binary.observed_filename
    return download_path, observed[0] if observed else ''


def _download_with_retry(md5):
    """Wrapper around _download_from_carbon_black that retries if an error occurs."""
    for attempt, sleep_secs in enumerate(RETRY_SLEEP_SECS, start=1):
        time.sleep(sleep_secs)
        LOGGER.info(
            '[Attempt %d] Downloading %s from %s', attempt, md5, os.environ['CARBON_BLACK_URL'])
        try:
            return _download_from_carbon_black(md5)
        except (cbapi.errors.ObjectNotFoundError, zipfile.BadZipFile) as error:
            # A 404 can be returned as an HTML response, which results in an internal
            # zipfile error in the cbapi.
            LOGGER.warning('Error downloading binary: %s', type(error))

            # If this was the final attempt, give up (re-raise the error).
            if attempt == len(RETRY_SLEEP_SECS):
                LOGGER.critical('Binary could not be retrieved')
                raise error


def _upload_to_s3(local_file_path, md5, observed_path):
    """Upload a binary to S3, keyed by a UUID.

    Args:
        local_file_path: [string] Path to the file to upload.
        md5: [string] MD5 of the binary. Will be added to S3 metadata.
        observed_path: [string] Path where the binary was originally discovered.
            Will be added to S3 metadata.

    Returns:
        The newly added S3 object key (UUID).
    """
    s3_object_key = str(uuid.uuid4())  # UUID makes duplicate uploads possible.
    LOGGER.info('Uploading to S3 with key %s', s3_object_key)

    with open(local_file_path, 'rb') as target_file:
        S3_CLIENT.put_object(
            Bucket=os.environ['TARGET_S3_BUCKET'],
            Body=target_file,
            Key=s3_object_key,
            Metadata={
                'reported_md5': md5,
                # Throw out any non-ascii characters (S3 metadata must be ascii).
                'observed_path': observed_path.encode('ascii', 'ignore').decode('ascii')
            }
        )

    return s3_object_key


def download_lambda_handler(event, _):
    """Lambda function entry point - copy a binary from CarbonBlack into the BinaryAlert S3 bucket.

    Args:
        event: [dict] of the form {'md5': 'binary-MD5'}.

    Returns:
        The newly added S3 object key (UUID) representing this binary.
    """
    LOGGER.info('Invoked with event %s', event)
    md5 = event['md5']
    download_path, observed_path = _download_with_retry(md5)
    s3_object_key = _upload_to_s3(download_path, md5, observed_path)

    # Truncate and remove the downloaded file (os.remove does not work as expected in Lambda).
    with open(download_path, 'w') as file:
        file.truncate()
    os.remove(download_path)

    return s3_object_key
