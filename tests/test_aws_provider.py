import unittest
from unittest.mock import MagicMock, patch
from src.python.orchestrator.core.normalizer import TargetResource, CloudProvider
from src.python.orchestrator.cloud_providers.aws import AWSProvider

class TestAWSProvider(unittest.TestCase):
    @patch('boto3.Session')
    def test_scan_ec2(self, mock_session):
        # Setup Mock
        mock_ec2 = MagicMock()
        mock_session.return_value.client.return_value = mock_ec2
        mock_session.return_value.get_available_regions.return_value = ['us-east-1']
        
        # Mock Paginator
        mock_paginator = MagicMock()
        mock_ec2.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'PublicIpAddress': '1.2.3.4',
                    'PublicDnsName': 'ec2-1-2-3-4.compute-1.amazonaws.com',
                    'State': {'Name': 'running'},
                    'ImageId': 'ami-12345678'
                }]
            }]
        }]

        # Execute
        provider = AWSProvider()
        resources = provider.scan_ec2()

        # Verify
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].id, 'i-1234567890abcdef0')
        self.assertEqual(resources[0].ip_address, '1.2.3.4')
        self.assertEqual(resources[0].provider, CloudProvider.AWS)

    @patch('boto3.Session')
    def test_scan_s3(self, mock_session):
        # Setup Mock
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        
        mock_s3.list_buckets.return_value = {
            'Buckets': [{'Name': 'my-test-bucket', 'CreationDate': '2023-01-01'}]
        }
        mock_s3.get_bucket_location.return_value = {'LocationConstraint': 'us-west-2'}

        # Execute
        provider = AWSProvider()
        resources = provider.scan_s3()

        # Verify
        self.assertEqual(len(resources), 1)
        self.assertEqual(resources[0].id, 'my-test-bucket')
        self.assertEqual(resources[0].region, 'us-west-2')

if __name__ == '__main__':
    unittest.main()
