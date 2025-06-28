# test_discover_aws_resources.py

import pytest
from unittest.mock import MagicMock
from discover_aws_resources import (
    sanitize_name,
    get_name_from_tags,
    discover_ec2
)

# --- Tests for Utility Functions ---

def test_sanitize_name():
    """Tests the name sanitization logic."""
    assert sanitize_name("My Awesome VPC!") == "My-Awesome-VPC"
    assert sanitize_name("a--b- -c") == "a-b-c"
    assert sanitize_name(" leading-and-trailing- ") == "leading-and-trailing"
    assert sanitize_name(None) == ""
    assert sanitize_name("no_changes_needed") == "no_changes_needed"

def test_get_name_from_tags():
    """Tests the logic for extracting a resource name from AWS tags."""
    # Case 1: 'Name' tag exists
    tags = [{'Key': 'Owner', 'Value': 'team'}, {'Key': 'Name', 'Value': 'My-Test-Instance'}]
    assert get_name_from_tags(tags, "default-name") == "My-Test-Instance"

    # Case 2: 'Name' tag does not exist
    tags = [{'Key': 'Owner', 'Value': 'team'}]
    assert get_name_from_tags(tags, "default-instance-123") == "default-instance-123"

    # Case 3: Tags list is empty or None
    assert get_name_from_tags([], "default-name") == "default-name"
    assert get_name_from_tags(None, "default-name") == "default-name"

# --- Tests for Discovery Functions ---

def test_discover_ec2_with_mock_data(mocker):
    """
    Tests the discover_ec2 function by mocking the boto3 client.
    This ensures we are testing our logic, not the AWS API.
    """
    # 1. Create a mock boto3 client
    mock_ec2_client = MagicMock()

    # 2. Define the fake data that our mock client will return
    mock_vpc_response = {
        'Vpcs': [{
            'VpcId': 'vpc-12345',
            'Tags': [{'Key': 'Name', 'Value': 'Test-VPC'}]
        }]
    }
    mock_instance_response = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-abcdef',
                'Tags': [{'Key': 'Name', 'Value': 'App-Server'}]
            }]
        }]
    }

    # 3. Configure the mock paginators to return our fake data
    # We use mocker.patch to replace the real get_paginator method
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = [
        [mock_vpc_response],  # Response for describe_vpcs
        [],                   # Empty response for subnets
        [],                   # Empty response for security groups
        [],                   # ... and so on for other ec2 calls
        [],
        [mock_instance_response]
    ]
    mocker.patch.object(mock_ec2_client, 'get_paginator', return_value=mock_paginator)
    
    # 4. Call our function with the mock client
    discovered_resources = discover_ec2(mock_ec2_client)

    # 5. Assert that our function processed the mock data correctly
    assert len(discovered_resources) == 2
    
    expected_output = [
        {'type': 'aws:ec2/vpc:Vpc', 'name': 'Test-VPC', 'id': 'vpc-12345'},
        {'type': 'aws:ec2/instance:Instance', 'name': 'App-Server', 'id': 'i-abcdef'}
    ]
    
    assert discovered_resources == expected_output
