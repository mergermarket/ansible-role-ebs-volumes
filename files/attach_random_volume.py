#!/usr/bin/python

import boto3

from cluster_instance_setup import (
    attach_ebs_volumes, get_availability_zone, get_instance_id, get_region)
from random import shuffle


def get_available_volumes(tag):
    client = boto3.client('ec2', region_name=get_region())
    ids = []
    filters = [
        {
            'Name': 'tag:Usage',
            'Values': ['jenkins-volume']
        },
        {
            'Name': 'status',
            'Values': ['available']
        },
        {
            'Name': 'availability-zone',
            'Values': [get_availability_zone()]
        }
    ]
    for volume in client.describe_volumes(Filters=filters)['Volumes']:
        ids.append(volume['VolumeId'])
    return ids


def main():
    volumes = get_available_volumes({'Usage': 'jenkins-volume'})
    if not volumes:
        ec2 = boto3.resource('ec2', region_name=get_region())
        instance = ec2.Instance(get_instance_id())
        instance.terminate()
    shuffle(volumes)
    for volume in volumes:
        volume_json = {
            "description": "random jenkins volume",
            "volume-id": volume,
            "device": "/dev/sde",
            "create-fs": True,
            "mount-point": "/var/lib/docker"
        }
        if attach_ebs_volumes([volume_json]):
            break


if __name__ == '__main__':
    main()
