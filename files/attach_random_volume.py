#!/usr/bin/python
import random
import time
from urllib2 import urlopen
from random import shuffle

import boto3

from cluster_instance_setup import attach_ebs_volumes


def get_availability_zone():
    return urlopen('http://169.254.169.254/latest/meta-data/placement/availability-zone').read()

 
def get_region():
    availability_zone = get_availability_zone()
    return availability_zone[:-1]


def get_available_volumes(tag):
    client = boto3.client('ec2', region_name=get_region())
    ids=[]
    for volume in client.describe_volumes(Filters=[{'Name':'tag:Usage', 'Values':['jenkins-volume']},{'Name':'status', 'Values':['available']},{'Name':'availability-zone', 'Values':[get_availability_zone()]}])['Volumes']:
       ids.append(volume['VolumeId'])
    return ids


def main():
    volumes = get_available_volumes({'Usage':'jenkins-volume'})
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
