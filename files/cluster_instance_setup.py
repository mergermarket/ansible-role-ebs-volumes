#!/usr/bin/python

"""Setup cluster instance.

Usage:
  cluster-instance-setup [--ebs-volumes=<ebs-volumes>] [--efs-filesystem=<efs-filesystem>]
  cluster-instance-setup (-h | --help)
  cluster-instance-setup --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --ebs-volumes=<ebs-volumes>  JSON array of ebs volumes to attach.
  --efs-filesystem=<efs-filesystem> ID of EFS filesystem to mount.

""" # noqa

from __future__ import print_function

# pylint: disable=C0111
# pylint: disable=W0703

import json
import sys
import re
import logging
from time import sleep
from os import path, environ
from subprocess import check_call, check_output
import boto3
from docopt import docopt
from random import random

datadog_key = environ.get('DATADOG_API_KEY', None)


def setup_logger():
    logger = logging.getLogger(__name__)
    channel = logging.StreamHandler(sys.stderr)
    channel.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    logger.addHandler(channel)
    logger.setLevel(level=logging.INFO)
    return logger

LOGGER = setup_logger()


def fetch_instance_metadata():
    return json.loads(check_output([
        "curl",
        "-s",
        "http://169.254.169.254/latest/dynamic/instance-identity/document/"
    ]))


def main(arguments):
    if arguments.get("--ebs-volumes") is not None:
        LOGGER.info("Attaching ebs volumes...")
        attach_ebs_volumes(json.loads(arguments.get("--ebs-volumes")))
        LOGGER.info("Done attaching ebs volumes.")
    if arguments.get("--efs-filesystem") is not None:
        LOGGER.info("Configuring EFS...")
        configure_efs(arguments.get("--efs-filesystem"))
        LOGGER.info("Done configuring EFS.")


def check_volume_attachment(
    boto_ec2_client, volume_id, device, local_device, detach
):
    LOGGER.info("Describing volume %s", volume_id)

    volume = boto_ec2_client.describe_volumes(
        VolumeIds=[volume_id]
    ).get("Volumes")[0]
    state = volume.get("State")

    LOGGER.info("Volume %s has state %s", volume_id, state)

    if state == "in-use":
        if attached_to_this_instance(volume_id, volume):
            LOGGER.info(
                "Volume %s already attached to this instance.", volume_id
            )
            return False
        elif detach:
            LOGGER.info("Detaching volume %s...", volume_id)
            detach_volume(boto_ec2_client, volume_id)
            return True
        else:
            raise AttachedToOtherInstanceException(
                "volume is attached to another instance"
            )

    elif state != "available":
        raise UnexpectedVolumeStateException(
            "volume %s is in state %s" % (volume_id, state)
        )

    return True

def detach_volume(boto_ec2_client, volume_id):
    max_wait = 5
    next_wait = 1

    while True:
        boto_ec2_client.detach_volume(VolumeId=volume_id)

        volume = boto_ec2_client.describe_volumes(
            VolumeIds=[volume_id]
        ).get("Volumes")[0]
        if volume.get("State") == 'available':
            return True
        else:
            next_wait = (0.875 + (random() / 4)) * min(max_wait, 2 * next_wait)

        sleep(next_wait)


def attach_volume(boto_ec2_client, instance_id, volume_id, device):
    max_wait = 10
    next_wait = 1

    while True:
        LOGGER.info(
            "Attaching volume {} to instance {} (device {})...".format(
                volume_id, instance_id, device
            )
        )
        volume = boto_ec2_client.describe_volumes(
            VolumeIds=[volume_id]
        ).get("Volumes")[0]
        if volume.get("State") == 'available':
            try:
                boto_ec2_client.attach_volume(
                    VolumeId=volume_id,
                    InstanceId=instance_id,
                    Device=device,
                )
            except Exception as err:
                LOGGER.error("Error attaching volume (%s) - %s", volume_id, err)

        if device_exist(device):
            return True

        next_wait = (0.875 + (random() / 4)) * min(max_wait, 2 * next_wait)
        sleep(next_wait)


def wait_for_device_to_exist(device):
    while True:
        LOGGER.info("Checking for existence of %s...", device)
        if path.exists(device):
            return
        sleep(1)


def device_exist(device):
    LOGGER.info("Checking for existence of %s...", device)
    if path.exists(device):
        return True


def attached_to_this_instance(volume_id, volume):
    metadata = fetch_instance_metadata()
    for attachment in volume.get("Attachments"):
        if attachment.get("State") == "attached":
            return attachment.get("InstanceId") == metadata.get("instanceId")
    raise Exception(
        "could not find attachment for in-use volume %s" % volume_id
    )


def check_filesystem(device, create_fs):
    LOGGER.info("Checking if filesystem exists on device %s...", device)
    if "XFS" not in check_output(["file", "-sL", device]).decode('ascii'):
        if create_fs:
            LOGGER.info("Creating XFS filesystem on device %s...", device)
            check_call(["mkfs.xfs", device])
        else:
            raise NoFilesystemException("no filesystem, not creating")


def check_filesystem_mount(volume_id, device, mount_point):
    LOGGER.info(
        "Checking if device %s is mounted at %s...", device, mount_point
    )
    mounted_at = get_mounts().get(device, None)
    if mounted_at is not None:
        if mounted_at != mount_point:
            raise Exception("volume %s mounted at %s (expected %s)" % (
                volume_id,
                mounted_at,
                mount_point,
            ))
        LOGGER.info("Device %s already mounted at %s.", device, mount_point)
        return
    LOGGER.info("Mounting device %s at %s...", device, mount_point)
    check_call(["mkdir", "-p", mount_point])
    check_call(["touch", "%s/%s" % (mount_point, "ebs-volume-not-mounted")])
    check_call(["mount", device, mount_point])


def get_mounts():
    return {key: val for key, val in [
        re.match(r"^(.*?) on (\S+)", line).groups()
        for line in str.splitlines(check_output(["mount"]))
    ]}


def check_fstab(device, mount_point):
    LOGGER.info(
        "Checking if mount point exists in /etc/fstab for %s...", device
    )
    for line in str.splitlines(open("/etc/fstab").read()):
        if line.startswith("%s " % device):
            if not line.startswith("%s %s " % (device, mount_point)):
                raise Exception(
                    "/etc/fstab contains device %s at %s (expected at %s)" % (
                        device,
                        line.search(r"^\S+ (\S+) ").groups()[0],
                        mount_point
                    )
                )
            LOGGER.info(
                "Mount point exists in /etc/fstab for {} at {}.".format(
                    device, mount_point
                )
            )
            return
    LOGGER.info("Writing to /etc/fstab for %s at %s...", device, mount_point)
    with open("/etc/fstab", "a") as handle:
        handle.write("%s %s auto defaults 0 0\n" % (device, mount_point))


def volume_values(volume):
    default_mount = "/mnt/{}".format(volume.get("volume-id"))
    return (
        volume.get("volume-id"),
        volume.get("mount-point", default_mount),
        volume.get("device"),
        re.sub(r"^/dev/sd", "/dev/xvd", volume.get("device")),
        volume.get("detach", True),
        volume.get("create-fs", False),
    )


def panic(title, text):
    metadata = fetch_instance_metadata()
    LOGGER.error(title + ": " + text)
    if datadog_key is not None:
        check_call([
            "curl",
            "-s", "https://app.datadoghq.com/api/v1/events?api_key={}".format(
                datadog_key
            ),
            "-H", "Content-Type: application/json",
            "-d", json.dumps({
                "title": title,
                "text": text,
                "host": check_output(["hostname"]),
                "tags": [
                    "%s:%s" % (k, v)
                    for k, v in {
                        "region": metadata["region"],
                        "az": metadata["availabilityZone"],
                        "instance-id": metadata["instanceId"],
                        "image-id": metadata["imageId"],
                        "account-id": metadata["accountId"],
                    }.items()
                ],
            })
        ])
    sys.exit(1)


def attach_ebs_volumes(volumes):
    for volume in volumes:
        try:
            metadata = fetch_instance_metadata()
            boto_ec2_client = boto3.session.Session(
                region_name=metadata.get("region")
            ).client("ec2")
            volume_id, mount_point, device, local_device, detach, create_fs =\
                volume_values(volume)
            if check_volume_attachment(
                boto_ec2_client, volume_id, device, local_device, detach
            ):
                attach_volume(
                    boto_ec2_client,
                    metadata.get('instanceId'),
                    volume_id,
                    local_device
                )
            check_filesystem(local_device, create_fs)
            check_filesystem_mount(volume_id, local_device, mount_point)
            check_fstab(local_device, mount_point)
        except Exception as err:
            panic(
                "error mounting ebs volume",
                "volume id: %s, error: %s" % (volume_id, str(err)),
            )

        LOGGER.info(
            "Volume {} successfully attached at mounted at {}.".format(
                volume_id, mount_point
            )
        )


def configure_efs(filesystem_id):
    metadata = fetch_instance_metadata()
    mount_point = "/mnt/efs"
    check_call(["mkdir", "-p", mount_point])
    with open("/etc/fstab", "a") as handle:
        handle.write(
            "{}.{}.efs.{}.amazonaws.com:/ {} nfs4 nfsvers=4.1 0 0\n".format(
                metadata.get("availabilityZone"),
                filesystem_id,
                metadata.get("region"),
                mount_point
            )
        )
    check_call(["mount", mount_point])


class NoFilesystemException(Exception):
    pass


class UnexpectedVolumeStateException(Exception):
    pass


class AttachedToOtherInstanceException(Exception):
    pass


if __name__ == "__main__":
    main(docopt(__doc__))
