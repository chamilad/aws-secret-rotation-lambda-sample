import random
import string

import boto3

"""
This is a sample Python3 script to demo AWS Secrets Manager Secret Rotation
function. It does not do anything significant, and is not optimised for
production code. Modifications are needed for any use case you might adopt this
code into.
"""


def generate_password(length: int) -> str:
    """
    generates a new random password
    """

    pool = f"{string.ascii_letters}{string.digits}"
    return "".join(random.choice(pool) for i in range(length))


def handle_event(event, context):
    """
    handle the Lambda invocation, this function name should be specified as the
    Handler function when creating the Lambda function.
    """

    secret_client = boto3.client("secretsmanager")

    if event["Step"] == "createSecret":
        # first step of the process, we are generating a new value for the next
        # version of the secret here.
        print(
            f"executing create step for secret {event['SecretId']} for "
            f"version {event['ClientRequestToken']}"
        )

        # generate a new password
        new_pwd = generate_password(16)

        # persist as a new secret version setting version stage to AWSPENDING,
        # the new password isn't usable yet
        secret_client.put_secret_value(
            ClientRequestToken=event["ClientRequestToken"],
            SecretId=event["SecretId"],
            SecretString=new_pwd,
            VersionStages=["AWSPENDING"],
        )

        # we are done with the first step
        return None

    elif event["Step"] == "setSecret":
        # in the next step, we apply the new version of the secret to the
        # remote server. There can be situations where a secret is not
        # necessarily about a service credential. In those cases, this step can
        # be skipped.
        print(
            f"setting the new password from secret {event['SecretId']} for "
            f"version {event['ClientRequestToken']}"
        )

        # real world case would call the service API to set the new password
        # for an example POST /_security/user/admin/_password for an
        # Elasticsearch instance

        # retrieve the secret version that will be the new value, we don't need
        # to specify the `VersionStage` as AWSPENDING since we specify the
        # version ID.
        secret_version = secret_client.get_secret_value(
            SecretId=event["SecretId"],
            VersionId=event["ClientRequestToken"],
        )

        new_value = secret_version["SecretString"]
        print(f"changing password in the remote server with value {new_value}")

        # done with setting the new password, from now on, clients should use
        # the newly generated password to connect to the remote system
        return None

    elif event["Step"] == "testSecret":
        # in this step, the remote server change is tested to be successful.
        # Like the previous step, if the secret is not a service credential or
        # has nothing to do with an external service, this step can be skipped.
        print(
            f"testing the newly set password from secret {event['SecretId']} "
            f"for version {event['ClientRequestToken']}"
        )

        # after setting the new password, we need to make sure it's correctly
        # applied on the remote service and that the new version of the secret
        # is ready to be promoted to AWSCURRENT stage. In the sample case, we
        # just output a message.

        secret_version = secret_client.get_secret_value(
            SecretId=event["SecretId"],
            VersionId=event["ClientRequestToken"],
        )

        new_value = secret_version["SecretString"]
        print(
            f"testing the newly set password {new_value} in the remote server")

        # done with testing, we are good to finalise the rotation
        return None

    elif event["Step"] == "finishSecret":
        # final step of the rotation process. We are transitioning the new
        # secret version to be the actual "current" version. The previous
        # version is preserved, however default reads point to the new version
        # only.
        print(
            f"finalising the new password for secret {event['SecretId']} "
            f"for version {event['ClientRequestToken']}"
        )

        # two things should happen at the same time. The AWSCURRENT staging
        # label should be removed from the old one, and should be set to the
        # new value. As a side effect, AWS assigns AWSPREVIOUS to the version
        # that AWSCURRENT was just removed from.

        # find the version ID to which AWSCURRENT is attached to now
        versions = secret_client.list_secret_version_ids(
            SecretId=event["SecretId"])

        prev_version_id: str = ""
        for version in versions["Versions"]:
            for stage in version["VersionStages"]:
                if stage == "AWSCURRENT":
                    prev_version_id = version["VersionId"]

        if prev_version_id == "":
            raise RuntimeError("could not find the previous version ID")

        # set the new value to AWSCURRENT
        secret_client.update_secret_version_stage(
            SecretId=event["SecretId"],
            VersionStage="AWSCURRENT",
            MoveToVersionId=event["ClientRequestToken"],
            RemoveFromVersionId=prev_version_id,
        )

        print(
            f"successfully rotated secret {event['SecretId']} to version "
            f"{event['ClientRequestToken']}"
        )
        return None

    else:
        raise RuntimeError(
            f"secret rotation step not supported {event['Step']}")
