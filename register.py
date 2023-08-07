#!/usr/bin/python3

import logging
import argparse
import os
import socket
import subprocess
import sys
import traceback
import time
import shutil
import re

import htcondor
import classad

logger = logging.getLogger("register")
logger.setLevel(logging.ERROR + 10)

DEFAULT_PORT = "9618"
WEBAPP_HOST = "os-registry.opensciencegrid.org"
DEFAULT_TARGET = "cm-1.ospool.osg-htc.org:{}".format(DEFAULT_PORT)
REGISTRATION_CODE_PATH = "token"
RECONFIG_COMMAND = ["condor_reconfig"]
DEFAULT_TOKEN_SCOPES = ["READ", "ADVERTISE_MASTER"]
RESOURCE_PREFIX = "RESOURCE-"
RESOURCE_POSTFIX = "cm-1.ospool.osg-htc.org"
NUM_RETRIES = 10
TOKEN_OWNER_USER = TOKEN_OWNER_GROUP = "condor"
SOURCE_CHECK = re.compile(r"^[a-zA-Z][-.0-9a-zA-Z]*$")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Register a resource with the Open Science pool."
    )

    parser.add_argument("--host", help="The resource hostname to register.", required=True)

    parser.add_argument(
        "--pool",
        help="The pool to register with. Defaults to {}. If you specify a custom pool but don't include a port, the default port will be used ({}).".format(
            DEFAULT_TARGET, DEFAULT_PORT
        ),
        default=DEFAULT_TARGET,
    )

    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose output. Useful for debugging.",
    )

    parser.add_argument(
        "--local-dir",
        default=None,
        help="Full path to the user's local token directory outside of the container.",
    )

    parser.add_argument(
        "--scope",
        "-s",
        action="append",
        default=DEFAULT_TOKEN_SCOPES,
        help=f"Additional IDTOKEN scope to request (default: {DEFAULT_TOKEN_SCOPES}). May be specified multiple times."
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    if args.verbose:
        # HTCondor library logging setup
        htcondor.param["TOOL_DEBUG"] = "D_FULLDEBUG D_SECURITY"
        htcondor.enable_debug()

        # Python logging setup
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)s ~ %(message)s"
            )
        )

        logger.addHandler(handler)

    if not SOURCE_CHECK.match(args.host):
        error(
            "The requested hostname must be composed of only alphabetical characters (A-Z, a-z), digits (0-9), periods (.), and dashes (-). It may not begin with a digit."
        )

    # TODO: Not clear this is necessary for Docker.
    #if not is_admin():
    #    error(
    #        "This command must be run as root (on Linux/Mac) or as an administrator (on Windows)"
    #    )

    logger.debug('Setting SEC_CLIENT_AUTHENTICATION_METHODS to "SSL"')
    htcondor.param["SEC_CLIENT_AUTHENTICATION_METHODS"] = "SSL"
    htcondor.param["SEC_CLIENT_ENCRYPTION"] = "REQUIRED"

    # TODO: temporary fix for https://github.com/HTPhenotyping/registration/issues/17
    if htcondor.param["AUTH_SSL_CLIENT_CAFILE"] == "/etc/ssl/certs/ca-bundle.crt":
        htcondor.param["AUTH_SSL_CLIENT_CAFILE"] = "/etc/ssl/certs/ca-certificates.crt"
    success = request_token(pool=args.pool, resource=args.host, scopes=args.scope, local_dir=args.local_dir)

    if not success:
        error("Failed to complete the token request workflow.")

    reconfig()

    print("Registration of resource {} is complete!".format(args.host))


def is_admin():
    try:  # unix
        return os.geteuid() == 0
    except AttributeError:  # windows
        import ctypes

        return ctypes.windll.shell32.IsUserAnAdmin() == 0


NONROOT_TOKEN_MSG = '''"Registration not run as root; to use token:"
  1. Copy token to the system tokens directory: cp "{path}" /etc/condor/tokens.d/
  2. Ensure the token is owned by HTCondor: chown condor: /etc/condor/tokens.d/{name}
'''


def request_token(pool, resource, scopes=None, local_dir=None):
    if ":" in pool:
        alias, port = pool.split(":")
    else:
        alias = pool
        port = DEFAULT_PORT
    ip, port = socket.getaddrinfo(alias, int(port), socket.AF_INET)[0][4]

    if not scopes:
        scopes = DEFAULT_TOKEN_SCOPES

    coll_ad = classad.ClassAd(
        {
            "MyAddress": "<{}:{}?alias={}>".format(ip, port, alias),
            "MyType": "Collector",
        }
    )
    logger.debug("Constructed collector ad: {}".format(repr(coll_ad)))

    htcondor.param["SEC_TOKEN_DIRECTORY"] = "/etc/condor/tokens.d"

    token = request_token_and_wait_for_approval(resource, alias, coll_ad, scopes)

    if token is None:
        return False

    print("Token request approved!")

    token_dir = htcondor.param["SEC_TOKEN_DIRECTORY"]
    token_name = "50-{}-{}-registration".format(alias, resource)
    token_path = os.path.join(token_dir, token_name)

    # We tell users to run register.py through the container and volume mount
    # "$PWD/tokens" into /etc/condor/tokens.d so our messages need to reflect
    # the host dir whenever they specify --local-dir (SOFTWARE-4372)
    if local_dir:
        # '/' is an accepted path separator across operating systems
        msg_path = os.path.join(local_dir, token_name).replace('\\', '/')
    else:
        msg_path = token_path

    logger.debug("Writing token to disk (in {})".format(msg_path))
    token.write(token_name)
    logger.debug("Wrote token to disk (at {})".format(msg_path))

    print("Token was written to {}".format(msg_path))
    if is_admin():
        logger.debug("Correcting token file permissions...")
        shutil.chown(token_path, user=TOKEN_OWNER_USER, group=TOKEN_OWNER_GROUP)
        logger.debug("Corrected token file permissions...")
    else:
        print(NONROOT_TOKEN_MSG.format(path=msg_path, name=token_name))

    return True


def request_token_and_wait_for_approval(
    resource, alias, collector_ad, scopes=None, retries=10, retry_delay=5
):
    """
    This function requests a token and waits for the request to be authorized.
    If the authorization flow is successful, it will return the token.
    Otherwise, it will return ``None``.

    Parameters
    ----------
    resource
        The resource to request a token for.
    alias
        The alias of the server (only used for user-facing messages).
    collector_ad
        The ClassAd used to contact the collector to make the token request to.
    retries
        The number of times to attempt the token authorization flow.

    Returns
    -------

    """
    if not scopes:
        scopes = DEFAULT_TOKEN_SCOPES

    start_time = None
    for attempt in range(1, retries + 1):
        if start_time is not None:
            elapsed_time = time.time() - start_time
            wait_time = retry_delay - elapsed_time
            if wait_time > 0:
                print(
                    "Waiting for ~{:.1f} seconds before retrying...".format(wait_time)
                )
                time.sleep(wait_time)

        start_time = time.time()

        print("\nAttempting to get token (attempt {}/{}) ...".format(attempt, retries))
        try:
            req = make_token_request(collector_ad, resource, scopes)
        except Exception as e:
            logger.exception("Token request failed")
            print("Token request failed due to: {}".format(e))
            continue

        try:
            # TODO: the url construction here is very manual; use urllib instead
            lines = [
                "Token request is queued with ID {}.".format(req.request_id),
                'Go to this URL in your web browser (copy and paste it into the address bar) and approve the request by clicking "Approve":',
                "https://{}/{}?code={}".format(
                    WEBAPP_HOST, REGISTRATION_CODE_PATH, req.request_id
                ),
            ]
            print("\n".join(lines))
            return req.result(0)
        except Exception as e:
            logger.exception("Error while waiting for token approval.")
            print("An error occurred while waiting for token approval: {}".format(e))


def make_token_request(collector_ad, resource, scopes=None):
    if not scopes:
        scopes = DEFAULT_TOKEN_SCOPES

    identity = "{}{}@{}".format(RESOURCE_PREFIX, resource, RESOURCE_POSTFIX)

    req = htcondor.TokenRequest(identity, bounding_set=scopes)
    req.submit(collector_ad)

    # TODO: temporary fix for https://github.com/HTPhenotyping/registration/issues/10
    # Yes, we could, in principle, hit the recursion limit here, but we would have to
    # get exceedingly unlucky, and this is a simple, straightforward fix.
    # Once we upgrade the server to whatever version of HTCondor this is fixed in,
    # we can drop this code entirely.
    if req.request_id.startswith("0"):
        logger.debug("Got a token with a leading 0; trying again.")
        return make_token_request(collector_ad, resource)

    return req


def reconfig():
    # only do the reconfig if the master is alive
    if not condor_master_is_alive():
        return

    logger.debug("Running condor_reconfig to pick up the new token.")

    cmd = subprocess.run(
        RECONFIG_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    if cmd.returncode != 0:
        print(cmd.stdout.decode())
        print(cmd.stderr.decode(), file=sys.stderr)
        warning(
            "Was not able to send a reconfig command to HTCondor to make it pick up the new token. Try running ' condor_reconfig ' yourself."
        )


def condor_master_is_alive():
    """
    Returns True if and only if the condor_master is alive.
    May give false negatives (i.e., the master is alive, but we return False),
    since we are very cautious.
    """
    cmd = subprocess.run(
        ["condor_who", "-quick"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # if condor_who fails, condor is not running (may not even be installed...)
    if cmd.returncode != 0:
        logger.error(
            "Failed to determine whether the condor_master is alive because condor_who failed; assuming it is not alive"
        )
        return False

    try:
        who_ad = classad.parseOne(cmd.stdout.decode())
    except Exception:
        # this usually means condor_who printed something that wasn't the who ad, which means condor is off
        logger.exception(
            "Failed to determine whether the condor_master is alive because condor_who output was not an ad; assuming it is not alive"
        )
        return False

    logger.debug("Contents of condor_who ad:\n{}".format(who_ad))

    try:
        return who_ad["MASTER"] == "Alive"
    except Exception:
        logger.exception(
            "Failed to determine whether the condor_master is alive from the condor_who ad; assuming it is not alive"
        )
        return False


def warning(msg):
    print(
        "Warning: {}".format(msg), file=sys.stderr,
    )


def error(msg, exit_code=1):
    print(
        "Error: {}\nConsider re-running with --verbose to see debugging information.".format(
            msg
        ),
        file=sys.stderr,
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("Aborted!")
    except Exception as e:
        traceback.print_exc()
        error("Encountered unhandled error: {}".format(e))
