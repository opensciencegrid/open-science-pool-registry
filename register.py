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

import classad2 as classad

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
TOKEN_DIR = "/etc/condor/tokens.d"
TOKEN_REQUEST_COMMAND = "condor_token_request"
TOKEN_REQUEST_ID_RE = re.compile(r"approve request (\S+)\.")
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

    # condor_token_request is a separate process, so configuration that needs to
    # apply to its collector connection is passed down via the standard
    # "_CONDOR_<PARAM>" environment variable override rather than htcondor.param.
    logger.debug('Setting SEC_CLIENT_AUTHENTICATION_METHODS to "SSL"')
    os.environ["_CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS"] = "SSL"
    os.environ["_CONDOR_SEC_CLIENT_ENCRYPTION"] = "REQUIRED"
    os.environ["_CONDOR_SEC_TOKEN_DIRECTORY"] = TOKEN_DIR

    success = request_token(
        pool=args.pool, resource=args.host, scopes=args.scope, local_dir=args.local_dir, verbose=args.verbose
    )

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


def request_token(pool, resource, scopes=None, local_dir=None, verbose=False):
    if ":" in pool:
        alias, port = pool.split(":")
    else:
        alias = pool
        port = DEFAULT_PORT
    ip, port = socket.getaddrinfo(alias, int(port), socket.AF_INET)[0][4]

    if not scopes:
        scopes = DEFAULT_TOKEN_SCOPES

    # condor_token_request accepts a sinful address (as well as a plain
    # hostname) for its "-pool" argument, so we can keep pinning the
    # resolved IP while preserving the alias for hostname-based auth checks.
    collector_addr = "<{}:{}?alias={}>".format(ip, port, alias)
    logger.debug("Constructed collector address: {}".format(collector_addr))

    token_name = "50-{}-{}-registration".format(alias, resource)
    token_path = os.path.join(TOKEN_DIR, token_name)

    success = request_token_with_retries(
        resource, collector_addr, token_name, scopes, verbose=verbose
    )

    if not success:
        return False

    print("Token request approved!")

    # We tell users to run register.py through the container and volume mount
    # "$PWD/tokens" into /etc/condor/tokens.d so our messages need to reflect
    # the host dir whenever they specify --local-dir (SOFTWARE-4372)
    if local_dir:
        # '/' is an accepted path separator across operating systems
        msg_path = os.path.join(local_dir, token_name).replace('\\', '/')
    else:
        msg_path = token_path

    print("Token was written to {}".format(msg_path))
    if is_admin():
        logger.debug("Correcting token file permissions...")
        shutil.chown(token_path, user=TOKEN_OWNER_USER, group=TOKEN_OWNER_GROUP)
        logger.debug("Corrected token file permissions...")
    else:
        print(NONROOT_TOKEN_MSG.format(path=msg_path, name=token_name))

    return True


def request_token_with_retries(
    resource, pool, token_name, scopes=None, retries=10, retry_delay=5, verbose=False
):
    """
    Retries request_token_and_wait_for_approval up to ``retries`` times (with
    ``retry_delay`` seconds between attempts), returning ``True`` as soon as
    an attempt succeeds, or ``False`` once all attempts are exhausted.

    Parameters
    ----------
    resource
        The resource to request a token for.
    pool
        The address of the collector to make the token request to.
    token_name
        The name of the token file condor_token_request should write to
        (inside SEC_TOKEN_DIRECTORY) once the request is approved.
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
            request_token_and_wait_for_approval(pool, resource, token_name, scopes, verbose)
            return True
        except Exception as e:
            logger.exception("Token request failed")
            print("Token request failed due to: {}".format(e))

    return False


def print_approval_url(request_id):
    # TODO: the url construction here is very manual; use urllib instead
    lines = [
        "Token request is queued with ID {}.".format(request_id),
        'Go to this URL in your web browser (copy and paste it into the address bar) and approve the request by clicking "Approve":',
        "https://{}/{}?code={}".format(
            WEBAPP_HOST, REGISTRATION_CODE_PATH, request_id
        ),
    ]
    print("\n".join(lines))


def request_token_and_wait_for_approval(pool, resource, token_name, scopes=None, verbose=False):
    """
    Shell out to condor_token_request to request a token for ``resource``
    from the collector at ``pool``. condor_token_request enqueues the
    request, prints the assigned request ID, and then blocks until the
    request is approved, at which point it writes the token to
    ``token_name`` (inside SEC_TOKEN_DIRECTORY) itself.

    Raises an exception if condor_token_request fails or exits without
    ever reporting a request ID.
    """
    if not scopes:
        scopes = DEFAULT_TOKEN_SCOPES

    identity = "{}{}@{}".format(RESOURCE_PREFIX, resource, RESOURCE_POSTFIX)

    cmd = [TOKEN_REQUEST_COMMAND, "-pool", pool, "-identity", identity, "-token", token_name]
    for scope in scopes:
        cmd += ["-authz", scope]
    if verbose:
        cmd.append("-debug:D_FULLDEBUG:D_SECURITY")

    # condor_token_request fully block-buffers its stdout once it isn't attached
    # to a terminal, so its approval-request message can sit unflushed in its
    # buffer for as long as it's polling for approval. stdbuf forces unbuffered
    # output so the message reaches us promptly.
    cmd = ["stdbuf", "-o0"] + cmd

    logger.debug("Running: {}".format(" ".join(cmd)))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    request_id = None
    for line in proc.stdout:
        line = line.rstrip()
        logger.debug("condor_token_request: {}".format(line))
        if request_id is not None:
            # Already found the request ID; this and any further lines are
            # just debug/error chatter that we don't need to act on.
            continue

        # condor_token_request has no machine-readable way to report the request
        # ID; it only prints a message like "... approve request <id>." once the
        # request is enqueued and before it blocks waiting for approval. Scrape
        # that line for the ID so we can build the approval URL below.
        match = TOKEN_REQUEST_ID_RE.search(line)
        if not match:
            continue
        request_id = match.group(1)
        print_approval_url(request_id)

    returncode = proc.wait()
    if request_id is None:
        raise RuntimeError("condor_token_request did not report a request ID")
    if returncode != 0:
        raise RuntimeError("condor_token_request exited with status {}".format(returncode))


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
