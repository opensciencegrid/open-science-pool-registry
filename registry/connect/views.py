from flask import Blueprint, make_response, render_template, current_app

from ..sources import get_user_info, get_access_point_fqdns, get_execution_endpoint_fqdns
from ..exceptions import ConfigurationError
from ..token.views import AP_ALLOWED_AUTHORIZATIONS, EE_ALLOWED_AUTHORIZATIONS

install_bp = Blueprint(
    "connect",
    __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static/connect",
)


@install_bp.route("/connect", methods=["GET"])
def connect():
    try:
        user_info = get_user_info()
    except ConfigurationError:
        return "Server configuration error", 500

    sources = get_access_point_fqdns(user_info)
    sources += get_execution_endpoint_fqdns(user_info)

    context = {"sources": sources}

    response = make_response(render_template("connect.html", **context))
    return response


@install_bp.route("/connect/docker", methods=["GET"])
def docker():
    try:
        user_info = get_user_info()
    except ConfigurationError:
        return "Server configuration error", 500

    def generate_cmd(sources, scopes):
        scope_opts = '--scope ' + ' --scope '.join(scopes)
        docker_registry = "hub.osg-htc.org"
        docker_image = "osg-htc/open-science-pool-registry:25-release"
        return {source: "mkdir -p tokens && " +
                "docker run --rm -v $PWD/tokens:/etc/condor/tokens.d" +
                f" {docker_registry}/{docker_image}" +
                f" register.py --local-dir $PWD/tokens --host {source} {scope_opts}"
                for source in sources}

    ap_sources = get_access_point_fqdns(user_info)
    ee_sources = get_execution_endpoint_fqdns(user_info)

    install_commands = generate_cmd(ee_sources, EE_ALLOWED_AUTHORIZATIONS)
    # If a host is in both the AP and EE lists, prefer an AP token
    install_commands.update(generate_cmd(ap_sources, AP_ALLOWED_AUTHORIZATIONS))

    context = {"sources": ap_sources + ee_sources, "install_commands": install_commands}

    response = make_response(render_template("docker.html", **context))
    return response


@install_bp.route("/connect/kubernetes", methods=["GET"])
def kubernetes():
    try:
        user_info = get_user_info()
    except ConfigurationError:
        return "Server configuration error", 500

    sources = get_access_point_fqdns(user_info)
    sources += get_execution_endpoint_fqdns(user_info)

    install_commands = {
        source: "bash install_htcondor.sh -c {} -n {} -d {} -x Docker".format(
            current_app.config["COLLECTOR"],
            source,
            current_app.config["DEFAULT_DATA_DIRECTORY"],
        )
        for source in sources
    }

    context = {"sources": sources, "install_commands": install_commands}

    response = make_response(render_template("kubernetes.html", **context))
    return response
