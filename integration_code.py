from collections import Counter
from functools import wraps
import requests
import socket
import time
import urllib.parse


def main():
    # useful for TI commands which have an enforced naming scheme
    # (https://xsoar.pan.dev/docs/integrations/code-conventions#ioc-reputation-commands)
    transform_from_alias = config_transform({
            "file": "get-file-sha256-intel",
            "url": "get-url-intel",
            "domain": "get-url-intel",
            "ip": "get-url-intel"
        },
        prefix="ses-",
        to_under=True
    )

    # better performance for commands that fire off multiple requests
    # (reuses underlying tcp connection)
    with requests.Session() as sesh:
        client = Client(
            demisto.params().get("url") + "/v1",
            demisto.params().get("oauth_credentials"),
            req_gateway=sesh
        )

        try:
            if demisto.command() == "test-module": # integration test button
                client._request_token()
                return_results("ok")
                return "ok"

            return_results(client(demisto.command(), demisto.args(),
                   transform_from_alias=transform_from_alias))
        except Exception as e:
            demisto.error(traceback.format_exc())
            return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


strip_protocol_prefix = lambda x : x[x.find("://") + 3:] if x[0:10].find("://") != -1 else x
# assumes x to not be iterable or be list/str (other iterables can lead to unexpected results)
as_li = lambda x : x if isinstance(x, list) else [x]


""" arg type conversion decorators """

def join_li_params(delimiter, li_params):
    def decorate_convert_join(cmeth):
        @wraps(cmeth)
        def cmeth_wrapper(client, demisto_args, *args, **kwargs):
            for p_key in li_params:
                try:
                    if isinstance(demisto_args[p_key], list):
                        demisto_args[p_key] = delimiter.join(demisto_args[p_key])
                except KeyError:
                    pass

            return cmeth(client, demisto_args, *args, **kwargs)

        return cmeth_wrapper
    return decorate_convert_join

def arg_as_li(key):
    def decorate_as_li(cmeth):
        @wraps(cmeth)
        def cmeth_wrapper(client, demisto_args, *args, **kwargs):
            if key in demisto_args:
                demisto_args[key] = as_li(demisto_args[key])
            return cmeth(client, demisto_args, *args, **kwargs)

        return cmeth_wrapper
    return decorate_as_li


""" arg translation/mapping decorators """

# When acquiring a new route in the future,
# where auto enum resolving is appropriate,
# please simply reuse the preconfigured `std_cfg_enum_resolve`
# decorator instead of reconfiguring the decorator yourself.
# This means you are implicitly using the mappings in `ARG_NAMES_TO_DYN_RESOLVE`,
# if those don't suffice, consider simply adding new items as needed.
def dyn_resolve_enum_params(names_arg_to_enum):
    def decorate_dyn_resolve_enums(cmeth):
        @wraps(cmeth)
        def cmeth_wrapper(client, demisto_args, *args, **kwargs):
            if demisto_args.get("bypass_dyn_enum_validation") == "yes":
                return_warning("Bypassing dynamic API device enum validation")
                return cmeth(client, demisto_args, *args, **kwargs)

            mappings = client.get_device_enums(None).outputs # dynamically retrieving enum mappings
            for arg_name in demisto_args:
                if names_arg_to_enum.get(arg_name) is None:
                    continue # no mapping wanted for this parameter name (configure via decorator param)
                if mappings.get(names_arg_to_enum[arg_name]) is None:
                    raise ValueError(f"This command is operating under influence of a decorator parameter value which specifies a dynamic API enum parameter value alias mapping for command parameter name \"{arg_name}\" via \"{names_arg_to_enum[arg_name]}\". However, the API is not providing an enum listing for \"{names_arg_to_enum[arg_name]}\"!")

                try:
                    demisto_args[arg_name] = translate_to_api_enums(
                        mappings[names_arg_to_enum[arg_name]],
                        demisto_args[arg_name]
                    )
                except ValueError as e: # value under an arg name which has configured aliasing but does not match anything
                    msg = "An error occured during API enum lookup, based on the following dynamic mapping: "
                    msg += repr({arg_name: names_arg_to_enum[arg_name]}) + "\n" + str(e)
                    return_error(msg)

            return cmeth(client, demisto_args, *args, **kwargs)

        return cmeth_wrapper

    return decorate_dyn_resolve_enums

@arg_as_li("device_id")
def _inner_autotranslate_to_dvc_ids(client, demisto_args):
    try:
        input_names = as_li(demisto_args["name"])
    except KeyError:
        return # nothing to translate
    # allowing empty here is fine, since we perform our own validation for more specific err msg
    matching_devices = client.search_devices({"name": input_names, "allow_empty": "yes"}).outputs
    err_flag = False

    if len(matching_devices) != len(input_names):
        err_flag = True
        return_warning(f"Detected size mismatch between {len(input_names)} given device names and {len(matching_devices)} retrieved device IDs")

    unique_names = list(set([dvc["name"] for dvc in matching_devices]))
    if len(unique_names) < len(matching_devices):
        err_flag = True
        multi_id_names = [kv[0] for kv in Counter([dvc["name"] for dvc in matching_devices]).items() if kv[1] > 1]
        return_warning(f"Found these names with more than one associated device ID: {multi_id_names}")

    if err_flag:
        for name in input_names:
            if not name in unique_names:
                return_warning(f"{name} could not be found!")

    if err_flag:
        raise KeyError("Automatic mapping from provided device names failed, please check the warnings above for details.")

    translated_ids = [dvc["id"] for dvc in matching_devices]
    demisto_args["device_id"] = list(set((demisto_args.get("device_id") or []) + translated_ids))
    del demisto_args["name"]

def autotranslate_to_dvc_ids(cmeth):
    @wraps(cmeth)
    def cmeth_wrapper(client, demisto_args, *args, **kwargs):
        _inner_autotranslate_to_dvc_ids(client, demisto_args)
        return cmeth(client, demisto_args, *args, **kwargs)
    return cmeth_wrapper


""" arg-specific transforming decorators """

def strip_addr_protocol(cmeth):
    @wraps(cmeth)
    def cmeth_wrapper(client, demisto_args, *args, **kwargs):
        try:
            demisto_args["address"] = strip_protocol_prefix(demisto_args["address"])
        except KeyError:
            pass

        return cmeth(client, demisto_args, *args, **kwargs)
    return cmeth_wrapper

""" decorators def end """

ARG_NAMES_TO_DYN_RESOLVE = {
    "device_status": "security_status",
    "device_status_reason": "security_status_reason"
}
std_cfg_enum_resolve = dyn_resolve_enum_params(ARG_NAMES_TO_DYN_RESOLVE)


class Client():
    """Each of the public methods works as a command invoking an API endpoint."""
    def __init__(self, base_url, oauth_credentials, req_gateway):
        self._base_url = base_url
        self._oauth_credentials = oauth_credentials
        self._req_gateway = req_gateway

    def get_device_enums(self, _):
        return dflt_cmd_res(
            self._req("/devices/enums"),
            "deviceEnums"
        )

    def check_device_details(self, args):
        return dflt_cmd_res(
            self._req("/devices", dyn_subdirs=(args["device_id"],)),
            "deviceDetails"
        )

    @std_cfg_enum_resolve
    @join_li_params(",", ["client_version", "device_status", "os", "device_type", "name", "device_group", "device_status_reason"])
    def search_devices(self, args):
        res = self._req(
            "/devices",
            query_params=dict(args),
            q_pms_registered_args=[
                "name", "device_group",
                "os", "device_type", "ipv4_address", "mac_address",
                "is_online", "edr_enabled", "client_version", "device_status", "device_status_reason"
            ]
        )
        devices = [{"name": device["name"], "id": device["id"]} for device in res["devices"]]
        if len(devices) < 1 and args.get("allow_empty") != "yes":
            raise ValueError("No devices found matching the specified criteria")

        return CommandResults(
            outputs=devices, outputs_prefix="SES.devices", outputs_key_field="id",
            raw_response=res, readable_output=tableToMarkdown(name="devices", t=devices)
        )

    @autotranslate_to_dvc_ids
    def contentupdate_device(self, args):
        """Perform an unscheduled update of security content."""
        return dflt_cmd_res(
            self._req(
                "/commands/update_content", method="POST",
                json={"device_ids": args["device_id"]}
            ),
            "contentupdateDevice"
        )

    @autotranslate_to_dvc_ids
    def unquarantine_device(self, args):
        return dflt_cmd_res(
            self._req(
                "/commands/allow", method="POST",
                json={"device_ids": args["device_id"]}
            ),
            "unquarantineDevice"
        )

    @autotranslate_to_dvc_ids
    def quickscan_device(self, args):
        return dflt_cmd_res(
            self._req(
                "/commands/scans/quick", method="POST",
                json={"device_ids": args["device_id"], "is_recursive": False}
            ),
            "quickscanDevice"
        )

    @autotranslate_to_dvc_ids
    def restart_device(self, args):
        return dflt_cmd_res(
            self._req(
                "/commands/restart", method="POST",
                json={
                    "device_ids": args["device_id"],
                    "payload": {
                        "reason_type": "remediation",
                        "schedule_type": "now", "prompt_type": "prompt",
                        "message": "This is a restart ordered by your IT-Security department."
                    }
                }
            ),
            "restartDevice"
        )

    @arg_as_li("hash")
    @autotranslate_to_dvc_ids
    def quarantine_file(self, args):
        """
        Remove any files matching the given hash from the given devices.

        I can NOT recommend this as your designated way of containing files.
        It has considerable latency and is not exactly the most reliable form
        of conducting containments. Judging from my own, limited end to end testing,
        containment of files via this method only succeed for files already analyzed
        by the EDR in the sandbox (seemingly, encounters during a scan also suffice).
        So when determining which files at which paths (if any) to contain, NO "live"
        inventory/device search is conducted. What happens instead could be described
        as a simple lookup/archive search instead. This severely impacts the
        applicability as a response action.

        Try blocking critical IOCs by using a Blacklist Policy instead.

        Implementation details (only regarding this specific XSOAR integration,
        not the API side of things): each time this method is called, it implicitly
        orders a quick scan for each of the given devices. This might aid in containing
        files which exist on the systems at hand but which the EDR has not analyzed/
        encountered yet. However, due to limitations on the XSOAR side of things,
        the quick scan, as well as the containment are simply fired off adhoc.
        There is no guarantee the quick scan finishes in time to positively affect
        the outcome of the containment. From a practical POV, it has been observed
        to help though. Currently relies on what seems like an implementation detail
        on the EDR side of things. That could be avoided by using proper scheduling.
        """
        self.quickscan_device(args) # order quickscan in case of unencountered file

        return dflt_cmd_res(
            self._req(
                "/commands/files/contain", method="POST",
                json={"device_ids": args["device_id"], "hash": args["hash"]}
            ),
            "quarantineFile"
        )

    @autotranslate_to_dvc_ids
    def quarantine_device(self, args):
        return dflt_cmd_res(
            self._req(
                "/commands/contain", method="POST",
                json={"device_ids": args["device_id"], "is_recursive": False}
            ),
            "quarantineDevice"
        )

    @join_li_params(",", ["correlation_id", "device_id", "state"])
    def search_command_history(self, args):
        res = self._req(
            "/commands",
            query_params=dict(args),
            q_pms_registered_args=[
                "command_name", "correlation_id",
                "device_id", "state"
            ]
        )

        # if such details are required, still retrievable via referencing the returned id(s) (or by looking at the raw response data)
        detailed_fields = ["correlation_id", "created", "device_name", "feature_name", "sub_state"]

        commands = [{k: v for k, v in cmd.items() if not k in detailed_fields} for cmd in res["commands"]]
        return CommandResults(
            outputs=commands, outputs_prefix="SES.commands", outputs_key_field="id",
            raw_response=res, readable_output=tableToMarkdown(name="commands", t=commands)
        )

    def check_command_state(self, args):
        return dflt_cmd_res(
            self._req(
                "/commands",
                dyn_subdirs=(args.get("command_id", None) or args.get("command_state_ref", None) or args["state_ref"],)
            ),
            "commandState"
        )

    def check_file_sha256_details(self, args):
        return dflt_cmd_res(self._req("/files", dyn_subdirs=(args["file_sha256"],)), "fileDetails")

    def search_file_sha256_devices(self, args):
        res = self._req("/files", dyn_subdirs=(args["file_sha256"], "devices"))
        devices = [{"name": dvc["name"]} for dvc in res["devices"]]
        return CommandResults(
            outputs=devices, outputs_prefix="SES.fileDevicesSeenOn",
            raw_response=res, readable_output=tableToMarkdown(name="fileDevicesSeenOn", t=devices)
        )

    @autotranslate_to_dvc_ids
    def search_file_sha256_paths(self, args):
        if len(args["device_id"]) == 1:
            args["device_id"] = args["device_id"][0]
        else:
            raise ValueError("Expecting exactly one device!")

        return dflt_cmd_res([
            {"path": path} for path in self._req("/files",
                dyn_subdirs=(args["file_sha256"], "devices", args["device_id"], "paths"))
        ], "filePaths")

    def get_file_sha256_intel(self, args):
        res = self._req("/threat-intel/insight/file", dyn_subdirs=(args["file_sha256"],))
        return dflt_cmd_res(
            res, "hashTI",
            indicator=as_indicator(res["file"], res)
        )

    @strip_addr_protocol
    def get_url_intel(self, args):
        res = self._req("/threat-intel/insight/network", dyn_subdirs=(args["address"],))
        return dflt_cmd_res(
            res, "hostTI",
            indicator=as_indicator(res["network"], res)
        )

    def get_file_sha256_related_intel(self, args):
        return dflt_cmd_res(
            self._req("/threat-intel/related/file", dyn_subdirs=(args["file_sha256"],)),
            "hashRelatedTI"
        )

    @strip_addr_protocol
    def get_url_related_intel(self, args):
        return dflt_cmd_res(
            self._req("/threat-intel/related/network", dyn_subdirs=(args["address"],)),
            "hostRelatedTI"
        )

    def _req(
        self,
        endpoint, method="GET",
        dyn_subdirs=None, query_params=None,
        unwrap=True, q_pms_registered_args=None,
        auth_override=None, **kwargs
    ):
        if query_params is not None and q_pms_registered_args is not None:
            query_params = {key: query_params[key] for key in q_pms_registered_args if query_params.get(key)}
            if len(query_params) == 0:
                return_warning("These are the permitted args for this command: " + repr(q_pms_registered_args))
                raise ValueError("No registered arguments were passed, aborting request")

        target = self._base_url + endpoint

        if dyn_subdirs is not None:
            for sub in dyn_subdirs:
                if not target.endswith("/"):
                    target += "/"
                target += urllib.parse.quote_plus(sub, safe="")

        res = getattr(self._req_gateway, method.lower())(
            target,
            params=query_params,
            headers=self._gen_headers(auth_override=auth_override),
            **kwargs
        )
        return self._unwrap_res(res) if unwrap else res

    def _gen_headers(self, auth_override=None):
        return {
            "accept": "application/json",
            "content-type": "application/json",
            "authorization": auth_override if auth_override else str(self._retrieve_token())
        }

    def _retrieve_token(self):
        token = get_integration_context().get("access_token")
        valid_until = get_integration_context().get("valid_until")
        now = int(time.time())

        if token and valid_until and now < valid_until:
            return token

        token = self._request_token()
        set_integration_context({
            "access_token": token,
            "valid_until": now + 3600 # API default expiration time: 1 hour
        })
        return token

    def _request_token(self):
        return self._req(
            "/oauth2/tokens",
            method="POST",
            auth_override=self._oauth_credentials
        )["access_token"]

    def _unwrap_res(self, response):
        try:
            response.raise_for_status()
            return response.json()
        except requests.HTTPError as e: # setup for possible expansion in the future (on certain calls, non-2XX status codes might be acceptable/expected)
            try: # try providing JSON via warning as additional context
                return_warning(response.json())
            except: # on non-successful requests, JSON might be invalid/not there at all (e.g. 404s)
                pass

            raise e # make the caller handle


    # provides a pythonic shortcut over calling a command method directly as seen in the internals directly below
    def __call__(self, cmd, args, transform_from_alias=None):
        target = transform_from_alias(cmd) if callable(transform_from_alias) else cmd
        # protects members only meant for internal usage from being accessed by the caller
        if target.startswith("_"): # either marked via leading underscore per convention or mangled
            return_error("Accessing private members directly as a command is disallowed.")

        try:
            callee = getattr(self, target)
        except AttributeError as e:
            return_warning("You tried to execute a command that does not exist/is not enabled: " + str(e))
            raise NotImplementedError() from e
        else:
            return callee(args)


def translate_to_api_enums(api_enum_strs_to_argv_aliases, values_to_translate):
    """
    Map alias names to enum values based on the given API JSON content.

    Given a dictionary of accepted enum values mapped to their alias
    as specified by a response of the `/devices/enums` endpoint
    and a single string or list of strings,
    replace each alias with the corresponding enum value.

    If any of the input strings is not found on either side of the mapping,
    emits a warning listing the dictionary and raises a ValueError.
    """
    res = []
    inv = {v: k for k, v in api_enum_strs_to_argv_aliases.items()} # aliases_to_api_enum_strs
    for v in values_to_translate if isinstance(values_to_translate, list) else [values_to_translate]:
        if v in api_enum_strs_to_argv_aliases: # caller passed api enum str directly
            res.append(v)
            continue

        try:
            res.append(inv[v])
        except KeyError:
            return_warning(f"These are the acceptable argument aliases and the values they map to: \"{repr(inv)}\"")
            raise ValueError(f"The following value is neither a known API enum value nor a permitted alias: \"{v}\"")

    if not isinstance(values_to_translate, list):
        assert len(res) == 1
        res = res[0]

    return res


def dflt_cmd_res(res, command_ctx_key, indicator=None):
    """Wrap dictionary into conventional XSOAR command output format."""
    return CommandResults(
        outputs_prefix="SES." + command_ctx_key,
        outputs=res, raw_response=res,
        readable_output=tableToMarkdown(name=command_ctx_key, t=res),
        indicator=indicator
    )


def categorize_ioc_type(value):
    """Try to deduce an IOC's type given only its string value."""
    if len(value) == 64: # assume sha256 based on length ..
        return "file"
    try:
        socket.inet_aton(value)
        return "ip" # IPv4
    except OSError:
        return "url" if "/" in strip_protocol_prefix(value) else "domain"

def translate_rep_to_dbot_score(ti_dict, strict=False):
    """
    Generate an indicator classification based on an API response.

    The verdict mainly hinges on the reputation value,
    the whole JSON-content is required though.
    This way, some FPs can be avoided by factoring in the categorization.
    """
    # odd behavior of Symantec TI reputation field: can't rely on its presence in all cases
    reputation = "" if ti_dict.get("reputation") is None else ti_dict["reputation"].upper()
    if reputation == "GOOD":
        return Common.DBotScore.GOOD
    elif reputation == "BAD":
        try:
            assert len(ti_dict["categorization"]["categories"]) == 1
            ti_dict["categorization"]["categories"][0]["name"]
        except (KeyError, TypeError, AssertionError):
            pass
        else: # prevent weird FPs which should really just be sus classifications, not clearly bad
            if ti_dict["categorization"]["categories"][0]["name"] == "Suspicious":
                return Common.DBotScore.SUSPICIOUS

        return Common.DBotScore.BAD
    else:
        return Common.DBotScore.SUSPICIOUS if strict else Common.DBotScore.NONE

def as_indicator(value, ti_dict, strict=False):
    """Create an XSOAR Indicator based on a value and API response."""
    value = urllib.parse.unquote_plus(value)
    cat = categorize_ioc_type(value)
    return getattr(Common, cat.upper() if len(cat) <= 3 else cat.capitalize())(
        **{
            cat if cat != "file" else "sha256": value,
            "dbot_score": Common.DBotScore(
                indicator = value,
                indicator_type = getattr(DBotScoreType, cat.upper()),
                score = translate_rep_to_dbot_score(ti_dict, strict=strict),
                integration_name = "SES - EDR (cloud)"
            )
        }
    )


def config_transform(alias_dict, prefix=None, to_under=False):
    def transform_from_alias(in_cmd):
        if prefix and in_cmd.startswith(prefix):
            in_cmd = in_cmd[len(prefix):]

        if alias_dict.get(in_cmd):
            return_warning(f"Applying command alias: \"{alias_dict[in_cmd]}\"")
            in_cmd = alias_dict[in_cmd]

        return in_cmd.replace("-", "_") if to_under else in_cmd

    return transform_from_alias


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
