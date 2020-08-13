import argparse
import base64
import datetime
import json
import os
import time
import os.path

from os import path
from cpapi import APIClient, APIClientArgs

# Script running time in seconds
DATETIME_NOW = datetime.datetime.now().replace(microsecond=0)
DATETIME_NOW_SEC = int(round(time.mktime(DATETIME_NOW.timetuple())))
DATETIME_FORMAT = "%Y-%m-%d %H:%M:%S"
DATETIME_NOW_STR = datetime.datetime.fromtimestamp(DATETIME_NOW_SEC).strftime(DATETIME_FORMAT)
log_file = None


def populate_parser():
    parser = argparse.ArgumentParser(
        description="Changed Policies Tool find which policies were changed between revisions.")
    parser.add_argument("-o", "--output-file", required=False, default="Changed_policies.json",
                        help="The name of output file")
    parser.add_argument("-u", "--username", required=False, default=os.getenv('MGMT_CLI_USER'),
                        help="The management administrator's user name.\nEnvironment variable: MGMT_CLI_USER")
    parser.add_argument("-p", "--password", required=False,
                        help="The management administrator's password.\nEnvironment variable: MGMT_CLI_PASSWORD")
    parser.add_argument("-m", "--management", required=False, default=os.getenv('MGMT_CLI_MANAGEMENT', "127.0.0.1"),
                        help="The management server's IP address (In the case of a Multi-Domain Environment, "
                             "use the IP address of the MDS domain).\nDefault: 127.0.0.1\nEnvironment variable: "
                             "MGMT_CLI_MANAGEMENT")
    parser.add_argument("--port", "--server-port", required=False, default=os.getenv('MGMT_CLI_PORT', 443),
                        help="The port of the management server\nDefault: 443\nEnvironment variable: MGMT_CLI_PORT")
    parser.add_argument("-d", "--domain", required=False, default=os.getenv('MGMT_CLI_DOMAIN'),
                        help="The name, uid or IP-address of the management domain\n"
                             "Environment variable: MGMT_CLI_DOMAIN")
    parser.add_argument('--root', '-r', choices=['true', 'false'],
                        help='\b{%(choices)s}\nLogin as root. When running on the management server, '
                             'use this flag with value set to \'true\' to login as Super User administrator.',
                        metavar=" \b\b")
    parser.add_argument("-c", "--changes", required=False,
                        help="\'show-changes\' output encoded in base 64. "
                             "Use this flag for integration with Smart Task.")

    return parser.parse_args()


# Print message with time description
def print_msg(msg):
    global log_file
    print("[{}] {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))
    log_file.write("[{}] {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg))


# Exit if the API-call failed & print error message
def exit_failure(error_msg, response):
    if response.success is False:
        print_msg(error_msg + " Error: {}".format(response.error_message))
        exit(1)


def login(user_args, client):
    if user_args.root is not None and user_args.root.lower() == 'true':
        if user_args.management == '127.0.0.1':
            login_res = client.login_as_root(domain=user_args.domain)
        else:
            print_msg("Error: Command contains ambiguous parameters. "
                      "Management server remote ip is unexpected when logging in as root.")
            exit(1)
    else:
        login_res = client.login(user_args.username, user_args.password, domain=user_args.domain, read_only=True)

    exit_failure("Failed to login.", login_res)


def find_object_usage_in_policy(client, object_id, changed_policies):
    where_used = client.api_call(command='where-used', payload={'uid': object_id})
    if where_used.success is False and "Requested object [" + object_id + "] not found" in where_used.error_message:
        print_msg("Object " + object_id + " was not found, might be not supported object.")
        return
    exit_failure("failed to find usages for " + object_id, where_used)

    get_policy_from_usage(changed_policies, where_used.data['used-directly'].get('access-control-rules', []))
    get_policy_from_usage(changed_policies, where_used.data['used-directly'].get('nat-rules', []))


def get_policy_from_usage(changed_policies, usages):
    for usage in usages:
        if usage.get('package', "") != "":
            changed_policies.append(usage.get('package').get('name'))


def get_all_packages(client, package_map):
    # if package_map is not None:
    if len(package_map) != 0:
        return package_map

    show_packages_res = client.api_query("show-packages", details_level="full", container_key="packages")
    exit_failure("failed to get packages", show_packages_res)

    for package in show_packages_res.data:
        package_name = package.get('name')
        add_layer_to_map("ALL", package_map, package_name)

        for access_layer in package.get('access-layers', []):
            add_layer_to_map(access_layer.get('uid'), package_map, package_name)

        show_nat_res = client.api_call("show-nat-rulebase", {'package': package_name})
        exit_failure("failed to get NAT rulebase", show_nat_res)
        add_layer_to_map(show_nat_res.data.get('uid'), package_map, package_name)

        add_layer_to_map(package.get('https-inspection-layer', {}).get('uid'), package_map, package_name)

    return package_map


def add_layer_to_map(layer_id, map_layers_in_packages, package_name):
    if layer_id is None:
        return

    if layer_id in map_layers_in_packages:
        map_layers_in_packages[layer_id].append(package_name)
    else:
        map_layers_in_packages[layer_id] = [package_name]


def get_package_from_map_by_layer_id(client, packages_map, layer_uid, object_type):
    changed_policies = []
    if packages_map.get(layer_uid) is not None:
        return packages_map.get(layer_uid)

    else:
        parent_layer = None
        inline_layers_in_package = set()
        current_layer_id = layer_uid

        rulebase_type = object_type.replace("rulebase", "layer")
        if rulebase_type.endswith("rule"):
            rulebase_type = object_type.replace("rule", "layer")

        while True:  # not supporting shared layers

            rulebase_res = client.api_call("show-" + rulebase_type, {"uid": current_layer_id})
            exit_failure("failed to get rulabase " + current_layer_id, rulebase_res)
            inline_layers_in_package.add(current_layer_id)

            if rulebase_res.data.get('parent-layer') is None:
                print_msg("layer " + current_layer_id + " is not in used in any package")
                # avoid this loop next time
                for layer in inline_layers_in_package:
                    packages_map.update({layer: []})
                return changed_policies

            if packages_map.get(rulebase_res.data.get('parent-layer')) is not None:
                parent_layer = rulebase_res.data.get('parent-layer')
                break

            current_layer_id = rulebase_res.data.get('parent-layer')

        for layer in inline_layers_in_package:
            if layer in packages_map:
                packages_map[layer] = packages_map[layer] + packages_map[parent_layer]
            else:
                packages_map[layer] = packages_map[parent_layer]

        changed_policies = packages_map.get(parent_layer)

    return changed_policies


def calculate_changes(client, changes, packages_map, old_object):
    if len(changes) == 0:
        return []

    changed_policies = []
    for change in changes:
        if len(change) == 0:
            continue
        changed_type = change.get('type').lower()
        # currently not supported
        if 'threat' in changed_type or 'https' in changed_type:
            print_msg(changed_type + " changes are not supported.")
            continue

        # check if global property - if yes return all packages and exit
        if change.get('type') == 'ImpliedRule' or change.get('type') == 'CpmiFirewallProperties':
            packages_map = get_all_packages(client, packages_map)
            if packages_map.get("ALL") is not None:
                return packages_map.get("ALL")

        # check if package
        if changed_type == 'package' or 'policy' in changed_type or 'policies' in changed_type:
            if change.get('name').startswith("##"):
                changed_policies.append(change.get('name')[2:])
            else:
                changed_policies.append(change.get('name'))
            continue

        # check if layer or rulebase
        if 'layer' in changed_type or 'rulebase' in changed_type:
            packages_map = get_all_packages(client, packages_map)
            changed_policies = changed_policies + get_package_from_map_by_layer_id(
                client, packages_map, change.get('uid'), changed_type)
            continue

        # check if section
        if 'section' in changed_type:
            continue

        # check if rule
        if 'rule' in changed_type:
            packages_map = get_all_packages(client, packages_map)
            # Nat rule
            if change.get('package') is not None:
                changed_policies = changed_policies + get_package_from_map_by_layer_id(
                    client, packages_map, change.get('package'), changed_type)
            # rest of the rules
            elif change.get('layer') is not None:
                changed_policies = changed_policies + get_package_from_map_by_layer_id(
                    client, packages_map, change.get('layer'), changed_type)

            continue

        # the changed object is an object
        if not old_object:
            find_object_usage_in_policy(client, change.get('uid'), changed_policies)

    return changed_policies


def print_output_to_file(changed_policies_list, session_id, domain, file_name):
    domain_name = "SMC User"
    if domain is not None:
        domain_name = domain
    print_msg("Updating output file " + file_name)
    if path.exists(file_name):
        with open(file_name, "r") as jsonFile:
            try:
                data = json.load(jsonFile)
            except ValueError:
                print_msg("Error: Decoding JSON has failed")
                exit(1)
    else:
        data = {}

    if data.get(domain_name) is None:
        data[domain_name] = {}

    if data.get(domain_name).get(session_id) is None:
        data[domain_name][session_id] = []

    data[domain_name][session_id] = changed_policies_list

    with open(file_name, 'w') as jsonFile:
        json.dump(data, jsonFile, indent=4)

    print_msg("The changed policies are:")
    global log_file
    log_file.write("{}\n".format(json.dumps({session_id: data[domain_name][session_id]}, indent=4)))
    print(json.dumps({session_id: data[domain_name][session_id]}, indent=4))

    return {session_id: data[domain_name][session_id]}


def main():
    user_args = populate_parser()
    show_changes_payload = {"details-level": "full"}

    client_args = APIClientArgs(server=user_args.management, port=user_args.port)

    with APIClient(client_args) as client:
        global log_file
        log_file = open('logfile_' + str(DATETIME_NOW_SEC) + '.txt', 'w+')
        print_msg('logfile_' + str(DATETIME_NOW_SEC) + '.txt file was created')
        # The API client, would look for the server's certificate SHA1 fingerprint in a file.
        # If the fingerprint is not found on the file, it will ask the user if he accepts the server's fingerprint.
        # In case the user does not accept the fingerprint, exit the program.
        if client.check_fingerprint() is False:
            print_msg("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)

        login(user_args, client)
        changed_policies_list = []
        diff = {}
        package_map = {}

        print_msg("Collecting data from machine..")
        if user_args.changes is None:
            changes_res = client.api_call(command='show-changes', payload=show_changes_payload)
            if changes_res.success is False:
                # in case that 'show-changes' command failed
                # we will consider this session as all the packages were changed
                print_msg("\'show-changes\' command failed. returning all packages.")

                packages_map = get_all_packages(client, package_map)
                if packages_map.get("ALL") is not None:
                    # get session details
                    last_published_session = client.api_call(command='show-sessions',
                                                             payload={'view-published-sessions': 'true', 'limit': '1'})
                    if last_published_session.success is False:
                        print_msg("Error: \'show-sessions\' command failed")
                        exit(1)
                    session_id = last_published_session.data['objects'][0]['uid']
                    changed_policies_list = list(set(packages_map.get("ALL")))
                    output = print_output_to_file(changed_policies_list, session_id,
                                                  user_args.domain,
                                                  user_args.output_file)

                    print_msg("Operation completed.")
                    return output
                else:
                    exit(1)

            diffs = changes_res.data['tasks'][0]['task-details'][0]['changes']
            if len(diffs) == 0:
                print_msg("No changes in the session.")
                print_msg("Operation completed.")
                exit(0)
            diff = diffs[0]
        else:
            decode = base64.b64decode(user_args.changes)
            diff = json.loads(decode)
            pass

        changed_policies_list = changed_policies_list + calculate_changes(
            client, diff.get('operations').get('added-objects'), package_map, False)
        changed_policies_list = changed_policies_list + calculate_changes(
            client, list(map(lambda diff_: diff_.get('new-object', {}),
                             diff.get('operations').get('modified-objects'))), package_map, False)

        changed_policies_list = changed_policies_list + calculate_changes(
            client, list(map(lambda diff_: diff_.get('old-object', {}),
                             diff.get('operations').get('modified-objects'))), package_map, True)
        changed_policies_list = changed_policies_list + calculate_changes(
            client, diff.get('operations').get('deleted-objects'), package_map, True)

        changed_policies_list = list(set(changed_policies_list))
        output = print_output_to_file(changed_policies_list, diff.get('session').get('session-uid'), user_args.domain,
                                      user_args.output_file)

        print_msg("Operation completed.")
        return output


if __name__ == "__main__":
    main()
