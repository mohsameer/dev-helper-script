import json
import consul
from tabulate import tabulate
import os
import sys

# Run script: python3 oidc-config-viewer.py <VAULT_TOKEN>
# Vault token required if you select option with secrets
# Fill below vars with environment variables

CONSUL_HOST="localhost"
CONSUL_PORT=8500
CONSUL_ADDR=CONSUL_HOST+":"+str(CONSUL_PORT)
VAULT_ADDR="http://localhost:8200"

VAULT_TOKEN=None
if len(sys.argv) > 1:
    VAULT_TOKEN=sys.argv[1]

c = consul.Consul(host=CONSUL_HOST, port=CONSUL_PORT)

def vault_evaluate_template(value):
    if VAULT_TOKEN == "" or VAULT_TOKEN is None:
        print("Please provide the VAULT_TOKEN in command line agument")
        exit(1)
    with open("./client_templ.json", "w") as f:
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        f.write(value.replace("`", "\""))
    # print(f"./consul-template -template \"./client_templ.json:./client_full.json\" -consul-addr {CONSUL_ADDR} -vault-addr {VAULT_ADDR} -vault-token {VAULT_TOKEN} -vault-renew-token=false -once ")
    try:
        os.popen(f"./consul-template -template \"./client_templ.json:./client_full.json\" -consul-addr {CONSUL_ADDR} -vault-addr {VAULT_ADDR} -vault-token {VAULT_TOKEN} -vault-renew-token=false -once  ").read()
        with open("./client_full.json", "r") as f:
            client_full = f.read()
            client_full = client_full.replace("\"\"[", "[").replace("]\"\"","]")
            client_full = client_full.replace("\"\"{", "{").replace("}\"\"","}")
            return json.loads(client_full)
    finally:
        os.remove("./client_templ.json")
        os.remove("./client_full.json")


def get_clients_with_secrets():
    clients = []
    for value in c.kv.get("oidcv2/clients", recurse=True)[1]:
        evaluated_template = vault_evaluate_template(value["Value"])
        clients.append(evaluated_template)
    return clients

def get_clients():
    clients = []
    for value in c.kv.get("oidcv2/clients", recurse=True)[1]:
        value["Value"] = json.loads(value["Value"])
        value['Value']["clientSecret"] = "********"
        value['Value']["clientId"] = "********"
        clients.append(value["Value"])
    return clients

def print_client_table(clients):
    client_tab = []
    headers = ["Description", "Client ID", "Client Secret", "RedirectUris"]
    for client in clients:
        description = client.get("description", client.get("clientName", "Not found"))
        client_tab.append([description, client["inum"], client["clientSecret"], client["redirectUris"]])
    print(tabulate(client_tab, headers=headers, tablefmt='orgtbl'))

def print_evaluated_template():
    consul_key = input("Enter the consul client key: ")
    result = c.kv.get("oidcv2/clients/"+consul_key)[1]
    if result is None:
        print("Key not found")
        exit(1)
    key_value = result["Value"].decode("utf-8")
    evaluated_template = vault_evaluate_template(key_value)
    print(json.dumps(evaluated_template, indent=2))


from simple_term_menu import TerminalMenu

options = ["Get client details", "Get client details with secrets", "Get evaluated template"]
terminal_menu = TerminalMenu(options)
menu_entry_index = terminal_menu.show()
if menu_entry_index == 0:
    print_client_table(get_clients())
if menu_entry_index == 1:
    print_client_table(get_clients_with_secrets())
if menu_entry_index == 2:
    print_evaluated_template()