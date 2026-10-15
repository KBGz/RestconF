
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ISPN router
api_base_url = "https://11.11.11.1/restconf/data"
basicauth = ("admin", "class")

headers = {
    "Accept": "application/yang-data+json",
    "Content-Type": "application/yang-data+json"
}


def configure_interface(interface_config):
    interface_name = interface_config["ietf-interfaces:interface"]["name"]

    api_url = (
        f"{api_base_url}/ietf-interfaces:interfaces/"
        f"interface={interface_name.replace('/', '%2F')}"
    )

    try:
        resp = requests.put(
            api_url,
            json=interface_config,
            auth=basicauth,
            headers=headers,
            verify=False,
            timeout=10
        )

        if 200 <= resp.status_code < 300:
            print(f"{interface_name}: OK ({resp.status_code})")
        else:
            print(f"{interface_name}: ERROR ({resp.status_code})")
            print(resp.text)

    except requests.RequestException as error:
        print(f"Request failed: {error}")


# Loopback0
loopback_config = {
    "ietf-interfaces:interface": {
        "name": "Loopback0",
        "description": "Internet",
        "type": "iana-if-type:softwareLoopback",
        "enabled": True,
        "ietf-ip:ipv4": {
            "address": [
                {
                    "ip": "192.168.128.129",
                    "prefix-length": 25
                }
            ]
        }
    }
}

# Serial0/1/0
serial_config = {
    "ietf-interfaces:interface": {
        "name": "Serial0/1/0",
        "description": "ISPN to JUNK",
        "type": "iana-if-type:other",
        "enabled": True,
        "ietf-ip:ipv4": {
            "address": [
                {
                    "ip": "192.168.129.1",
                    "prefix-length": 30
                }
            ]
        }
    }
}

configure_interface(loopback_config)
configure_interface(serial_config)
