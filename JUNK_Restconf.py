
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


api_base_url = "https://11.11.11.2/restconf/data"

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


# Serial interface connecting JUNK to ISPN
serial_config = {
    "ietf-interfaces:interface": {
        "name": "Serial0/1/0",
        "description": "JUNK to ISPN",
        "type": "iana-if-type:other",
        "enabled": True,
        "ietf-ip:ipv4": {
            "address": [
                {
                    "ip": "192.168.129.2",
                    "prefix-length": 30
                }
            ]
        }
    }
}

#KiLLLLL Meeeeeeeee i want to bash my head to the walllllllllll


lan_config = {
    "ietf-interfaces:interface": {
        "name": "GigabitEthernet0/0/0",
        "description": "JUNK LAN",
        "type": "iana-if-type:ethernetCsmacd",
        "enabled": True,
        "ietf-ip:ipv4": {
            "address": [
                {
                    "ip": "192.168.130.1",
                    "prefix-length": 24
                }
            ]
        }
    }
}

configure_interface(serial_config)
configure_interface(lan_config)

