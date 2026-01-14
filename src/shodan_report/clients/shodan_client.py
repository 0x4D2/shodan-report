import shodan


class ShodanClient:
    def __init__(self, api_key: str):
        if not api_key:
            raise ("API-Key fehlt!")
        self.client = shodan.Shodan(api_key)

    def get_host(self, ip: str) -> dict:
        return self.client.host(ip)
