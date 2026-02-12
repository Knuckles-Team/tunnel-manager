import os
from tunnel_manager.tunnel_manager import Tunnel

username = os.environ.get("TUNNEL_USERNAME")
password = os.environ.get("TUNNEL_PASSWORD")


def test_password_authentication():
    print("Testing password-based authentication...")
    try:
        tunnel = Tunnel(
            remote_host="10.0.0.11",
            username=username,
            password=password,
        )

        tunnel.connect()

        out, err = tunnel.run_command("whoami; cd ~/Development/; ls -la")
        print(f"Command 'whoami' output: {out}")
        if err:
            print(f"Command error: {err}")

        print(f"Command output: {out}")
        tunnel.send_file(
            "/home/genius/Development/inventory/inventory.yml",
            "/home/genius/Downloads/remote_test.txt",
        )
        tunnel.receive_file(
            "/home/genius/Downloads/remote_test.txt", "./tests/downloaded_inventory.txt"
        )

        tunnel.close()
        print("Password-based authentication test completed successfully.")
    except Exception as e:
        print(f"Password-based authentication test failed: {str(e)}")


def test_key_authentication():
    print("\nTesting key-based authentication...")
    try:
        tunnel = Tunnel(
            remote_host="10.0.0.11",
            username=username,
            identity_file=os.path.expanduser("~/.ssh/id_rsa"),
        )

        tunnel.connect()

        out, err = tunnel.run_command("whoami")
        print(f"Command 'whoami' output: {out}")
        if err:
            print(f"Command error: {err}")

        tunnel.close()
        print("Key-based authentication test completed successfully.")
    except Exception as e:
        print(f"Key-based authentication test failed: {str(e)}")


if __name__ == "__main__":
    print("Starting SSH Tunnel Tests\n")
    test_password_authentication()
    test_key_authentication()
    print("\nAll tests completed.")
