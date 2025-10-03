import os
from tunnel_manager.tunnel_manager import Tunnel


username = os.environ.get("TUNNEL_USERNAME")
password = os.environ.get("TUNNEL_PASSWORD")


def test_password_authentication():
    print("Testing password-based authentication...")
    try:
        # Initialize tunnel with username and password
        tunnel = Tunnel(
            remote_host="10.0.0.11",
            username=username,
            password=password,
            log_file="tunnel_password.log",
        )

        # Connect to the remote host
        tunnel.connect()

        # Run a simple command
        out, err = tunnel.run_command("whoami; cd ~/Development/; ls -la")
        print(f"Command 'whoami' output: {out}")
        if err:
            print(f"Command error: {err}")

        print(f"Command output: {out}")
        # Example file transfer (uncomment to test, ensure files exist)
        tunnel.send_file(
            "./tests/local_test.txt", "/home/genius/Downloads/remote_test.txt"
        )
        tunnel.receive_file(
            "/home/genius/Downloads/remote_test.txt", "./tests/downloaded_test.txt"
        )

        tunnel.close()
        print("Password-based authentication test completed successfully.")
    except Exception as e:
        print(f"Password-based authentication test failed: {str(e)}")


def test_key_authentication():
    print("\nTesting key-based authentication...")
    try:
        # Initialize tunnel with identity file
        tunnel = Tunnel(
            remote_host="10.0.0.11",
            username=username,
            identity_file=os.path.expanduser("~/.ssh/id_rsa"),
            log_file="tunnel_key.log",
        )

        # Connect to the remote host
        tunnel.connect()

        # Run a simple command
        out, err = tunnel.run_command("whoami")
        print(f"Command 'whoami' output: {out}")
        if err:
            print(f"Command error: {err}")

        # Example file transfer (uncomment to test, ensure files exist)
        # tunnel.send_file("local_test.txt", "/home/genius/remote_test.txt")
        # tunnel.receive_file("/home/genius/remote_test.txt", "downloaded_test.txt")

        tunnel.close()
        print("Key-based authentication test completed successfully.")
    except Exception as e:
        print(f"Key-based authentication test failed: {str(e)}")


if __name__ == "__main__":
    print("Starting SSH Tunnel Tests\n")
    test_password_authentication()
    test_key_authentication()
    print("\nAll tests completed.")
