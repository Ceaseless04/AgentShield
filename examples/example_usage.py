"""Example showing how to use the AgentShield SDK."""
from agentshield import OutputGuard, SecureFS


def main():
    fs = SecureFS()
    # suppose config.env contains sensitive key
    try:
        safe = fs.read_file("config.env")
        print("Read file:", safe)
    except Exception as e:
        print("error reading file:", e)

    guard = OutputGuard()
    user_output = "Here is my token: ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
    try:
        clean = guard.inspect(user_output)
        print("Guarded output:", clean)
    except Exception as e:
        print("output blocked:", e)


if __name__ == "__main__":
    main()
