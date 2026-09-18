import json
import sys

from prevention.prevention_engine import PreventionEngine


def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "success": False,
            "error": "Usage: python -m prevention.cli <block|unblock|list> [ip] [reason]",
        }))
        sys.exit(1)

    action = sys.argv[1].lower()
    engine = PreventionEngine()

    if action == "list":
        result = engine.list_rules()
    elif action == "block":
        if len(sys.argv) < 3:
            result = {
                "success": False,
                "error": "Usage: python -m prevention.cli block <ip> [reason]",
            }
        else:
            reason = sys.argv[3] if len(sys.argv) > 3 else "Manual operator action"
            result = engine.block_ip(sys.argv[2], reason=reason, source="manual")
    elif action == "unblock":
        if len(sys.argv) < 3:
            result = {
                "success": False,
                "error": "Usage: python -m prevention.cli unblock <ip>",
            }
        else:
            result = engine.unblock_ip(sys.argv[2])
    else:
        result = {
            "success": False,
            "error": f"Unknown action: {action}",
        }

    print(json.dumps(result))
    sys.exit(0 if result.get("success") else 1)


if __name__ == "__main__":
    main()
