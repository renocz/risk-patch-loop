"""rpl <command>: scan | inventory | risk | fixcheck | proposals | patch   (see README.md)"""
import sys

from . import __version__

COMMANDS = {
    "scan": "scan",
    "inventory": "inventory",
    "risk": "risk",
    "fixcheck": "fixcheck",
    "proposals": "proposals",
    "patch": "patch",
}


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
        print(f"risk-patch-loop {__version__}\nusage: rpl <command> [options]\ncommands: " + " | ".join(COMMANDS))
        return 0
    if sys.argv[1] == "--version":
        print(__version__)
        return 0
    name = COMMANDS.get(sys.argv[1])
    if not name:
        print(f"unknown command '{sys.argv[1]}'; commands: " + " | ".join(COMMANDS))
        return 2
    mod = __import__(f"rpl.{name}", fromlist=["main"])
    return mod.main(sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
