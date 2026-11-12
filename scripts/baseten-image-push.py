"""Push a sandbox image build directory to Baseten and print its versions.

Invoked by scripts/build-baseten-pi-image.sh through `uv run`, which pins the
SDK. Reads BASETEN_API_KEY from the environment and never prints it.
"""
import argparse
import os
import sys

from baseten.sandbox import SandboxClient


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    with SandboxClient(api_key=os.environ["BASETEN_API_KEY"]) as client:
        info = client.images.push(name=args.name, directory=args.dir, wait=True)
        print(f"name={info.name} status={info.status}")
        for tag in client.images.list_tags(name=args.name):
            print(f"tag={tag.name} created={tag.created_at:%Y-%m-%dT%H:%M:%SZ} size={tag.size_bytes}")
        return 0 if str(info.status).upper().endswith("BUILT") else 1


if __name__ == "__main__":
    sys.exit(main())
