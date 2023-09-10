#!/usr/bin/env python
import os
import sys
if __name__ == "__main__":
    print(f"Got it: {os.getenv('MYSECRET')}", file=sys.stderr)
    print(os.getenv("MYSECRET"))   
