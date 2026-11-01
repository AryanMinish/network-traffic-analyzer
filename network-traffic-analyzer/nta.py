#!/usr/bin/env python3
"""Convenience launcher:  python nta.py analyze samples/lab_traffic.pcap"""
import sys

from nta.cli import main

if __name__ == "__main__":
    sys.exit(main())
