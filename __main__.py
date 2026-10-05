"""python -m pwcheck 入口（含直接运行回退）。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pwcheck import main

if __name__ == "__main__":
    raise SystemExit(main())
