from __future__ import annotations

import sys

from eval.cli import build_run_parser, execute_run


def main() -> int:
    args = build_run_parser().parse_args()
    return execute_run(args)


if __name__ == "__main__":
    sys.exit(main())
