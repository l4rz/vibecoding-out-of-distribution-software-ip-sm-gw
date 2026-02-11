#!/usr/bin/env python3
"""CLI utility to encode RP-DATA (MO) + SMS-DELIVER TPDU and print components.

Defaults:
- Originating address (TP-OA, MSISDN): 18051234567
- Text: "Test34234"
- TP-PID: 0x00
- TP-DCS: 0x00 (GSM 7-bit)
- RP Message Reference: 0x02

Prints:
- TPDU hex
- RP header hex (without RP-UD length and data)
- Full concatenated RP+TPDU hex
"""

from __future__ import annotations

import argparse
from datetime import datetime

from gsm_rp_sms_apdu import build_rp_mo_with_sms_deliver


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Encode RP-DATA (MO) + SMS-DELIVER TPDU and print PDUs",
    )
    parser.add_argument("--oa", dest="oa", default="18051234567", help="Originating address (TP-OA) MSISDN, default: 18051234567")
    parser.add_argument("--text", dest="text", default="Test34234", help="User data text, default: 'Test34234'")
    parser.add_argument("--pid", dest="pid", default="0", help="TP-PID in hex or decimal (e.g., 0 or 0x00)")
    parser.add_argument("--dcs", dest="dcs", default="0", help="TP-DCS in hex or decimal (e.g., 0 or 0x00)")
    parser.add_argument("--mr", dest="mr", default="2", help="RP Message Reference in hex or decimal, default: 2 (0x02)")
    parser.add_argument("--rp-da", dest="rp_da", default=None, help="RP-Destination-Address MSISDN (optional)")
    return parser.parse_args()


def parse_int(val: str) -> int:
    val = str(val).strip()
    if val.lower().startswith("0x"):
        return int(val, 16)
    return int(val, 10)


def main() -> None:
    args = parse_args()
    pid = parse_int(args.pid)
    dcs = parse_int(args.dcs)
    mr = parse_int(args.mr)

    tpdu_hex, rp_header_hex, concatenated_hex = build_rp_mo_with_sms_deliver(
        oa_number=args.oa,
        text=args.text,
        pid=pid,
        dcs=dcs,
        rp_mr=mr,
        rp_da_number=args.rp_da,
    )

    print("=" * 60)
    print(f"TPDU:            {tpdu_hex}")
    print(f"RP header:       {rp_header_hex}")
    print(f"RP+TPDU:         {concatenated_hex}")
    print("=" * 60)


if __name__ == "__main__":
    main()

