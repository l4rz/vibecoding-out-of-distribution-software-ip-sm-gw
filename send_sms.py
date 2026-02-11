#!/usr/bin/env python3
"""Send a SIP MESSAGE with application/vnd.3gpp.sms payload (MT-SMS test).

Two modes of operation:
- If --pdu is supplied: send that concatenated RP-DATA + TPDU hex payload as-is
- Else: build an SMS-DELIVER TPDU from --oa and --text using library helper,
  wrap it via the same logic as the encoder utility, and send

Network parameters mirror the previous send_sms_test.py.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from typing import Tuple

import aiovoip
from aiovoip.application import Application
from aiovoip.contact import Contact
from aiovoip.message import Request

from gsm_rp_sms_apdu import (
    build_rp_mo_with_sms_deliver,
)

LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'
logger = logging.getLogger("send_sms")


def _parse_hostport(value: str) -> Tuple[str, int]:
    """Parse "host[:port]" and return (host, port)."""
    if ':' in value:
        host, port_str = value.rsplit(':', 1)
        return host, int(port_str)
    return value, 5060  # default SIP port


def _parse_int(val: str) -> int:
    val = str(val).strip()
    if val.lower().startswith("0x"):
        return int(val, 16)
    return int(val, 10)

def _make_request(cseq: int, from_contact: Contact, to_contact: Contact, to_uri: str,
                  local_host: str, local_port: int, payload: bytes) -> Request:
    """Construct an aiovoip.message.Request object for SIP MESSAGE."""

    call_id = f"{uuid.uuid4()}@ipsmgw"

    headers = {
        'Call-ID': call_id,
        'CSeq': f"{cseq} MESSAGE",
        'Max-Forwards': '70',
        'Content-Type': 'application/vnd.3gpp.sms',
        'Content-Transfer-Encoding': 'binary',
        'Accept-Contact': '*;+g.3gpp.smsip;require;explicit',
        'P-Called-Party-ID': f'<{to_uri}>',
        'Content-Length': str(len(payload)),
    }

    req = Request(
        'MESSAGE',
        cseq,
        from_details=from_contact,
        to_details=to_contact,
        contact_details=Contact.from_header(
            f'<sip:gw@{local_host}:{local_port};transport=udp>'
        ),
        headers=headers,
        payload='',  # we inject raw bytes below
    )

    # Inject binary payload – bypass any internal utf-8 encoding
    req._raw_payload = payload  # type: ignore[attr-defined]
    req._payload = ''  # skip encoding step
    return req


async def _async_main(args: argparse.Namespace) -> None:
    logging.basicConfig(level=(logging.DEBUG if args.verbose else logging.INFO), format=LOG_FORMAT)

    if not args.pdu:
        if not args.oa or not args.text:
            raise SystemExit("Either --pdu must be provided, or both --oa and --text must be set to build the payload")
        rp_mr_value = _parse_int(args.mr)
        # Use the same builder logic as the encoder utility
        tpdu_hex, rp_header_hex, concatenated_hex = build_rp_mo_with_sms_deliver(
            oa_number=args.oa,
            text=args.text,
            pid=0x00,
            dcs=0x00,
            rp_mr=rp_mr_value,
            rp_da_number=None,
        )
        # Debug breakdown like the encoder utility
        logger.debug("%s", "=" * 60)
        logger.debug("TPDU:            %s", tpdu_hex)
        logger.debug("RP header:       %s", rp_header_hex)
        logger.debug("RP+TPDU:         %s", concatenated_hex)
        logger.debug("RP-MR:           0x%02X (%d)", rp_mr_value & 0xFF, rp_mr_value & 0xFF)
        logger.debug("%s", "=" * 60)
        logger.info("Built RP+TPDU: %s", concatenated_hex)
        payload_bytes = bytes.fromhex(concatenated_hex)
    else:
        payload_bytes = bytes.fromhex(args.pdu.replace(' ', ''))

    remote_host, remote_port = _parse_hostport(args.remote)
    local_host, local_port = _parse_hostport(args.local)

    app = Application()
    logger.info("Connecting to %s:%d (local %s:%d)…", remote_host, remote_port, local_host, local_port)

    peer = await app.connect(
        remote_addr=(remote_host, remote_port),
        protocol=aiovoip.UDP,
        local_addr=(local_host, local_port),
    )

    to_uri = f"sip:+{args.dest}@{args.domain}"
    logger.info("Destination URI: %s", to_uri)

    to_contact = Contact.from_header(f'<{to_uri}>')

    # Prefer From to reflect OA if provided; otherwise use a generic local Contact
    if args.oa:
        from_contact = Contact.from_header(f'<sip:{args.oa}@{args.domain}>')
    else:
        from_contact = Contact.from_header(f'<sip:gw@{local_host}:{local_port}>')

    request = _make_request(1, from_contact, to_contact, to_uri, local_host, local_port, payload_bytes)

    logger.info("Sending SIP MESSAGE…")
    for k, v in request.headers.items():
        logger.info("%s: %s", k, v)
    logger.info("Payload (%d bytes): %s", len(payload_bytes), payload_bytes.hex().upper())

    try:
        response = peer.send_message(request)
        if asyncio.iscoroutine(response):
            response = await response
        logger.info("SIP MESSAGE sent, response: %s", response)
    except Exception as exc:
        logger.error("Failed to send SIP MESSAGE: %s", exc)
    finally:
        await app.close()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send SIP MESSAGE carrying GSM RP+SMS payload (MT-SMS test)")
    parser.add_argument('-d', '--dest', required=True, help='Destination MSISDN or SIP URI of the handset')
    parser.add_argument('-p', '--pdu', required=False, help='Hex string of concatenated RP-DATA+TPDU payload')
    parser.add_argument('-r', '--remote', default='127.0.0.1:5060', help='Remote x-CSCF address (host[:port])')
    parser.add_argument('-l', '--local', default='0.0.0.0:0', help='Local bind address (host[:port])')
    parser.add_argument('--domain', default='ims.mnc001.mcc001.3gppnetwork.org', help='IMS domain to use for building SIP URI')

    # Optional build parameters (used only when --pdu is not given)
    parser.add_argument('--oa', required=False, help='TP-Originating-Address (MSISDN) for building TPDU')
    parser.add_argument('--text', required=False, help='User data text for building TPDU')
    parser.add_argument('--mr', required=False, default='2', help='RP Message Reference (hex like 0x9C or decimal, default: 2)')

    # Verbose/debug output
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable DEBUG logging (prints TPDU/RP breakdown)')

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main() 
