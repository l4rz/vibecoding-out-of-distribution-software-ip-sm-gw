#!/usr/bin/env python3
"""Simple command–line utility to send a SIP MESSAGE that carries an
application/vnd.3gpp.sms payload to a mobile handset (UE).

This script is meant purely for *manual testing* of the MT-SMS path – it
creates a minimal outbound SIP MESSAGE using the aiovoip library and
injects the binary RP-DATA + TPDU blob that is supplied on the command
line.

For the initial implementation we keep the interface extremely simple:

    python send_sms_test.py \
        --dest '18051234567' \
        --remote 10.40.0.21:6060 \
        --local 10.40.0.19:5065 \
	--pdu <hex pdu>

Arguments
---------
--dest/-d      Destination MSISDN or full SIP URI. If a bare number is
               given, it will be translated into the standard IMS URI
               form  (e.g. sip:+number@ims.mncXXX.mccYYY.3gppnetwork.org).
--remote/-r    IP[:port] of the UE / P-CSCF we want to send the message
               to.  Default port is 5060.
--local/-l     Optional local bind IP[:port] for the UDP socket.
--pdu/-p       Hex string of the concatenated RP-DATA + TPDU payload. The
               string may contain spaces.

NOTE: *encode_rp_sms_pdu()* will be added to gsm_rp_sms_apdu.py in a later
step – for now we expect the raw hex on the CLI.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import uuid
from typing import Tuple

import aiovoip
from aiovoip.application import Application
from aiovoip.contact import Contact
from aiovoip.message import Request

LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s %(message)s'
logger = logging.getLogger("send_sms_test")


def _parse_hostport(value: str) -> Tuple[str, int]:
    """Parse "host[:port]" and return (host, port)."""
    if ':' in value:
        host, port_str = value.rsplit(':', 1)
        return host, int(port_str)
    return value, 5060  # default SIP port


def _build_sip_uri(number: str) -> str:
    """Translate a bare MSISDN into a sip:+number@... URI if required."""
    if number.lower().startswith('sip:'):
        return number
    return f"sip:+{number}@ims.mnc001.mcc001.3gppnetwork.org"


def _make_request(cseq: int, from_contact: Contact, to_contact: Contact, to_uri: str,
                  local_host: str, local_port: int, payload: bytes) -> Request:
    """Construct a aiovoip.message.Request object for SIP MESSAGE."""

    # Build SIP headers – include mandatory SIP/SMS headers requested by user
    call_id = f"{uuid.uuid4()}@ipsmgw"

    headers = {
        'Call-ID': call_id,
        'CSeq': f"{cseq} MESSAGE",  # explicit – Request would add it anyway but we override
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

    # Inject binary payload – avoids any utf-8 conversion inside aiovoip
    req._raw_payload = payload  # type: ignore[attr-defined]
    req._payload = ''  # skip encoding step
    return req


async def _async_main(args):
    logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)

    remote_host, remote_port = _parse_hostport(args.remote)
    local_host, local_port = _parse_hostport(args.local)

    # Prepare Application and connect a Peer to the UE side
    app = Application()
    logger.info("Connecting to %s:%d (local %s:%d)…", remote_host, remote_port, local_host, local_port)

    peer = await app.connect(
        remote_addr=(remote_host, remote_port),
        protocol=aiovoip.UDP,
        local_addr=(local_host, local_port),
    )

    to_uri = _build_sip_uri(args.dest)
    logger.info("Destination URI: %s", to_uri)

    to_contact = Contact.from_header(f'<{to_uri}>')
    from_contact = Contact.from_header(f'<sip:352655999999@ims.mnc002.mcc270.3gppnetwork.org>')
    logger.info("From contact: %s", from_contact)

    payload_bytes = bytes.fromhex(args.pdu.replace(' ', ''))

    request = _make_request(1, from_contact, to_contact, to_uri, local_host, local_port, payload_bytes)

    # Log the outgoing SIP headers for visibility
    logger.info("Sending SIP MESSAGE…")
    for k, v in request.headers.items():
        logger.info("%s: %s", k, v)
    logger.info("Payload (%d bytes): %s", len(payload_bytes), payload_bytes.hex().upper())

    try:
        response = peer.send_message(request)
        if asyncio.iscoroutine(response):
            response = await response  # send_message might be async in newer versions
        logger.info("SIP MESSAGE sent, response: %s (send_message might be async)", response)
    except Exception as exc:
        logger.error("Failed to send SIP MESSAGE: %s", exc)
    finally:
        await app.close()


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Send a SIP MESSAGE carrying a GSM RP+SMS payload (MT-SMS test)")
    parser.add_argument('-d', '--dest', required=True, help='Destination MSISDN or SIP URI of the handset')
    parser.add_argument('-p', '--pdu', required=True, help='Hex string of concatenated RP-DATA+TPDU payload')
    parser.add_argument('-r', '--remote', default='127.0.0.1:5060', help='Remote UE/P-CSCF address (host[:port])')
    parser.add_argument('-l', '--local', default='0.0.0.0:0', help='Local bind address (host[:port])')

    parsed_args = parser.parse_args(argv)

    try:
        asyncio.run(_async_main(parsed_args))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
