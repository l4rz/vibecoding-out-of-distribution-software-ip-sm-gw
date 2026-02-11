import asyncio
import xml.etree.ElementTree as ET
from sms_codec import decode_vnd_sms
from router import select_route
import logging
import aiovoip
import traceback
from aiovoip import Dialog, Application, BaseDialplan, Message
from ursine import URI, Header
import subprocess

logger = logging.getLogger("ipsmgw")

# Monkey patch to fix aiovoip Via header issue
# The original code expects a string but receives a list
import aiovoip.application
original_run_dialplan = aiovoip.application.Application._run_dialplan

async def patched_run_dialplan(self, protocol, msg):
    call_id = msg.headers['Call-ID']
    via_header = msg.headers['Via']
    
    # Fix: Handle case where Via header is a list
    if isinstance(via_header, list):
        via_header = via_header[0]  # Take the first Via header
        logger.info(f"Fixed Via header from list: {via_header}")
    
    connector = self._connectors[type(protocol)]
    from aiovoip.via import Via
    via = Via.from_header(via_header)
    via_addr = via['host'], int(via['port'])
    # get_peer handles connection part, either creates or finds existing one
    peer = await connector.get_peer(protocol, via_addr)

    handler = await self.dialplan.resolve(
        method=msg.method,
        message=msg,
        protocol=peer.protocol,
        local_addr=peer.local_addr,
        remote_addr=peer.peer_addr
    )

    if not handler or not asyncio.iscoroutinefunction(handler):
        await reply(msg, status_code=501)
        return

    # Create task and manage it like the original code
    t = asyncio.create_task(self._call_route(peer, handler, msg))
    self._tasks.append(t)
    try:
        await t
    finally:
        self._tasks.remove(t)

# Add the _call_route method to the Application class
async def patched_call_route(self, peer, route, msg):
    call_id = msg.headers['Call-ID']
    from aiovoip.application import Request
    request = Request(peer, msg, call_id)
    await route(request, msg)

# Apply the monkey patches
aiovoip.application.Application._run_dialplan = patched_run_dialplan
aiovoip.application.Application._call_route = patched_call_route

class SIPDialplan(BaseDialplan):
    def __init__(self, registry):
        super().__init__()
        self.registry = registry
        
    async def resolve(self, method, message, protocol, local_addr, remote_addr):
        await super().resolve(method, message, protocol, local_addr, remote_addr)
        
        logger.info(f"Resolving SIP method: {method}")
        logger.info(f"Protocol: {protocol}")
        logger.info(f"Local addr: {local_addr}")
        logger.info(f"Remote addr: {remote_addr}")
        
        # Safe logging of message headers and body
        try:
            logger.info(f"Message headers: {message.headers}")
        except Exception as e:
            logger.warning(f"Could not log message details: {e}")
        
        if method == 'REGISTER':
            return self.on_register
        elif method == 'MESSAGE':
            return self.on_message
        else:
            logger.warning(f"Unsupported SIP method: {method}")
            return None
    
    async def on_register(self, request, message):
        """Handle SIP REGISTER requests"""
        logger.info("REGISTER handler called")
        logger.info(f"Request: {request}")
        
        # Safe logging of message details
        try:
            logger.info(f"Message headers: {message.headers}")
        except Exception as e:
            logger.warning(f"Could not log message details: {e}")
        
        try:
            # Extract IMSI from various possible locations
            imsi = None
            tel_uri = None
            expiry = 3600  # Default expiry
            
            # Try to extract from SIP headers
            auth_header = message.headers.get('Authorization', '')
            from_header = message.headers.get('From', '')
            contact_header = message.headers.get('Contact', '')
            to_header = message.headers.get('To', '')
            expires_header = message.headers.get('Expires', '3600')
            
            logger.info(f"Auth header: {auth_header}")
            logger.info(f"From header: {from_header}")
            logger.info(f"Contact header: {contact_header}")
            logger.info(f"To header: {to_header}")
            logger.info(f"Expires header: {expires_header}")
            
            # Extract IMSI from Authorization or From header
            import re
            for header in [auth_header, from_header]:
                if header:
                    imsi_match = re.search(r'(\d{14,15})', header)
                    if imsi_match:
                        imsi = imsi_match.group(1)
                        logger.info(f"Extracted IMSI from header: {imsi}")
                        break
            
            # Extract TEL URI from Contact or To header
            for header in [contact_header, to_header]:
                if header:
                    tel_match = re.search(r'tel:([^>\s]+)', header)
                    if tel_match:
                        tel_uri = f"tel:{tel_match.group(1)}"
                        logger.info(f"Extracted TEL URI from header: {tel_uri}")
                        break
            
            # Extract expiry
            if expires_header:
                try:
                    expiry = int(expires_header)
                    logger.info(f"Extracted expiry: {expiry}")
                except ValueError:
                    logger.warning(f"Invalid expiry value: {expires_header}")
            
            # TBD: If we still don't have IMSI, try to extract from XML body
            '''
            if not imsi and message.body: # there is no body in the REGISTER request
                content_type = message.headers.get('Content-Type', '')
                if 'application/3gpp-ims+xml' in content_type:
                    logger.info("Found 3GPP IMS XML content, attempting to parse...")
                    try:
                        # Parse XML to extract IMSI and TEL URI
                        root = ET.fromstring(message.body)
                        
                        # Look for IMSI in private-id element
                        private_id = root.findtext('.//private-id')
                        if private_id:
                            imsi = private_id
                            logger.info(f"Extracted IMSI from XML: {imsi}")
                        
                        # Look for TEL URI in public-id element
                        public_id = root.findtext('.//public-id')
                        if public_id and public_id.startswith('tel:'):
                            tel_uri = public_id
                            logger.info(f"Extracted TEL URI from XML: {tel_uri}")
                        
                    except ET.ParseError as e:
                        logger.error(f"Failed to parse XML: {e}")
                    except Exception as e:
                        logger.error(f"Error parsing XML content: {e}")
            '''
            # TBD: Validate extracted data
            '''
            if not imsi:
                logger.error("Could not extract IMSI from REGISTER request")
                await request.prepare(status_code=400)
                return
            '''
            
            # Extract MSISDN from From header (digits after sip:+ and before @ or >)
            msisdn_match = re.search(r'sip:\+(\d+)', from_header)
            msisdn = msisdn_match.group(1) if msisdn_match else None

            if not msisdn:
                logger.error("Could not extract MSISDN from REGISTER request")
                await request.prepare(status_code=400)
                return

            # Extract src-ip parameter from Contact header
            src_ip_match = re.search(r'src-ip=([0-9.]+)', contact_header)
            ip_addr = src_ip_match.group(1) if src_ip_match else remote_addr[0]

            visited_network = message.headers.get('P-Visited-Network-ID', '')
            access_network_info = message.headers.get('P-Access-Network-Info', '')
            charging_vector = message.headers.get('P-Charging-Vector', '')

            logger.info(f"Parsed REGISTER MSISDN={msisdn}, IP={ip_addr}, VNID={visited_network}, PANI={access_network_info}, PCV={charging_vector}, expiry={expiry}")

            await self.registry.add_or_update(msisdn, ip_addr, visited_network, access_network_info, charging_vector, expiry)
            logger.info(f"Registration stored for MSISDN={msisdn}")
            
            # Send 200 OK response
            await request.prepare(status_code=200)
            
        except Exception as e:
            logger.exception(f"Exception in REGISTER handler: {e}")
            await request.prepare(status_code=400)

    async def on_message(self, request, message):
        """Handle SIP MESSAGE requests"""
        logger.info("MESSAGE handler called")
        
        # Debug Request object structure
        logger.info("=== REQUEST OBJECT DEBUG ===")
        logger.info(f"Request type: {type(request)}")
        logger.info(f"Request dir: {dir(request)}")
        logger.info(f"Request dict: {request.__dict__}")
        
        # Debug Message object structure
        logger.info("=== MESSAGE OBJECT DEBUG ===")
        logger.info(f"Message type: {type(message)}")
        # logger.info(f"Message dir: {dir(message)}")
        logger.info(f"Message dict: {message.__dict__}")
        
        # Safe logging of message details
        try:
            logger.info(f"Message headers: {message.headers}")
            
            # Check all possible body attributes
            # for attr in ['body', 'payload', 'data', 'content', '_raw_payload', '_payload']:
            # for attr in ['payload', 'data', 'content', '_raw_payload', '_payload']:
            for attr in ['payload', 'data', 'content', '_payload']:
                if hasattr(message, attr):
                    value = getattr(message, attr)
                    logger.info(f"Message.{attr}: {value}")
                    if value and isinstance(value, bytes):
                        logger.info(f"Message.{attr} (hex): {value.hex()}")
                        logger.info(f"Message.{attr} (length): {len(value)}")
                else:
                    logger.info(f"Message.{attr}: <not found> 252")
                    
        except Exception as e:
            logger.warning(f"Could not log message details: {e}")
        
        try:
            content_type = message.headers.get('Content-Type', '')
            logger.info(f"Content-Type: {content_type}")
            
            if 'application/vnd.3gpp.sms' in content_type:
                logger.info("Found 3GPP SMS content")
                
                # Extract SMS data from the request body
                sms_data = None
                
                # Try different ways to get the SMS data
                if hasattr(message, '_raw_payload') and message._raw_payload:
                    sms_data = message._raw_payload
                    logger.info(f"SMS data from _raw_payload: {len(sms_data)} bytes")
                
                if sms_data:
                    # logger.info(f"SMS binary data (hex): {sms_data.hex()}")
                    logger.info(f"SMS binary data: {sms_data}")
                    
                    # check if the SMS is a RP-ACK
                    if sms_data.hex().startswith('02'):
                        logger.info("SMS is a RP-ACK from the network, likely SMS-DELIVER REPORT for MT SMS, skipping sending RP-ACK back to the network")
                        try:
                            from ims_sms_rp_ack import build_rp_ack_payload
                            from gsm_rp_sms_apdu import decode_rp_sms_pdu
                            rp_msg = decode_rp_sms_pdu(sms_data.hex())
                            logger.info(f"RP-ACK: {rp_msg}")
                        except Exception as e:
                            logger.error(f"Failed to decode RP-ACK: {e}")
                        logger.info("Returning 200 OK")
                        await request.prepare(status_code=200)
                        return
                    
                    # if it's not a RP-ACK but the message, we need to decode the SMS, forward it and send RP-ACK back to the network
                    try:
                        sms_info = decode_vnd_sms(sms_data)
                        logger.info(f"Decoded SMS: {sms_info}")
                    except Exception as decode_error:
                        logger.error(f"SMS decode error: {decode_error}")
                        sms_info = {"from": "unknown", "to": "unknown", "text": "decode_error", "ref": 0}
                    
                    # Future processing:
                    # Forward to SMS hub

                    # For now: if autoroute command line is present, run send_sms.py script with the SMS data
                    # basically, route the sms from OA to DA
                    if True:
                        # extract --dest, --oa and --text from sms data
                        # use hardcoded --remote 10.40.0.21:6060 --local 10.40.0.19:5064 for now    
                        # todo: add config "autoroute" to enable this feature
                        dest = sms_info['to']
                        # strip "+" from dest
                        dest = dest.lstrip('+')
                        oa = sms_info['from']
                        # from, as returned by decode_vnd_sms(), likely is unknown (OA not present in the SMS data?)
                        # so we need to use the From header from the original SIP message
                        # the format is <sip:+12312317284312@ims.mnc00x.mcc2xx.3gppnetwork.org>
                        from_header = message.headers.get('From', '')
                        oa = from_header.split('@')[0].split('+')[1]
                        text = sms_info['text']
                        logger.info(f"Autoroute command line is present, running send_sms.py script with the SMS data: oa={oa}, dest={dest}, text={text}")
                        subprocess.run(['python', 'send_sms.py', '--oa', oa, '--dest', dest, '--text', sms_info['text'], '--remote', '10.40.0.21:6060', '--local', '10.40.0.19:5064'])

                    logger.info(f"Returning 202 Accepted")
                    # Send 202 Accepted response
                    await request.prepare(status_code=202)

                    # Build and send RP-ACK back to network
                    try:
                        from ims_sms_rp_ack import build_rp_ack_payload
                        from gsm_rp_sms_apdu import decode_rp_sms_pdu

                        # Re-parse to get RP/TP context (we already have sms_data & headers)
                        rp_msg = decode_rp_sms_pdu(sms_data.hex())
                        logger.info(f"rp_mr: {rp_msg.rp_mr}")
                        ack_payload = build_rp_ack_payload(rp_mr=rp_msg.rp_mr,
                                                          tpdu_submit=rp_msg.tpdu,
                                                          ok=True)
                        await self._send_sip_sms_ack(request, ack_payload)
                    except Exception as ack_error:
                        logger.error(f"Failed to send RP-ACK: {ack_error}")
                        logger.error(traceback.format_exc())

                else:
                    logger.error("No SMS data found in any message attribute")
                    await request.prepare(status_code=400)
            else:
                logger.warning(f"Unsupported MESSAGE Content-Type: {content_type}")
                await request.prepare(status_code=415)
                
        except Exception as e:
            logger.exception(f"Exception in MESSAGE handler: {e}")
            await request.prepare(status_code=400)

    async def _send_sip_sms_ack(self, sip_request, payload: bytes):
        """Craft and send a SIP MESSAGE (RP-ACK) back to the S-CSCF.
        Logging of headers & payload included for debugging.
        Uses the same `peer` that delivered the original MESSAGE.
        """
        import traceback, aiovoip
        from aiovoip.contact import Contact

        peer = sip_request.peer  # aiovoip.peer.Peer instance
        logger.info('--- send_sip_sms_ack to peer: ---')
        logger.info(peer)

        to_uri = sip_request.msg.headers.get('From', '').split(';')[0] # tag = sip_request.msg.headers.get('From', '').split(';')[1]
        to_details=Contact.from_header(to_uri)        
        logger.info('to_details')
        logger.info(to_details)

        # Determine local bind from the peer (fallback to zeros if missing)
        try:
            local_host, local_port = peer.local_addr  # Tuple[str, int]
        except Exception:
            local_host, local_port = '0.0.0.0', 0

        from_details=Contact.from_header(f'"IP-SM-GW" <sip:gw@{local_host}:{local_port}>')
        logger.info(f'"IP-SM-GW" <sip:gw@{local_host}:{local_port}>')

        last_cseq = int(sip_request.msg.headers['CSeq'].split()[0])
        cseq_num = last_cseq + 1

        logger.info('--- Constructing SIP RP-ACK ---')
        logger.info(f'<sip:gw@{local_host}:{local_port};transport=udp>')
        

        headers = {
            'CSeq': f"{cseq_num} MESSAGE",
            'Max-Forwards': '70',
            'Content-Type': 'application/vnd.3gpp.sms',
            'Accept-Contact': '*;+g.3gpp.smsip;require;explicit',
            'Content-Length': str(len(payload)),
        }

        from aiovoip.message import Request

        # class Request(Message): #def __init__(self, method, cseq,  from_details=None, to_details=None, contact_details=None, headers=None, payload=None, first_line=None
        try:

            binary_ack = payload                    # bytes
            ack_msg = Request('MESSAGE', cseq_num,from_details=from_details,to_details=to_details,
                         contact_details=Contact.from_header(f'<sip:gw@{local_host}:{local_port};transport=udp>'),headers=headers,payload='')


            # Inject the binary RP-ACK directly, otherwise APDU's get mangled
            ack_msg._raw_payload = binary_ack          # << bytes
            ack_msg._payload = ''                        # make .encode() skip

        except Exception as e:
            logger.error("aiovoip Request failed: %s", e)
            logger.error
            (traceback.format_exc())

        # Verbose logging - TODO: NEED TO LOG THE SHIT THAT ACTUALLY GOES OUT, not 'headers'
        logger.info('--- Sending SIP RP-ACK ---')
        for k, v in ack_msg.headers.items():
            logger.info(f"{k}: {v}")
        logger.info("Payload (%d bytes): %s", len(payload), payload.hex().upper())

        try:
            # NOTE: adding await here might require patching the aiovoip library
            # peers.py line 33 def send_message -> async def send_message
            # dialog.py line 267 (async def reply() add await before self.peer.send_message)
            await peer.send_message(ack_msg)
            logger.info('--- SIP RP-ACK sent ---')
        except Exception as e:
            logger.error("aiovoip send_request failed: %s", e)
            logger.error(traceback.format_exc())
        logger.info('--- SIP RP-ACK finished ---')

class SIPServer:
    def __init__(self, config, registry):
        self.config = config
        self.registry = registry
        self.app = None
        self.running = False
        
    async def start(self):
        """Start the SIP server using aiovoip"""


        try:
            logger.info("Starting SIP server with aiovoip...")
            logger.info(f"Configuration:")
            logger.info(f"  Local Bind: {self.config['sip']['bind']}")
            logger.info(f"  Local Port: {self.config['sip']['port']}")
            logger.info(f"  Home Domain: {self.config['sip']['home_domain']}")
            logger.info(f"  Autoroute: {self.config['autoroute']}")
            
            # Create aiovoip application with custom dialplan
            dialplan = SIPDialplan(self.registry)
            self.app = Application(dialplan=dialplan)
            
            # Start the application
            await self.app.run(
                protocol=aiovoip.UDP,  # Use UDP protocol
                local_addr=(self.config['sip']['bind'], self.config['sip']['port'])
            )
            
            self.running = True
            logger.info("SIP server started successfully!")
            logger.info(f"Listening on {self.config['sip']['bind']}:{self.config['sip']['port']}")
            logger.info("Waiting for incoming SIP messages...")
            
        except Exception as e:
            logger.exception(f"Failed to start SIP server: {e}")
            raise

    async def stop(self):
        """Stop the SIP server"""
        if self.app and self.running:
            await self.app.close()
            self.running = False
            logger.info("SIP server stopped")

async def start_sip_server(config, registry):
    """Start the SIP server using aiovoip"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s'
    )
    logger.info("Starting IP-SM-GW SIP server with aiovoip...")
    
    # Create and start SIP server
    sip_server = SIPServer(config, registry)
    await sip_server.start()
    
    try:
        # Keep the server running with periodic status updates
        counter = 0
        while sip_server.running:
            await asyncio.sleep(1)
            counter += 1
            if counter % 30 == 0:  # Log every 30 seconds
                logger.info("Server is running and waiting for SIP messages...")
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        await sip_server.stop() 