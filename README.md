# Vibecoding Out-of-Distribution Software: Building an IP-SM-GW with Cursor and Live Network Testing

## TL;DR

I built a working ISC interface for an IP Short Message Gateway (IP-SM-GW) for IMS networks from scratch using AI assistance. The project involved research, abandoning broken Python libraries, implementing GSM/3GPP protocols from standards document and debugging with packet captures from a live mobile network.

Note: This project was developed using Cursor and models available in early August 2025 (mostly gpt-4.1, some o3 and some gpt-5).

## The problem

I needed a working implementation of an application server that connects to S-CSCF (vendor-provided) via ISC (a SIP-based protocol) and allows sending and receiving SMS to/from mobile terminals registered in an LTE network (SMS over LTE). The full implementation of IP-SM-GW would require an SS7 MAP connection to SMSC, HSS/HLR and possibly an interface to OCS; however, for my purposes—testing MO and MT SMS—an ISC-only application was sufficient. Obviously I didn't want to buy commercial IP-SM-GW from the usual suspects, so I decided to give vibecoding a chance.

The core idea: all existing and legacy mobile telecommunication protocols are well documented in 3GPP, ETSI, and GSMA documents; therefore, despite the fact that telecom software is rather niche (compared to, for example, 90% of mobile apps), the vibecoding approach has a much better chance of success than for truly specific tasks such as writing APIs for obscure Japanese tensor multiplier hardware acquired on eBay.

## Phase 1: The Perplexity Blueprint and obsolete libraries

SMS over LTE flows are described in 3GPP specification 23.341 (tl;dr [^1])

I started by asking Perplexity: "Write a specification for an IP-SM-GW proof-of-concept in Python". The result was surprisingly coherent—a 7-page document with architecture diagrams, protocol flows per 3GPP 23.341 / ETSI TS 124 341, and a recommended tech stack:

```
Recommended Libraries:
- aiosip (https://github.com/Eyepea/aiosip) (SIP stack)
- python-diameter (https://pypi.org/project/python-diameter/) (Diameter/HSS)
- smspdu (https://github.com/gecko-landmarks/smspdu) (SMS PDU parsing)
```

The spec looked legit. It referenced the right 3GPP standards, had plausible call flows, and even suggested reasonable module boundaries. I saved it as my implementation blueprint and got to work.

### The `aiosip` situation

First problem: `aiosip` was last updated in 2018 and didn't work with Python 3.8+; Perplexity had hallucinated library recommendations based on what *used to exist* rather than what was currently maintained.

After surveying the Python SIP landscape:
- `aiosip` - abandoned
- `pyVoIP` - different use case (consumer VoIP, not server)
- `python-sipsimple` - massive C dependencies, unclear async support

I found [`aiovoip`](https://github.com/py-craft/aiovoip)—a fork of aiosip maintained by py-craft. It had recent commits and claimed Python 3.12 support. Good enough. I instructed Cursor to create a basic SIP server to handle SIP REGISTER and MESSAGE, spun it up and connected to S-CSCF. Now I was ready to receive mobile-originated (MO) SMS messages from phones registered on the live network.

```
main.py
  ├─► config.yaml
  ├─► registry.py - SQLite subscriber database
  └─► sip_frontend.py - SIP server
      ├─► on_register() - Handle third-party REGISTER
      └─► on_message() - Handle MO-SMS
          └─► sms_codec.py - decode IMS SIP SMS `application/vnd.3gpp.sms` binary payload
```

### The `smspdu` disaster

IP-SM-GW and S-CSCF communicate via SIP, though SMS are not delivered as plaintext SIP MESSAGE, but rather using `application/vnd.3gpp.sms` encoding; the encoded messages are actually legacy GSM SMS PDUs transported as payload in SIP messages. So a working SMS decoding/encoding library was essential to parse SMS PDUs.

```
SIP MESSAGE
├─ Message Header
└─ Message Body: application/vnd.3gpp.sms (binary)
   └─ GSM A-I/F RP - RP-DATA (MS to Network)
      ├─ RP-MR: Message Reference
      ├─ RP-OA: Originating Address
      ├─ RP-DA: Destination Address
      └─ RP-UD: User Data
         └─ GSM SMS TPDU (GSM 03.40) SMS-SUBMIT
            ├─ TP-MR: Reference
            ├─ TP-DA: Destination Addresses
            ├─ TP-PID: Protocol ID
            ├─ TP-DCS: Data Coding Scheme
            ├─ TP-User-Data-Length
            └─ TP-UD: User Data (SMS text)
```

The spec suggested `smspdu` for parsing SMS PDUs. This library was from the Python 2.7 era and hadn't been updated in 14 years. I spent a few hours trying to get it working, but eventually decided to implement GSM 03.40 SMS TPDU parsing from <s>the first principles</s> scratch.

I had a strong aversion to implementing any PDU parsing by hand because of relics such as ASN.1 structures, 7-bit character packing into octets, BCD (Binary-Coded Decimal) encoding, obscure timestamp formats, and multiple message types with conditional fields. At the same time, it looked like a perfect task for vibecoding because:
* Wireshark's source code (`packet-gsm_sms.c`) exists
* 3GPP TS 23.040 is available online
* It was trivial to obtain real SMS PDUs from packet captures to test against

## Phase 2: Building an SMS PDU decoding library 

First step: asking Cursor to implement from scratch, in Python, the functionality to decode SMS PDUs similar to the `smspdu` library but without looking at `smspdu` code. I directed Cursor to consult 3GPP TS and `packet-gsm_sms.c` from the Wireshark codebase and test it by decoding SMS PDUs captured from the live network.

After Cursor generated the first version of SMS PDU parser library (`gsm_sms_apdu.py` for parsing TPDUs and `gsm_rp_sms_apdu.py` for parsing RP-DATA envelopes that wrap TPDUs in IMS SMS) based on Wireshark implementation and GSM 03.40 spec, I needed to verify it actually worked. I asked Cursor to generate a couple of test scripts for the decoder, intended to test decoding of various types of SMS PDUs:

* `gsm_sms_apdu_test.py` - for GSM SMS TPDU (SMS-SUBMIT/SMS-DELIVER) decoding
* `gsm_smsc_sms_apdu_test.py` - for SMSC header + GSM SMS TPDU (SMS-SUBMIT/SMS-DELIVER) decoding
* `gsm_rp_sms_apdu_test.py` - for RP-DATA + GSM SMS TPDU (IMS SMS PDUs transported over SIP) decoding

```
$ python gsm_sms_apdu_test.py 310D0B911326880736F40000A90FF7FBDD454E87CDE1B0DB357EB701
Testing PDU #1: 310D0B911326880736F40000A90FF7FBDD454E87CDE1B0DB357EB701
Length: 56 hex chars (28 bytes)
============================================================
PDU TYPE: SMS-SUBMIT
============================================================
Message Reference: 13
TO: +31628870634
TEXT: www.diafaan.com
Protocol ID: 0x00
Data Coding Scheme: 0x00
User Data Length: 15
Reject Duplicates: False
Validity Period Format: 2
RAW DATA: F7FBDD454E87CDE1B0DB357EB701
```

```
$ python gsm_rp_sms_apdu_test.py 003c00099153620000001011f11301080c9153621216001200000646e9733a4402
Decoded RP-SMS Message:
=====================
RP-MTI: 0x00 (RP-DATA MT)
RP-MR: 0x3C
RP-DA: +352600000001111
RP-OA: (empty)

Embedded TPDU:
--------------
PDU Type: SMS-SUBMIT
TP-DA: +352621610021
TP-UD: FROSCH
```

I used real SMS messages from a live mobile network as my test cases, as well as some examples from web tools ([^2]). I captured some messages, opened them with Wireshark, and saved the hex contents of GSM SMS. The testing routine involved decoding the same SMS with `gsm_sms_apdu_test.py`, comparing its results against Wireshark's reference decode, and telling Cursor what to fix, for example:

```
Me to Cursor:
"The RP-MTI shows as 0x00 (RP-DATA MT) but Wireshark shows 0x01 (RP-DATA MO).
The first byte of the PDU is 0x00, so why does Wireshark say 0x01?"

Cursor:
"The RP-MTI is encoded with direction bits. From the spec:
- 0x00 = RP-DATA (direction bit 0 = MS→NW when from MS perspective)
- Wireshark interprets this as 0x01 (MO) because it knows the context

Your parser is showing the raw byte value. For display purposes, you should map:
- 0x00 → 'RP-DATA MO' (when received at network side)
- 0x01 → 'RP-DATA MT' (when received at MS side)"

Fixed the logic. Please proceed with testing.
```

After some iterations, I managed to get `gsm_sms_apdu` working correctly.

## Phase 3: Constructing RP-ACK messages

With SMS decoding working, I moved to the next step. The IP-SM-GW needed to send RP-ACK messages back (just like it's done in legacy SS7 networks) to acknowledge received SMS; upon acknowledgment, the originating phone marks the SMS as sent; otherwise it gets stuck in sending mode followed by failure.

Per 3GPP TS 24.341, the IP-SM-GW must respond to each MO-SMS with concatenated [RP-ACK header][SMS-SUBMIT-REPORT TPDU]. I asked Cursor to implement `ims_sms_rp_ack.py` to build these payloads. The generated code looked correct, but I was unable to test RP-ACK generation locally; the only way was to send it to the network and observe the result on the phone, or capture the exchange with Wireshark and look for abnormalities.

Instead of running a test script and feeding the results to Cursor, debugging loop looked like this:

Step 1: Capture the exchange and open the capture in Wireshark

```
python main.py &
sudo tcpdump -i eth0 -w rp_ack_test.pcap port 5060
<send SMS from phone>
# Stop capture (Ctrl+C)
wireshark rp_ack_test.pcap
# Filter: sip.Method == "MESSAGE"
# Look at GSM SMS dissection in packet details pane
```

Step 2: Relay Wireshark's diagnosis to Cursor

```
Me to Cursor:
"Wireshark correctly identifies the message as GSM A-I/F RP - RP-ACK (MS to Network).
But it should be of type Network to MS and also the RP-Message reference is incorrect
(Wireshark reported 0xC1, and in my logging I've got ref: 12)"

Cursor's response:
"We're playing the 'SMSC / network' role. The S-CSCF sent us RP-DATA (MS→NW, 0x01)
on behalf of the UE. Per spec 24.011 §8.2.2.1, the matching ACK is 0x03 ('RP-ACK, Network→MS').

Also, the ACK must echo the Message-Reference byte-for-byte. Wireshark sees 0xC1;
your parser logged 12 → you're treating it as hex digits instead of a single byte."

Fixes applied:
[....]
```

Step 3: Fix and repeat

I had to go through 5 or so iterations, with Wireshark indicating "Unknown RP Message Type (0x30)", "Unknown RP message type (0x0c)", etc. Finally, I managed to craft the correct (according to Wireshark) acknowledgment; however, I stumbled upon another issue.

## Phase 4: The 481 "Transaction Does Not Exist" issue

As the RP-ACK messages I was sending to the mobile network were no longer malformed, the S-CSCF/network started to process them, and every RP-ACK got 481 "Transaction Does Not Exist" from the S-CSCF.

I asked Cursor to double-check the relevant standards (specifically, RFC 3261 Section 17.1) and fed it the actual SIP headers of the RP-ACK messages I was sending to the network. It turned out that SIP is picky about transaction matching. The response must have:

* Same Call-ID (I was accidentally mutating it)
* Incremented CSeq (I was restarting at 1)
* To: header without tag (I was copying the tag from the From: header)
* Correct Via branch (I was generating new branches)
* Binary payload (I was letting Python encode it as UTF-8, corrupting the binary data)

After a couple of iterations, it fixed the code, removing the tag from the `To:` header, etc., and I got 202 Accepted. The phone marked the SMS as successfully sent. Victory!

## Phase 5: MT-SMS - Sending messages to handsets

Receiving messages (MO-SMS, aka SMS-SUBMIT TPDU) was working. Now for the reverse direction: sending SMS TO phones (MT-SMS, aka SMS-DELIVER TPDU).

This required:
1. Building SMS-DELIVER TPDUs  
2. Wrapping in RP-DATA with correct direction indicators
3. Sending via SIP MESSAGE to S-CSCF which forwarded it to the network
4. Observing the handset for delivery

I asked Cursor to implement encoding functions in `gsm_rp_sms_apdu.py`:

```python
def encode_gsm_sms_deliver(tp_oa_number: str, text: str,
                           pid: int = 0x00, dcs: int = 0x00) -> str:
    """Build an SMS-DELIVER TPDU for MT-SMS"""
    # Encode originating address
    # Pack user data as 7-bit GSM
    # Generate timestamp (current UTC)
    # Return hex string
```

Then built test tools:
* `gsm_rp_sms_apdu_encode_test.py` - for building of RP, TPDU and concatenated RP+TPDU that can be tested for correct decoding via Wireshark and/or other tools [^2]
* `send_sms_test.py` - for sending SMS PDUs (created by by `gsm_rp_sms_apdu_encode_test.py`) via SIP interface to S-CSCF

This made it possible to proceed with the same Wireshark-Cursor debug loop. I'd build a PDU, send it to the network, capture the response, and use Wireshark to tell me what went wrong. Then I'd relay Wireshark's diagnosis to Cursor for fixes.

```
Me to Cursor:
> Hey I'm trying to use SMS PDU `000C9153625599391200005280400100000007D4F29C6EB3D900` but when it's being sent, in Wireshark dissector it's being recognized as SMS-DELIVER REPORT, not SMS-DELIVER

Cursor's diagnosis (based on Wireshark behavior):
> Wireshark decides whether a TPDU that has MTI = 00 is SMS-DELIVER (SC → MS) or SMS-DELIVER-REPORT (MS → SC) by looking at the flag bits in the first octet. If all flag bits are clear (0x00), Wireshark assumes it's the very short SMS-DELIVER-REPORT because in a genuine DELIVER message the SC normally sets bit 2 (TP-MMS: "More-Messages-to-Send").

The fix: Change first byte from `00` to `04`:

040C9153625599391200005280400100000007D4F29C6EB3D900
^^
04 = 0b00000100
     • MTI = 00 (SMS-DELIVER)
     • MMS = 1  (set this flag!)
     • all other flags 0
```

```
Me to Cursor:
> OK could you please evaluate the concatenated RP and SMS for correctness? Wireshark complains about some "extraneous data" maybe some data length bytes are set to incorrect values.
>
> RP: `009C07915362559939120014`
> SMS: `040C9153625599391200005280400100000007D4F29C6EB3D900`
> Concatenated: `009C07915362559939120014040C9153625599391200005280400100000007D4F29C6EB3D900`

Cursor (interpreting Wireshark's error):
> Problem spotted: In RP-DATA the "RP-User-Data Length" octet must equal the size of the embedded TPDU in bytes. Your header shows `14` (0x14 = 20), yet the TPDU you appended is 26 bytes long. Wireshark therefore decodes 20 bytes, finds more data, and flags the remainder as "extraneous".
>
> Fix: TPDU size = 26 bytes = 0x1A. Replace the length octet.

Changed `14` to `1A`:

009C0791536255993912001A040C9153625599391200005280400100000007D4F29C6EB3D900
                      ^^
```

## Phase 6: Monkey patches and production realities

### The `aiovoip` bug

Around this time, I started getting:

```python
RuntimeWarning: coroutine 'Peer.send_message' was never awaited
  self.peer.send_message(msg)
```

I checked the aiovoip source code. Line 267 of `dialog.py`:

```python
self.peer.send_message(msg)  # Missing 'await'!
```

The fix was trivial:

```python
await self.peer.send_message(msg)
```

But this is a library installed in system site-packages. Do I:
1. Fork aiovoip, fix it, submit PR, wait for review, wait for release, update requirements.txt?
2. Just edit `/root/miniforge3/envs/myenv/lib/python3.12/site-packages/aiovoip/dialog.py`?

I went with option 2. I documented it in `aiovoip_library_fixes.md` and moved on.

### The Via header bug

Another aiovoip issue: sometimes the Via header came as a list, sometimes as a string. This broke parsing:

```python
via = Via.from_header(via_header)  # Expects string
# TypeError: expected str, got list
```

Solution: monkey-patch at runtime in `sip_frontend.py`:

```python
import aiovoip.application
original_run_dialplan = aiovoip.application.Application._run_dialplan

async def patched_run_dialplan(self, protocol, msg):
    via_header = msg.headers['Via']

    # Fix: Handle case where Via header is a list
    if isinstance(via_header, list):
        via_header = via_header[0]

    # ... rest of original code
```

Is this ugly? Yes. Does it work? Also yes.

### Final Architecture

```
main.py 
  ├─► config.yaml
  ├─► registry.py - SQLite subscriber database
  └─► sip_frontend.py - SIP server + monkey patches
      ├─► on_register() - Handle third-party REGISTER
      └─► on_message() - Handle MO-SMS
          ├─► sms_codec.py - decode IMS SIP SMS `application/vnd.3gpp.sms` binary payload
          ├─► gsm_rp_sms_apdu.py - RP-DATA codec
          │   └─► gsm_sms_apdu.py - TPDU codec
          └─► ims_sms_rp_ack.py -  RP-ACK with SMS-SUBMIT-REPORT response builder

Tools:
  send_sms.py - MT-SMS CLI compose+send tool 
  send_sms_test.py - MT-SMS CLI send tool (for raw TPDUs)
  gsm_sms_apdu_test.py - TPDU decoder CLI
  gsm_rp_sms_apdu_test.py - RP+TPDU decoder CLI
  gsm_smsc_sms_apdu_test.py - SMSC headers + TPDU decoder CLI
  gsm_rp_sms_apdu_encode_test.py - Encoder CLI
```

## Observations

You need intuition to recognize when an iteration is going nowhere. Even with properly configured tests and prompts, sometimes the coding direction is fundamentally wrong—and only a human can recognize this. For example, I spent several hours trying to make the legacy `smspdu` library work with Python 3.8+. At some point, I realized it was a dead end: the library's architecture assumed Python 2.7 string handling, and patching it would require rewriting most of it anyway. The decision to abandon this route and implement from scratch had to be mine, as Cursor would have kept trying increasingly convoluted workarounds indefinitely.

With well-defined test cases ("decode string X and it must yield Y"), coding models sometimes try to fake passing results. I observed this pattern repeatedly: Cursor would try approach A, then approach B, and if both failed or raised exceptions, it would eventually just hardcode the expected output and call it a day. The generated code would essentially say: "if input == X: return Y" instead of actually implementing the decoding logic. This still happens, though it can probably be prevented with more explicit prompts or by requiring the code to handle multiple test cases simultaneously.

Context pollution is real and degrades output quality noticeably. When a chat accumulates too much irrelevant or obsolete information (old error essages, abandoned approaches, superseded code versions) the quality of Cursor's responses deteriorates. You can feel it: identical prompts that worked earlier start producing worse results. The solution: start fresh chats for each micro-task. For this project, I maintained separate Cursor sessions for "SMS decoder implementation", "RP-ACK debugging", and "MT-SMS encoding" rather than trying to handle everything in one long conversation.

## Conclusion

This project took approximately 12 hours of active development time, starting from a Cursor installation, with negligible cost ($20/month Cursor plan). The key takeaway: this isn't "no-code AI magic" but rather accelerated skill acquisition using AI as a force multiplier. Even fragmentary domain-specific knowledge and some familiarity with mobile network protocols facilitated this process; the ability to do live tests and integrate their results into the Cursor coding loop was the key enabler.

[^1]: https://www.sharetechnote.com/html/IMS_SIP_SMSoverIMS.html
[^2]: https://www.smsdeliverer.com/online-sms-pdu-decoder.aspx, https://www.diafaan.com/sms-tutorials/gsm-modem-tutorial/online-sms-deliver-pdu-decoder/

## Written by

l4rz 