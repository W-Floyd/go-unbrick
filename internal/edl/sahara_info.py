# Sahara chip identity, without uploading a programmer. Run by go-unbrick with
# the managed venv's interpreter; prints one JSON line prefixed with MARKER.
#
# edlclient's own entry point cannot do this: with no --loader it autodetects
# one from its bundled database and uploads it. A non-empty programmer name
# skips that search inside cmd_info, and exiting before upload_loader leaves the
# PBL in Sahara, so the next edl invocation can still hand it a loader.
import json
import logging
import sys
import time

from edlclient.Config.usb_ids import default_ids
from edlclient.Library.Connection.usblib import usb_class
from edlclient.Library.sahara import sahara
from edlclient.Library.sahara_defs import cmd_t, sahara_mode_t

MARKER = "GO-UNBRICK-SAHARA: "


def emit(out):
    print(MARKER + json.dumps(out), flush=True)


def main():
    wait = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    cdc = usb_class(portconfig=default_ids, loglevel=logging.ERROR)
    cdc.timeout = 1500
    deadline = time.time() + wait
    while not cdc.connect():
        if time.time() > deadline:
            emit({"mode": "absent"})
            return
        time.sleep(1)
    try:
        sh = sahara(cdc, loglevel=logging.ERROR)
        # Listen only. sahara.connect() pokes a silent device with a Firehose
        # nop and then a NAND-programmer packet, which wedges a running
        # programmer until a power cycle. Silence here means no hello is on
        # offer (usually a programmer is running) and is left for edlclient's
        # own session to handle.
        try:
            v = cdc.read(length=0xC * 0x4, timeout=1)
        except Exception:  # pylint: disable=broad-except
            v = b""
        out = {"mode": "quiet", "vid": cdc.vid, "pid": cdc.pid}
        if v and b"<?xml" in v:
            out["mode"] = "firehose"
        if not v or v[0] != 0x01 or sh.ch.pkt_cmd_hdr(v).cmd != cmd_t.SAHARA_HELLO_REQ:
            emit(out)
            return
        hello = sh.ch.pkt_hello_req(v)
        sh.pktsize, sh.version = hello.cmd_packet_length, hello.version
        out["mode"] = "sahara"
        out["sahara_version"] = hello.version
        if hello.mode == sahara_mode_t.SAHARA_MODE_MEMORY_DEBUG:
            out["memory_debug"] = True
            emit(out)
            return
        sh.programmer = "go-unbrick:no-upload"
        if not sh.cmd_info(version=hello.version):
            out["error"] = "sahara command mode refused"
            emit(out)
            return
        out.update({
            "serial": sh.serials or "",
            "hwid": sh.hwidstr or "",
            "pkhash": sh.pkhash or "",
        })
        emit(out)
    finally:
        cdc.close()


if __name__ == "__main__":
    main()
