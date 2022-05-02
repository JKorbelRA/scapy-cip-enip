#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Nicolas Iooss, SUTD
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Ethernet/IP over UDP scapy dissector

This dissector only supports a "keep-alive" kind of packet which has been seen
in SUTD's secure water treatment testbed.
"""
import struct

from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet, LEIntField, LEShortField, \
    LEShortEnumField, PacketListField

import scapy_cip_enip_common.utils as utils

# Keep-alive sequences
ENIP_UDP_KEEPALIVE = (
        b'\x01\x00\xff\xff\xff\xff' +
        b'\xff\xff\xff\xff\x00\x00\x00\x00' +
        b'\xff\xff\xff\xff\x00\x00\x00\x00' +
        b'\xff\xff\xff\xff\x00\x00\x00\x00' +
        b'\xff\xff\xff\xff\x00\x00\x00\x00')


class EnipUdpSequencedAddress(Packet):
    name = "EnipUdpSequencedAddress"
    fields_desc = [
        LEIntField("connection_id", 0),
        LEIntField("sequence", 0),
    ]


class EnipUdpItem(Packet):
    name = "EnipUdpItem"
    fields_desc = [
        LEShortEnumField("type_id", 0, {
            0x00b1: "Connected_Data_Item",
            0x8002: "Sequenced_Address",
        }),
        LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay


class EnipUDP(Packet):
    """Ethernet/IP packet over UDP"""
    name = "EnipUDP"
    fields_desc = [
        utils.LEShortLenField("count", None, count_of="items"),
        PacketListField("items", [], EnipUdpItem,
                        count_from=lambda p: p.count),
    ]

    def extract_padding(self, p):
        return "", p


bind_layers(UDP, EnipUDP, sport=2222, dport=2222)
bind_layers(EnipUdpItem, EnipUdpSequencedAddress, type_id=0x8002)

if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a keep-alive packet
    pkt = Ether(src='00:1d:9c:c8:13:37', dst='01:00:5e:40:12:34')
    pkt /= IP(src='192.168.1.42', dst='239.192.18.52')
    pkt /= UDP(sport=2222, dport=2222)
    pkt /= EnipUDP(items=[
        EnipUdpItem() / EnipUdpSequencedAddress(connection_id=1337, sequence=42),
        EnipUdpItem(type_id=0x00b1) / Raw(load=ENIP_UDP_KEEPALIVE),
    ])

    # Build!
    data = bytes(pkt)
    pkt = Ether(data)
    pkt.show()

    # Test the value of some fields
    assert pkt[EnipUDP].count == 2
    assert pkt[EnipUDP].items[0].type_id == 0x8002
    assert pkt[EnipUDP].items[0].length == 8
    assert pkt[EnipUDP].items[0].payload == pkt[EnipUdpSequencedAddress]
    assert pkt[EnipUdpSequencedAddress].connection_id == 1337
    assert pkt[EnipUdpSequencedAddress].sequence == 42
    assert pkt[EnipUDP].items[1].type_id == 0x00b1
    assert pkt[EnipUDP].items[1].length == 38
    assert pkt[EnipUDP].items[1].payload.load == ENIP_UDP_KEEPALIVE
