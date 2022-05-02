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
"""Ethernet/IP over TCP scapy dissector"""
import struct

from scapy.all import Packet, LEIntField, LEShortField, LEShortEnumField, PacketListField, \
    LEIntEnumField, LELongField, bind_layers, Ether, IP, TCP, Raw

import scapy_cip_enip_common.utils as utils


class EnipConnectionAddress(Packet):
    name = "EnipConnectionAddress"
    fields_desc = [LEIntField("connection_id", 0)]


class EnipConnectionPacket(Packet):
    name = "EnipConnectionPacket"
    fields_desc = [LEShortField("sequence", 0)]


class EnipSendUnitData_Item(Packet):
    name = "EnipSendUnitData_Item"
    fields_desc = [
        LEShortEnumField("type_id", 0, {
            0x0000: "null_address",  # NULL Address
            0x00a1: "conn_address",  # Address for connection based requests
            0x00b1: "conn_packet",  # Connected Transport packet
            0x00b2: "unconn_message",
            # Unconnected Messages (eg. used within CIP command SendRRData)
            0x0100: "listservices_response",  # ListServices response
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


class EnipSendUnitData(Packet):
    """Data in ENIP header specific to the specified command"""
    name = "EnipSendUnitData"
    fields_desc = [
        LEIntField("interface_handle", 0),
        LEShortField("timeout", 0),
        utils.LEShortLenField("count", None, count_of="items"),
        PacketListField("items", [], EnipSendUnitData_Item,
                        count_from=lambda p: p.count),
    ]


class EnipSendRRData(Packet):
    name = "EnipSendRRData"
    fields_desc = EnipSendUnitData.fields_desc


class EnipRegisterSession(Packet):
    name = "EnipRegisterSession"
    fields_desc = [
        LEShortField("protocol_version", 1),
        LEShortField("options", 0),
    ]


class EnipTCP(Packet):
    """Ethernet/IP packet over TCP"""
    name = "EnipTCP"
    fields_desc = [
        LEShortEnumField("command_id", None, {
            0x0004: "ListServices",
            0x0063: "ListIdentity",
            0x0064: "ListInterfaces",
            0x0065: "RegisterSession",
            0x0066: "UnregisterSession",
            0x006f: "SendRRData",  # Send Request/Reply data
            0x0070: "SendUnitData",
        }),
        LEShortField("length", None),
        LEIntField("session", 0),
        LEIntEnumField("status", 0, {0: "success"}),
        LELongField("sender_context", 0),
        LEIntField("options", 0),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            l = len(pay)
            p = p[:2] + struct.pack("<H", l) + p[4:]
        return p + pay


bind_layers(TCP, EnipTCP, dport=44818)
bind_layers(TCP, EnipTCP, sport=44818)

bind_layers(EnipTCP, EnipRegisterSession, command_id=0x0065)
bind_layers(EnipTCP, EnipSendRRData, command_id=0x006f)
bind_layers(EnipTCP, EnipSendUnitData, command_id=0x0070)
bind_layers(EnipSendUnitData_Item, EnipConnectionAddress, type_id=0x00a1)
bind_layers(EnipSendUnitData_Item, EnipConnectionPacket, type_id=0x00b1)

if __name__ == '__main__':
    # Test building/dissecting packets
    # Build a raw packet over ENIP
    pkt = Ether(src='01:23:45:67:89:ab', dst='ba:98:76:54:32:10')
    pkt /= IP(src='192.168.1.1', dst='192.168.1.42')
    pkt /= TCP(sport=10000, dport=44818)
    pkt /= EnipTCP()
    pkt /= EnipSendUnitData(items=[
        EnipSendUnitData_Item() / EnipConnectionAddress(connection_id=1337),
        EnipSendUnitData_Item() / EnipConnectionPacket(sequence=4242) / Raw(load='test'),
    ])

    # Build!
    data = str(pkt)
    pkt = Ether(data)
    pkt.show()

    # Test the value of some fields
    assert pkt[EnipTCP].command_id == 0x70
    assert pkt[EnipTCP].session == 0
    assert pkt[EnipTCP].status == 0
    assert pkt[EnipTCP].length == 26
    assert pkt[EnipSendUnitData].count == 2
    assert pkt[EnipSendUnitData].items[0].type_id == 0x00a1
    assert pkt[EnipSendUnitData].items[0].length == 4
    assert pkt[EnipSendUnitData].items[0].payload == pkt[EnipConnectionAddress]
    assert pkt[EnipConnectionAddress].connection_id == 1337
    assert pkt[EnipSendUnitData].items[1].type_id == 0x00b1
    assert pkt[EnipSendUnitData].items[1].length == 6
    assert pkt[EnipSendUnitData].items[1].payload == pkt[EnipConnectionPacket]
    assert pkt[EnipConnectionPacket].sequence == 4242
    assert pkt[EnipConnectionPacket].payload.load == 'test'
