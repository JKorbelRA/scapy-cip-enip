# -*- coding: utf-8 -*-
# Copyright (c) 2015 David I. Urbina, david.urbina@utdallas.edu
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
"""Ethernet/IP Common Packet Format Scapy dissector."""
import struct

from scapy.all import Packet, LEIntField, LEShortEnumField, LEShortField, bind_layers

from enip_constants import cpf_item_ids


class CpfConnectionAddress(Packet):
    name = "CpfConnectionAddress"
    fields_desc = [LEIntField("connection_id", 0)]


class CpfConnectedTransportPacket(Packet):
    name = "CpfConnectedTransportPacket"
    fields_desc = [LEShortField("sequence", 0)]


class CpfSequencedAddress(Packet):
    name = "CpfSequencedAddress"
    fields_desc = [
        LEIntField("connection_id", 0),
        LEIntField("sequence_number", 0),
    ]


class CpfItem(Packet):
    name = "CpfItem"
    fields_desc = [
        LEShortEnumField('type_id', 0, cpf_item_ids),
        LEShortField("length", None),
    ]

    def extract_padding(self, p):
        return p[:self.length], p[self.length:]

    def post_build(self, p, pay):
        if self.length is None and pay:
            p = p[:2] + struct.pack("<H", len(pay)) + p[4:]
        return p + pay


bind_layers(CpfItem, CpfConnectionAddress, type_id=0x00a1)
bind_layers(CpfItem, CpfConnectedTransportPacket, type_id=0x00b1)
bind_layers(CpfItem, CpfSequencedAddress, type_id=0x8002)
