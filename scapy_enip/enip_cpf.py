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

from scapy_enip.enip_constants import cpf_item_ids


class CpfNullAddress(Packet):
    cpf_type_id = 0x00
    name = cpf_item_ids[cpf_type_id]
    fields_desc = []


class CpfConnectionAddress(Packet):
    cpf_type_id = 0xa1
    name = cpf_item_ids[cpf_type_id]
    fields_desc = [LEIntField("connection_id", 0)]


class CpfSequencedAddress(Packet):
    cpf_type_id = 0x8002
    name = cpf_item_ids[cpf_type_id]
    fields_desc = [
        LEIntField("connection_id", 0),
        LEIntField("sequence_number", 0),
    ]


class CpfUnconnectedData(Packet):
    cpf_type_id = 0xb2
    name = cpf_item_ids[cpf_type_id]
    fields_desc = []


class CpfConnectedData(Packet):
    cpf_type_id = 0xb1
    name = cpf_item_ids[cpf_type_id]
    fields_desc = []


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


bind_layers(CpfItem, CpfNullAddress, type_id=CpfNullAddress.cpf_type_id)
bind_layers(CpfItem, CpfConnectionAddress, type_id=CpfConnectionAddress.cpf_type_id)
bind_layers(CpfItem, CpfSequencedAddress, type_id=CpfSequencedAddress.cpf_type_id)
bind_layers(CpfItem, CpfUnconnectedData, type_id=CpfUnconnectedData.cpf_type_id)
bind_layers(CpfItem, CpfConnectedData, type_id=CpfConnectedData.cpf_type_id)
