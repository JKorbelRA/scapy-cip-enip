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

from scapy.all import bind_layers, Ether, IP, TCP, Raw

from enip import Enip
from enip_commands import EnipSendUnitData
from enip_cpf import CpfItem, CpfConnectedTransportPacket, CpfConnectionAddress


bind_layers(TCP, Enip, dport=44818)
bind_layers(TCP, Enip, sport=44818)


def run_tests():
    # Test building/dissecting packets
    # Build a raw packet over ENIP
    pkt = Ether(src='01:23:45:67:89:ab', dst='ba:98:76:54:32:10')
    pkt /= IP(src='192.168.1.1', dst='192.168.1.42')
    pkt /= TCP(sport=10000, dport=44818)
    pkt /= Enip()
    pkt /= EnipSendUnitData(items=[
        CpfItem() / CpfConnectionAddress(connection_id=1337),
        CpfItem() / CpfConnectedTransportPacket(sequence=4242) / Raw(load='test'),
    ])

    # Build!
    data = bytes(pkt)
    pkt = Ether(data)
    pkt.show()

    # Test the value of some fields
    assert pkt[Enip].command_id == 0x70
    assert pkt[Enip].session == 0
    assert pkt[Enip].status == 0
    assert pkt[Enip].length == 26
    assert pkt[EnipSendUnitData].count == 2
    assert pkt[EnipSendUnitData].items[0].type_id == 0x00a1
    assert pkt[EnipSendUnitData].items[0].length == 4
    assert pkt[EnipSendUnitData].items[0].payload == pkt[CpfConnectionAddress]
    assert pkt[CpfConnectionAddress].connection_id == 1337
    assert pkt[EnipSendUnitData].items[1].type_id == 0x00b1
    assert pkt[EnipSendUnitData].items[1].length == 6
    assert pkt[EnipSendUnitData].items[1].payload == pkt[CpfConnectedTransportPacket]
    assert pkt[CpfConnectedTransportPacket].sequence == 4242
    assert pkt[CpfConnectedTransportPacket].payload.load == b'test'


if __name__ == '__main__':
    run_tests()
