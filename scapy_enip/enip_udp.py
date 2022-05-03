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

from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet, PacketListField

import scapy_cip_enip_common.utils as utils
from scapy_enip.enip import Enip
from scapy_enip.enip_commands import EnipSendUnitData
from scapy_enip.enip_cpf import CpfItem, CpfConnectedTransportPacket, CpfConnectionAddress, CpfSequencedAddress

# ConnectedTransportPacket payload for ENIP UDP_KEEP_ALIVE
ENIP_UDP_KEEPALIVE = (
    b'\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00'
    b'\xff\xff\xff\xff\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00'
)


class EnipUDP(Packet):
    """Ethernet/IP packet over UDP"""
    name = "EnipUDP"
    fields_desc = [
        utils.LEShortLenField("count", None, count_of="items"),
        PacketListField("items", [], CpfItem,
                        count_from=lambda p: p.count),
    ]

    def extract_padding(self, p):
        return b"", p


bind_layers(UDP, Enip, dport=44818)
bind_layers(UDP, Enip, sport=44818)
bind_layers(UDP, EnipUDP, sport=2222, dport=2222)


def keep_alive_test(verbose: bool):
    # Test building/dissecting packets
    # Build a keep-alive packet
    pkt = Ether(src='00:1d:9c:c8:13:37', dst='01:00:5e:40:12:34')
    pkt /= IP(src='192.168.1.42', dst='239.192.18.52')
    pkt /= UDP(sport=2222, dport=2222)
    pkt /= EnipUDP(items=[
        CpfItem() / CpfSequencedAddress(connection_id=1337, sequence_number=42),
        CpfItem(type_id=0x00b1) / Raw(load=ENIP_UDP_KEEPALIVE),
    ])

    # Build!
    data = bytes(pkt)
    pkt = Ether(data)
    if verbose:
        pkt.show()

    # Test the value of some fields
    assert pkt[EnipUDP].count == 2
    assert pkt[EnipUDP].items[0].type_id == 0x8002
    assert pkt[EnipUDP].items[0].length == 8
    assert pkt[EnipUDP].items[0].payload == pkt[CpfSequencedAddress]
    assert pkt[CpfSequencedAddress].connection_id == 1337
    assert pkt[CpfSequencedAddress].sequence_number == 42
    assert pkt[EnipUDP].items[1].type_id == 0x00b1
    assert pkt[EnipUDP].items[1].length == 36
    assert pkt[EnipUDP].items[1].payload.load == ENIP_UDP_KEEPALIVE


def run_tests(verbose: bool = True):
    keep_alive_test(verbose)

    # Test building/dissecting packets
    # Build a raw packet over ENIP
    pkt = Ether(src='01:23:45:67:89:ab', dst='ba:98:76:54:32:10')
    pkt /= IP(src='192.168.1.1', dst='192.168.1.42')
    pkt /= UDP(sport=10000, dport=44818)
    pkt /= Enip()
    pkt /= EnipSendUnitData(items=[
        CpfItem() / CpfConnectionAddress(connection_id=1337),
        CpfItem() / CpfConnectedTransportPacket(sequence=4242) / Raw(load='test'),
    ])

    # Build!
    data = bytes(pkt)
    pkt = Ether(data)
    if verbose:
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
