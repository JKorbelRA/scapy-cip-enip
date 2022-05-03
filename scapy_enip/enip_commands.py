# Copyright (c) 2022, Vojtěch Chvojka, Rockwell Automation, inc.
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

from struct import pack

from scapy.all import Packet, LEIntField, LEShortField, PacketListField, bind_layers

from scapy_enip.enip import Enip
from scapy_enip.enip_cpf import CpfItem
import scapy_cip_enip_common.utils as utils


class EnipSendUnitData(Packet):
    """Data in ENIP header specific to the specified command"""
    name = "EnipSendUnitData"
    fields_desc = [
        LEIntField("interface_handle", 0),
        LEShortField("timeout", 0),
        utils.LEShortLenField("count", None, count_of="items"),
        PacketListField("items", [], CpfItem, count_from=lambda p: p.count),
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


bind_layers(Enip, EnipRegisterSession, command_id=0x0065)
bind_layers(Enip, EnipSendRRData, command_id=0x006f)
bind_layers(Enip, EnipSendUnitData, command_id=0x0070)
