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


commands = {
    0x00: "Nop",
    0x04: "ListServices",
    0x63: "ListIdentity",
    0x64: "ListInterfaces",
    0x65: "RegisterSession",
    0x66: "UnRegisterSession",
    0x6F: "SendRRData",
    0x70: "SendUnitData",
    0xC8: "StartDtls"
}

statuses = {
    0x00: "Success",
    0x01: "InvalidCommand",
    0x02: "InsufficientMemory",
    0x03: "IncorrectData",
    0x64: "InvalidSessionHandle",
    0x65: "InvalidLength",
    0x69: "UnsupportedProtocolVersion",
    0x6A: "CipServiceNotAllowed"
}

cpf_item_ids = {
    0: "NullAddress",
    0xC: "CipIdentity",
    0x86: "CipSecurityInfo",
    0x87: "EnipCapability",
    0xa1: "ConnectionBasedAddress",
    0xb1: "ConnectedTransportPacket",
    0xb2: "UnconnectedMessage",
    0x100: "ListServicesResponse",
    0x8000: "SockaddrInfoOrigToTgt",  # Originator to target.
    0x8001: "SockaddrInfoTgtToOrig",  # Target to originator.
    0x8002: 'SequencedAddressItem',
    0x8003: "UnconnectedMessageUdp"
}
