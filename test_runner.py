import scapy_cip.cip
import scapy_cip_enip_common.test_utils
import scapy_enip.enip
import scapy_enip.enip_tcp
import scapy_enip.enip_udp


if __name__ == "__main__":
    scapy_cip_enip_common.test_utils.run_tests()

    scapy_enip.enip.run_tests(False)
    scapy_enip.enip_tcp.run_tests(False)
    scapy_enip.enip_udp.run_tests(False)
    scapy_cip.cip.run_tests(True)
