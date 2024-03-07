from local_dns_server import DNSHeader
from local_dns_server import DNSQuestion
from local_dns_server import DNSRR
from local_dns_server import DNSMessage

def read_bytes_from_file(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return f.read()

def write_bytes_to_file(file_path: str, data: bytes):
    with open(file_path, 'wb') as f:
        f.write(data)

import unittest
class TestDNSResolver(unittest.TestCase):

    def setUp(self):
        self.dns_response_bytes = read_bytes_from_file('./raw_packet/dns_response.raw')
        self.header_bytes = read_bytes_from_file('./raw_packet/header.raw')
        self.question_bytes = read_bytes_from_file('./raw_packet/question.raw')
      

    def test_header(self):
        header = DNSHeader.from_wire(self.header_bytes)
        self.assertEqual(type(header), DNSHeader)
        self.assertEqual(header.id, 33119)
        self.assertEqual(header.flag, b'\x84\x80')
        self.assertEqual(header.qdcount, 1)
        self.assertEqual(header.ancount, 2)
        self.assertEqual(header.nscount, 2)
        self.assertEqual(header.arcount, 5)
        print("**header test passed**")

    def test_question(self):
        question = DNSQuestion.from_wire(self.question_bytes)
        self.assertEqual(type(question), DNSQuestion)
        self.assertEqual(question.qname, 'www.sustech.edu.cn')
        self.assertEqual(question.qtype, 1)
        self.assertEqual(question.qclass, 1)
        print("**question test passed**")

    def test_whole_msg(self):
        msg = DNSMessage.from_wire(self.dns_response_bytes)
        self.assertEqual(type(msg), DNSMessage)
        self.assertEqual(msg.header.id, 33119)
        self.assertEqual(msg.header.flag, b'\x84\x80')
        self.assertEqual(msg.header.qdcount, 1)
        self.assertEqual(msg.header.ancount, 2)
        self.assertEqual(msg.header.nscount, 2)
        self.assertEqual(msg.header.arcount, 5)
        self.assertEqual(msg.question.qname, 'www.sustech.edu.cn')
        self.assertEqual(len(msg.answer), 2)
        self.assertEqual(msg.answer[0].name, 'www.sustech.edu.cn')
        self.assertEqual(msg.answer[0].type, 5)
        self.assertEqual(msg.answer[0].class_, 1)
        self.assertEqual(msg.answer[0].ttl, 3600)
        self.assertEqual(msg.answer[0].rdlength, 2)
        self.assertEqual(msg.answer[0].rdata, 'sustech.edu.cn')
        self.assertEqual(msg.answer[1].name, 'sustech.edu.cn')
        self.assertEqual(msg.answer[1].type, 1)
        self.assertEqual(msg.answer[1].class_, 1)
        self.assertEqual(msg.answer[1].ttl, 3600)
        self.assertEqual(msg.answer[1].rdlength, 4)
        self.assertEqual(msg.answer[1].rdata, '172.18.1.3')
        self.assertEqual(len(msg.authority), 2)
        self.assertEqual(msg.authority[0].name, 'sustech.edu.cn')
        self.assertEqual(msg.authority[0].type, 2)
        self.assertEqual(msg.authority[0].rdata, 'ns2.sustech.edu.cn')
        self.assertEqual(msg.authority[1].name, 'sustech.edu.cn')
        self.assertEqual(msg.authority[1].rdata, 'ns1.sustech.edu.cn')
        self.assertEqual(len(msg.additional), 5)
        self.assertEqual(msg.additional[0].name, 'ns1.sustech.edu.cn')
        self.assertEqual(msg.additional[0].type, 1)
        self.assertEqual(msg.additional[0].rdata, '172.18.1.92')
        self.assertEqual(msg.additional[1].name, 'ns1.sustech.edu.cn')
        self.assertEqual(msg.additional[1].type, 28)
        self.assertEqual(msg.additional[1].rdata, '2001:da8:201d::42:92')
        self.assertEqual(msg.additional[4].name, 'root')
        self.assertEqual(msg.additional[4].type, 41)
        print("**whole msg test passed**")



if __name__ == '__main__':
    unittest.main()