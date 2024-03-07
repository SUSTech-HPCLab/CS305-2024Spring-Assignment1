import socketserver
import socket

class MyLocalDNSServerHandler(socketserver.BaseRequestHandler):

    def __init__(self, request, client_address, server):
        """
        We list the root DNS server (a-g) here.
        You can use this list to query the root server.
        """
        self.root_dns_address = ['198.41.0.4', '199.9.14.201','192.33.4.12',
        '199.7.91.13','192.203.230.10', '192.5.5.241', '192.112.36.4']

        super().__init__(request, client_address, server)


    def change_rd_bit(self, data):
        """
        :param data: Input message from client dig
        Change the rd bit into 0, since the default query of dig is recursive
        """
        flag = bytes.fromhex('0000')
        return data[0:2] + flag + data[4:]


    def query_server(self,data, server_ip_list, server_port=53):
        """
        You may need this function to query the DNS server
        :data: the message to send to the server
        :server_ip_list: a list of ip addresses of the server
        :server_port: the port of the server default to 53
        """
       
        if len(server_ip_list) == 0:
            raise ValueError('There is no server ip address to query.')
        timeout_limit = 3
        while True :
            try:
                server_ip = server_ip_list[0]
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                server_socket.sendto(data,(server_ip,server_port))
                server_socket.settimeout(timeout_limit) # time out after 3 seconds
                response, _ = server_socket.recvfrom(10240)
                server_socket.settimeout(None)
                server_socket.close()
                return response
            except:
                print(f'Failed to connect to {server_ip_list[0]} with time out {timeout_limit}s. Try another server.')
                server_ip_list.pop(0)
                if len(server_ip_list) == 0:
                    raise ValueError('There is no avaliable server.')

    def handle(self):
        data = self.request[0].strip() # data from the client (dig in this case)
        socket = self.request[1] # connection with the client
        data = self.change_rd_bit(data) # change recursive query to iterative query

        response = None 
        # TODO: implement the logic to handle the DNS query




        socket.sendto(response, self.client_address)



class DNSHeader:

    def __init__(self, *args, **kwargs): # You can modify the input of __init__ function as you like

        # TODO: Finish all the following attributes. You can't change the type of attributes
        self.id : int = 0 
        self.flag : bytes = b''
        self.qdcount : int = 0 
        self.ancount : int = 0 
        self.nscount : int = 0 
        self.arcount : int = 0 

    @classmethod
    def from_wire(cls, data: bytes):
        # TODO: decode the bytes to create a DNSHeader object. This function is used for testing
        pass

    def __str__(self):
        # Don't change this function
        return f'ID: {self.id} Flag: {self.flag} QDCOUNT: {self.qdcount} ANCOUNT: {self.ancount} NSCOUNT: {self.nscount} ARCOUNT: {self.arcount}'

class DNSQuestion:

    def __init__(self, *args, **kwargs): # You can modify the input of __init__ function as you like

        # TODO: finish all the following attributes. You can't change the type of attributes
        self.qname : str = ""
        self.qtype : int = 0
        self.qclass : int = 0

    @classmethod
    def from_wire(cls, data: bytes): # Don't change the input of this function
        # TODO: decode the bytes to create a DNSQuestion object
        pass

    def __str__(self):
        # Don't change this function
        return f'QNAME: {self.qname} QTYPE: {self.qtype} QCLASS: {self.qclass}'

class DNSRR:

    def __init__(self, *args, **kwargs): # You can modify the input of __init__ function as you like

        # TODO: finish all the following attributes. You can't change the type of attributes
        self.name : str = ""
        self.type: int = 0
        self.class_ : int = 0
        self.ttl : int = 0
        self.rdlength: int = 0
        if self.type == 2:
            self.rdata : str = ""
        elif self.type == 1:
            # ipv4 address
            self.rdata : str = ""
        elif self.type == 28:
            # ipv6 address
            self.rdata : str = ""
        elif self.type == 5:
            # cname
            self.rdata : str = ""
        else:
            # other types, store as bytes
            self.rdata : bytes = b''

    def __str__(self):
        # Don't change this function
        return f'NAME: {self.name} TYPE: {self.type} CLASS: {self.class_} TTL: {self.ttl} RDLENGTH: {self.rdlength} RDATA: {self.rdata}'

class DNSMessage:

    def __init__(self, *args, **kwargs): # You can modify the input of __init__ function as you like
        self.header : DNSHeader = None
        self.question : DNSQuestion = None # We make sure there is only one question during the test
        self.answer : list[DNSRR] = [] # a list of DNSRR
        self.authority : list[DNSRR] = [] # a list of DNSRR
        self.additional : list[DNSRR] = [] # a list of DNSRR

    @classmethod
    def from_wire(cls, data: bytes): # Don't change the input of this function
        # TODO: decode the bytes to create a DNSQuestion object
        pass
        

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 9999
    with socketserver.UDPServer((HOST, PORT), MyLocalDNSServerHandler) as server:
        print('The local DNS server is running')
        server.serve_forever()