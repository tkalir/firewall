import select, socket, sys, queue
import selectors

class queue_worker:
    def __init__(self, client, deque):
        self.sock = client
        self.deque = deque

    def fileno(self):
        return self.sock.fileno()

    def send_from_queue(self): #returns false if closed
        socket = self.sock
        deque = self.deque
        while deque:	
            data = deque.popleft()
            if isinstance(data, str):
                data = data.encode()
            sent = socket.send(data)
            if sent == -1:
                return False
            if sent < len(data):
                data = data[sent:]
                deque.appendleft(data)
                return True
        return True

###################################################

class Client_reader(queue_worker):
    def __init__(self, sock, deque):      
        super().__init__(sock, deque)

###################################################

class Server_writer(queue_worker):
    def __init__(self, sock, deque):      
        super().__init__(sock, deque)

###################################################
class Client_writer(queue_worker):
    def __init__(self, sock, deque):      
        super().__init__(sock, deque)

###################################################

class Server_reader(queue_worker):
    def __init__(self, sock, to_client):      
        super().__init__(sock, to_client)

###################################################

class Dispatcher:
    def __init__(self, sock, reader, writer):
        self.sock = sock
        self.reader = reader
        self.writer = writer

    def fileno(self):
        return self.sock.fileno()
###################################################
class Connection:
    def __init__(self, client, server):
        self.client = client
        self.server = server
        self.client_closed = False
        self.server_closed = False

    def close_server(self):
        if self.server_closed == False:
            sel.unregister(self.server)
            self.server.close()
            self.server_closed = True

    def close_client(self):
        if self.client_closed == False:
            sel.unregister(self.client)
            self.client.close()
            self.client_closed = True
        self.close_server()
###################################################

def write_to_client(writer, mask):
    if writer.send_from_queue() == False:
        writer.connection.close_client()

def disptach_server(dispatcher, mask):
        if mask & selectors.EVENT_READ == selectors.EVENT_READ:
            read_from_server(dispatcher.reader, mask)
        else:
            write_to_server(dispatcher.writer, mask)
            
def disptach_client(dispatcher, mask):
    if mask & selectors.EVENT_READ == selectors.EVENT_READ:
        read_from_client(dispatcher.reader, mask)
    else: 
        write_to_client(dispatcher.writer, mask)

def read_from_client(reader, mask):
    while True:
        try:
            data = reader.sock.recv(1024)
            if data:
                reader.deque.append(data)
                print(data, flush=True)
            else: #client closed
                reader.connection.close_client()
                return
        except Exception as e: #we will get an exception when socket empties
            #traceback.print_exc()
            #if reader.sock.fileno() > 0:
            #   reader.sock.close()
            return

def create_sock(port, backlog):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.listen(backlog)
    return sock

def write_to_server(writer, mask):
    if writer.send_from_queue() == False:
        writer.connection.close_server()

def read_from_server(reader, mask):
    while True:
        try:
            data = reader.sock.recv(1024)
            if data:
                reader.preprocessed.append(data)
                while reader.preprocessed:
                    if reader.parser.process() == 1:
                        reader.parser.reset()
            else:
                reader.connection.close_server()
                return
        except:
            return 

class Proxy:
    def __init__(self, proxy_dev, socket, acceptor):
        self.proxy_dev = proxy_dev
        self.sock = socket
        self.sel = selectors.DefaultSelector()
        self.sel.register(self, selectors.EVENT_READ, acceptor)

    def fileno(self):
        return self.sock.fileno()

    def run_forever(self):
        while True:
            events = self.sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask) 
