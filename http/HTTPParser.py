class HTTPParser:
    def __init__(self, preprocessed, ready):
        self.headers = ''
        self.headers_done = False
        self.done = False
        self.body_len = -1
        self.n_body_read = 0
        self.preprocessed = preprocessed
        self.ready = ready

    def reset(self):
        self.headers = ''
        self.headers_done = False
        self.done = False
        self.body_len = -1
        self.n_body_read = 0

    def on_headers_end(self, txt, headers_end):
        self.headers += txt[:headers_end + 4]
        after_headers = txt[headers_end + 4:]
        print("after: " + after_headers, flush=True)
        self.headers_done = True
        self.parse_headers()
        self.ready.append(self.headers)
        self.preprocessed.appendleft(after_headers)
  
    # returns 1 when done with request. 
    def process(self): 
        data = self.preprocessed.popleft()
        if self.headers_done == False:
            if isinstance(data, str) == False:
               data = data.decode('utf-8', errors = 'ignore')
            headers_end = data.find('\r\n\r\n')
            if headers_end == -1:
                self.headers += data
            else:
                self.on_headers_end(data, headers_end)
            return 0
        if self.headers_done == True:
            self.n_body_read += len(data)
            if self.n_body_read > self.body_len:
                overflow = self.n_body_read - self.body_len 
                self.preprocessed.appendleft(data[-overflow:])
                data = data[:-overflow]

            if self.should_drop_body == False:
                self.ready.append(data)
            if self.n_body_read >= self.body_len:
                return 1
            else:
                return 0

    def remove_key(self, key):
        key_start = self.headers.find(key + ": ")
        key_end = self.headers.find('\r', key_start)
        before_key = self.headers[:key_start]
        after_key = self.headers[key_end + 2:]
        self.headers =  before_key + after_key    

    def drop_body(self):
        self.remove_key("Content-Length")
        self.headers = self.headers.replace("200 OK", "403 Forbidden", 1)

    def drop_body2(self):
        len_start = self.headers.find('Content-Length: ')
        len_end = self.headers.find('\r', len_start)
        before_len = self.headers[:len_start]
        after_len = self.headers[len_end + 2:]
        self.headers =  before_len + after_len
        self.headers = self.headers.replace("200 OK", "403 Forbidden", 1)

    def parse_headers(self):
        len_start = self.headers.find('Content-Length: ')
        if len_start == -1:
            self.body_len = 0
            self.should_drop_body = False
            return
        len_end = self.headers.find("\r", len_start)
        self.body_len = int(self.headers[len_start + 16: len_end])
        type_start = self.headers.find('Content-Type: ')
        type_end = self.headers.find('\r', type_start)
        cont_type = self.headers[type_start + 14: type_end]
        if(cont_type == "application/zip" or cont_type == "text/csv"):
            self.should_drop_body = True
            self.drop_body()
        else:
            self.should_drop_body = False

