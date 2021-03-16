from flask import Flask, render_template
from main import *
from prettytable import PrettyTable

from scan import scan_request

app = Flask(__name__)


@app.route('/requests')
def get_requests():
    requests = rep.select_requests()
    pretty_req = prettify_requests(requests)
    return render_template("requests.html", tbl=pretty_req.get_html_string(attributes={"class": "foo"}))


@app.route('/request/<int:id>')
def get_request(id):
    req = rep.select_request_by_id(id)
    pretty_req = prettify_requests([req])
    return render_template("requests.html", tbl=pretty_req.get_html_string(attributes={"class": "foo"}))


@app.route('/scan/<int:id>')
def scan_request_route(id):
    req = rep.select_request_by_id(id)

    try:
        result = scan_request(req[2], req[1], req[3])
    except Exception as e:
        return str(e.__str__())

    if result:
        return "Запрос уязвим"
    else:
        return "Уязвимостей не обнаружено"


def prettify_requests(requests):
    table = PrettyTable()
    table.field_names = ["id", "host", "request", "tls"]
    for req in requests:
        table.add_row([req[0], req[1], req[2], req[3]])
    return table


@app.route("/repeat/<int:id>")
def repeat_request(id):
    request_from_db = rep.select_request_by_id(id)
    if request_from_db[3] == 1:
        reply = get_reply_from_host(request_from_db[2], request_from_db[1], 443, 1)
    else:
        reply = get_reply_from_host(request_from_db[2], request_from_db[1], 80, 0)
    return str(reply.decode())


if __name__ == '__main__':
    app.run()
