#!/usr/bin/env python
"""Deliberately injectable HTTP fixture. Run only on the isolated audit lab network."""
import html
from flask import Flask, request
from db import connect, engine

app = Flask(__name__)

@app.get('/<account>/get_int')
def query(account):
    accounts = {'admin': {'mysql': 'root', 'mariadb': 'root', 'postgres': 'postgres', 'mssql': 'sa', 'oracle': 'audit_owner'},
                'app': dict.fromkeys(('mysql', 'mariadb', 'postgres', 'mssql', 'oracle'), 'audit_app'),
                'limited': dict.fromkeys(('mysql', 'mariadb', 'postgres', 'mssql', 'oracle'), 'audit_limited')}
    if account not in accounts:
        return 'unknown account', 404
    conn = None
    try:
        conn = connect(accounts[account][engine], pooled=True)
        cursor = conn.cursor()
        cursor.execute('SELECT id,name,surname FROM users WHERE id=%s' % request.args.get('id', '1'))
        rows = cursor.fetchall()
        body = '<html><body><table>'
        for row in rows:
            body += '<tr>' + ''.join('<td>%s</td>' % html.escape('' if value is None else str(value)) for value in row) + '</tr>'
        return body + '</table></body></html>'
    except Exception as ex:
        # Render the driver's message, not Python's repr of its argument tuple.
        message = next((value for value in ex.args if isinstance(value, str)), str(ex))
        return '<html><body>%s</body></html>' % html.escape(message)
    finally:
        if conn is not None:
            conn.close()


app.run(host='0.0.0.0', port=8080, threaded=True)
