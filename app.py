from flask import Flask, session, request, render_template
import dataset
import settings
import secrets

app = Flask(__name__)
db: dataset.Database = dataset.connect(url=settings.DATABASE_URL)
token_table: dataset.Table = db['token_data']


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/heart-beat', methods=['GET'])
def heartbeat():
    token = request.args.get('token')
    if token is None:
        return 'Invalid arguments.', 400
    db_row = token_table.find_one(token=token)
    if db_row is None:
        return 'Invalid token.', 401


@app.route('/register')
def register():
    while True:
        gen_token = secrets.token_hex(8)
        if token_table.find_one(token=gen_token) is None:
            token = gen_token
            break
    return render_template('register.html', token=token)


if __name__ == '__main__':
    app.run(threaded=True)
