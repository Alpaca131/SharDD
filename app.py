from flask import Flask, session, request
import dataset
import settings

app = Flask(__name__)
db: dataset.Database = dataset.connect(url=settings.DATABASE_URL)
token_table: dataset.Table = db['token_data']


@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route('/api/register', methods=['GET'])
def register():
    token = request.args.get('token')
    if token is None:
        return 'Invalid arguments.', 400
    db_row = token_table.find_one(token=token)
    if db_row is None:
        return 'Invalid token.', 401


if __name__ == '__main__':
    app.run()
