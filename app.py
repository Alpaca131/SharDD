import secrets

import dataset
import requests
from flask import Flask, session, request, render_template, redirect, url_for, Response

import json
import settings

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SESSION_SECRET
CLIENT_ID = settings.CLIENT_ID
CLIENT_SECRET = settings.CLIENT_SECRET
db: dataset.Database = dataset.connect(url=settings.DATABASE_URL)
token_table: dataset.Table = db['token_data']
register_info_table: dataset.Table = db['register_info']
bot_info_table: dataset.Table = db['bot_info']
DISCORD_BASE_URL = 'https://discordapp.com/api/'
heartbeat_token_dict = {}


@app.route('/')
def index():
    print(request.method)
    return render_template('index.html')


@app.route('/api/heart-beat', methods=['GET'])
def heartbeat():
    token = request.args.get('token')
    if token is None:
        return 'Invalid arguments.', 400
    db_row = token_table.find_one(token=token)
    if db_row is None:
        return 'Invalid token.', 401


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if session.get('logged_in') is not True:
            return redirect(url_for('login', return_url=request.url))
        return render_template('register.html', token='None')
    else:
        bot_id = request.form.get('bot_id')
        shard_count = request.form.get('shard_count')
        if bot_info_table.find_one(bot_id=bot_id) is not None:
            return """
            <h1>既に登録済みです。</h1>
            """
        if register_info_table.find_one(bot_id=bot_id) is not None:
            register_info_table.delete(bot_id=bot_id)
        while True:
            gen_token = secrets.token_hex(8)
            if token_table.find_one(token=gen_token) is None:
                token = gen_token
                break
        register_info_table.insert(dict(bot_id=bot_id, token=token, shard_count=shard_count), ['bot_id'])
        return render_template('register.html', token=token, bot_id=bot_id)


@app.route('/check-register', methods=['POST'])
def check_register():
    bot_id = request.args.get('bot_id')
    r = requests.get(f'https://discord.com/api/v8/applications/public?application_ids={bot_id}',
                     headers={'Authorization': settings.DISCORD_TOKEN})
    description = r.json()[0]['description']
    register_data = register_info_table.find_one(bot_id=bot_id)
    register_token = register_data['token']
    if register_token in description:
        shard_count = register_data['shard_count']
        shard_number = 0
        token_dict = {}
        while len(token_dict) != shard_count:
            gen_token = secrets.token_hex(16)
            if token_table.find_one(token=gen_token) is None:
                if gen_token not in token_dict.keys():
                    token_dict[shard_number] = gen_token
                    shard_number = shard_number + 1
        for shard_id in token_dict:
            token = token_dict[shard_id]
            token_table.insert(dict(token=token, bot_id=bot_id, shard_id=shard_id))
        bot_info_table.insert(dict(bot_id=bot_id, shard_count=len(token_dict), token=json.dumps(token_dict)))
        return Response(json.dumps(token_dict), status=200, mimetype='application/json')
    return redirect(request.referrer), 401


@app.route('/login')
def login():
    code = request.args.get('code')
    if code is None:
        session['return_url'] = request.args.get('return_url')
        return redirect('https://discord.com/api/oauth2/authorize?client_id=760150837926035506&'
                        'redirect_uri=https%3A%2F%2Fbotdd.alpaca131.tk%2Flogin&response_type=code&scope=identify')
    return_url = session.get('return_url')
    if return_url is None:
        return_url = url_for('index')
    res_token = exchange_code(code=code, redirect_url=f'https://botdd.alpaca131.tk/login')
    token = res_token['access_token']
    refresh_token = res_token['refresh_token']
    res_info = requests.get(DISCORD_BASE_URL + 'users/@me', headers={'Authorization': f'Bearer {token}'})
    res_dict = json.loads(res_info.content.decode())
    session['logged_in'] = True
    session['user_id'] = int(res_dict['id'])
    session['user_name'] = res_dict['username']
    session['discord_refresh_token'] = refresh_token
    session.pop('return_url', None)
    return redirect(return_url)


@app.route('/logout')
def logout():
    session['logged_in'] = False
    session.pop('discord_id', None)
    return redirect(url_for('index'))


def exchange_code(code, redirect_url):
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_url,
        'scope': 'identify'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    r = requests.post('https://discordapp.com/api/oauth2/token', data=data, headers=headers)
    print(data)
    r.raise_for_status()
    return r.json()


if __name__ == '__main__':
    app.run(threaded=True)
