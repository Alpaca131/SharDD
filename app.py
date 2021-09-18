import random
import secrets
import string

import dataset
import requests
from flask import Flask, session, request, render_template, redirect, url_for, Response

import datetime
import json
import settings

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SESSION_SECRET
CLIENT_ID = settings.CLIENT_ID
CLIENT_SECRET = settings.CLIENT_SECRET
ACCESS_TOKEN = settings.ACCESS_TOKEN
db: dataset.Database = dataset.connect(url=settings.DATABASE_URL)
token_table: dataset.Table = db['token_data']
one_time_token_table: dataset.Table = db['one_time_token']
bot_info_table: dataset.Table = db['bot_info']
DISCORD_BASE_URL = 'https://discordapp.com/api/'
token_on_memory = {}
for row in token_table.find():
    row_dict = dict(row)
    row_dict.pop('token', None)
    token_on_memory[row['token']] = row_dict


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        if session.get('logged_in') is not True:
            return redirect(url_for('login', return_url=request.url))
        return render_template('register.html', token='None')
    else:
        bot_id = request.form.get('bot_id')
        shard_count = request.form.get('shard_count')
        webhook_url = request.form.get('webhook_url')
        user_ids_args = request.form.get('user_ids')
        role_ids_args = request.form.get('role_ids')
        if user_ids_args is not None:
            user_ids = []
            for i in user_ids_args.split():
                user_ids.append(int(i))
        else:
            user_ids = None
        if role_ids_args is not None:
            role_ids = []
            for i in role_ids_args.split():
                role_ids.append(int(i))
        else:
            role_ids = None
        if bot_info_table.find_one(bot_id=bot_id) is not None:
            return """
            <h1>既に登録済みです。</h1>
            """
        if one_time_token_table.find_one(bot_id=bot_id) is not None:
            one_time_token_table.delete(bot_id=bot_id)
        gen_token = secrets.token_hex(8)
        one_time_token_table.insert(
            dict(bot_id=bot_id, token=gen_token, shard_count=shard_count,
                 webhook_url=webhook_url, role_ids=role_ids, user_ids=user_ids),
            ['bot_id'])
        return render_template('register.html', token=gen_token, bot_id=bot_id)


@app.route('/check-register', methods=['POST'])
def check_register():
    bot_id = request.args.get('bot_id')
    r = requests.get(f'https://discord.com/api/v8/applications/public?application_ids={bot_id}',
                     headers={'Authorization': settings.DISCORD_TOKEN})
    description = r.json()[0]['description']
    register_data = one_time_token_table.find_one(bot_id=bot_id)
    register_token = register_data['token']
    if register_token in description:
        shard_count = register_data['shard_count']
        webhook_url = register_data['webhook_url']
        role_id_list = register_data['role_ids']
        user_id_list = register_data['user_ids']
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
            token_on_memory[token] = dict(bot_id=bot_id, shard_id=shard_id)
        bot_info_table.insert(
            dict(bot_id=bot_id, shard_count=shard_count, token=token_dict,
                 role_mentions=role_id_list, user_mentions=user_id_list,
                 webhook_url=webhook_url))
        one_time_token_table.delete(bot_id=bot_id)
        return Response(json.dumps(token_dict), status=200, mimetype='application/json',
                        headers={'Content-Disposition': 'attachment; filename=BotDD_TOKEN.json'})
    return redirect(request.referrer), 401


@app.route('/login')
def login():
    code = request.args.get('code')
    if code is None:
        session['return_url'] = request.args.get('return_url')
        state = random_strings(n=16)
        session['state'] = state
        return redirect('https://discord.com/api/oauth2/authorize?client_id=760150837926035506&redirect_uri=https%3A'
                        f'%2F%2Fbotdd.alpaca131.com%2Flogin&response_type=code&scope=identify&state={state}')
    return_url = session.get('return_url')
    if return_url is None:
        return_url = url_for('index')
    if request.args.get("state") != session["state"]:
        return "Authorization Error.", 401
    res_token = exchange_code(code=code, redirect_url=f'https://botdd.alpaca131.com/login')
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


@app.route('/api/heartbeat', methods=['POST'])
def post_heartbeat():
    token = request.headers.get('token')
    if token not in token_on_memory:
        return {'Error': 'Please register your bot first. https://botdd.alpaca131.com/'}, 401
    now = datetime.datetime.now()
    token_data = token_on_memory[token]
    token_data["last_access"] = now
    token_on_memory[token] = token_data
    token_table.update(dict(token=token, last_access=now), ['token'])
    return 'success', 200


@app.route('/api/check-heartbeat')
def check_heartbeat():
    access_token = request.args.get('token')
    if access_token != ACCESS_TOKEN:
        return 'Authentication failed.', 401
    alert_token_row = []
    for token in token_on_memory:
        token_data = token_on_memory[token]
        last_access = token_data['last_access']
        if last_access is None:
            continue
        now = datetime.datetime.now()
        td: datetime.timedelta = last_access - now
        if td.total_seconds() > 90:
            alert_token_row.append(token_data)
    for i in alert_token_row:
        bot_id = i['bot_id']
        shard_id = i['shard_id']
        bot_info = bot_info_table.find_one(bot_id=bot_id)
        webhook_url = bot_info['webhook_url']
        if bot_info['user_mentions'] == 'null':
            user_mention_list = []
        else:
            user_mention_list = json.loads(bot_info['user_mentions'])
        if bot_info['role_mentions'] == 'null':
            role_mention_list = []
        else:
            role_mention_list = json.loads(bot_info['role_mentions'])
        content = ""
        for user_id in user_mention_list:
            content = f'{content}<@{user_id}> '
        for role_id in role_mention_list:
            content = f'{content}<@&{role_id}> '
        requests.post(webhook_url,
                      json={
                          "content": content,
                          "embeds": [{
                              "title": "アラート",
                              "description": "Botがダウンしました。",
                              "fields": [
                                  {
                                      "name": "BOT",
                                      "value": f"<@{bot_id}>",
                                      "inline": False
                                  },
                                  {
                                      "name": "シャード",
                                      "value": f"ID: {shard_id}",
                                      "inline": False
                                  }
                              ],
                              "color": "16711680"
                          }]
                      })
    return 'succeed', 200


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


def random_strings(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


if __name__ == '__main__':
    app.run(threaded=True)
