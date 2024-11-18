import datetime
import json
import random
import secrets
import string
import time

import dataset
import requests
import sentry_sdk
from flask import Flask, session, request, render_template, redirect, url_for, Response, abort
from flask_cors import cross_origin, CORS
from sentry_sdk.integrations.flask import FlaskIntegration

import settings

sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    integrations=[FlaskIntegration()],

    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=1.0
)

app = Flask(__name__)
app.config['SECRET_KEY'] = settings.SESSION_SECRET
CLIENT_ID = settings.CLIENT_ID
CLIENT_SECRET = settings.CLIENT_SECRET
ACCESS_TOKEN = settings.ACCESS_TOKEN
db: dataset.Database = dataset.connect(url="sqlite:///shardd.sqlite")
token_table: dataset.Table = db['token']
one_time_token_table: dataset.Table = db['one_time_token']
bot_info_table: dataset.Table = db['bot_info']
DISCORD_BASE_URL = 'https://discordapp.com/api/'
CORS(app, resources={r"/api/*": {"origins": "*"}})


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
                 webhook_url=webhook_url, role_ids=json.dumps(role_ids), user_ids=json.dumps(user_ids)),
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
        role_id_list = json.loads(register_data['role_ids'])
        user_id_list = json.loads(register_data['user_ids'])
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
        bot_info_table.insert(
            dict(bot_id=bot_id, shard_count=shard_count, tokens=json.dumps(token_dict),
                 role_mentions=json.dumps(role_id_list), user_mentions=json.dumps(user_id_list),
                 webhook_url=webhook_url, user_id=session['user_id']))
        one_time_token_table.delete(bot_id=bot_id)
        return Response(json.dumps(token_dict), status=200, mimetype='application/json',
                        headers={'Content-Disposition': 'attachment; filename=BotDD_TOKEN.json'})
    return redirect(request.referrer), 401


@app.route('/status/<int:bot_id>')
def status_page(bot_id):
    bot_info_row = bot_info_table.find_one(bot_id=bot_id)
    if bot_info_row is None:
        return abort(404)
    bot_name = get_bot_name(bot_id)
    if "user_id" in session:
        session_user_id = session["user_id"]
    else:
        session_user_id = None
    if bot_info_row["user_id"] == session_user_id:
        show_machine_name = True
    else:
        show_machine_name = False
        if bot_info_row["role_id"] is not None and session_user_id is not None:
            if len(set(json.loads(bot_info_row["role_mentions"])) & set(get_user_roles(bot_info_row["guild_id"]))) > 0:
                show_machine_name = True
    shard_list = []
    offline_count = 0
    for shard_id in range(0, bot_info_row["shard_count"]):
        if shard_id in json.loads(bot_info_row["offline_shards"]):
            offline_count += 1
            token = json.loads(bot_info_row["tokens"])[str(shard_id)]
            token_data = token_table.find_one(token=token)
            last_access = datetime.datetime.fromtimestamp(token_data["last_access"],
                                                          datetime.timezone(datetime.timedelta(hours=9)))
            shard_data = {"id": shard_id, "status": "offline",
                          "last_access": last_access.strftime('%m/%d %H:%M')}
        else:
            token_data = None
            shard_data = {"id": shard_id, "status": "online"}

        if token_data is None:
            token = json.loads(bot_info_row["tokens"])[str(shard_id)]
            token_data = token_table.find_one(token=token)
        machine_name = token_data["machine_name"]
        if machine_name == "unknown":
            machine_name = "未設定"
        shard_data["machine_name"] = machine_name
        shard_list.append(shard_data)
    if offline_count == 0:
        bot_status = "online"
    elif offline_count == bot_info_row["shard_count"]:
        bot_status = "all offline"
    else:
        bot_status = "some offline"
    return render_template("status_page.html",
                           bot_name=bot_name, shard_list=shard_list, bot_status=bot_status,
                           show_machine_name=show_machine_name)


def get_user_roles(guild_id: int):
    api_res = requests.get(DISCORD_BASE_URL + f'users/@me/guilds/{guild_id}/member',
                           headers={'Authorization': f'Bearer {session["access_token"]}'})
    return api_res.json()['roles']


@app.route('/login')
def login():
    code = request.args.get('code')
    if code is None:
        session['return_url'] = request.args.get('return_url')
        state = random_strings(n=16)
        session['state'] = state
        return redirect(f'https://discord.com/api/oauth2/authorize?client_id=760150837926035506&redirect_uri=https%3A'
                        f'%2F%2Fbotdd.alpaca131.com%2Flogin&response_type=code&scope=guilds%20identify%20guilds'
                        f'.members.read&state={state}')
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
    session['access_token'] = token
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
    token = request.headers.get('Authorization')[7:]
    token_data = token_table.find_one(token=token)
    request_json = request.get_json()
    if request_json is not None:
        machine_name = request_json.get('machine_name')
    else:
        machine_name = None

    if token_data is None:
        return {'Error': 'Please register your bot first. https://botdd.alpaca131.com/'}, 401
    now = time.time()
    token_data["last_access"] = now
    if machine_name is None:
        machine_name = "unknown"
    token_table.update(dict(token=token, last_access=now, alerted=False, machine_name=machine_name), ['token'])
    # offline_shardsカラムからそのシャードを除外
    bot_id = token_data["bot_id"]
    bot_data = bot_info_table.find_one(bot_id=bot_id)
    offline_shards = json.loads(bot_data["offline_shards"])
    if token_data["shard_id"] in offline_shards:
        offline_shards.remove(token_data["shard_id"])
        bot_info_table.update(dict(bot_id=bot_id, offline_shards=json.dumps(offline_shards)), ["bot_id"])
    return 'succeed', 200


@app.route('/api/check-heartbeat')
def check_heartbeat():
    access_token = request.args.get('token')
    if access_token != ACCESS_TOKEN:
        return 'Authentication failed.', 401
    alert_token_row = []
    for row in token_table.find():
        last_access = row['last_access']
        if last_access is None:
            continue
        now = time.time()
        if now - last_access > 60:
            alert_token_row.append(row)
    for i in alert_token_row:
        if i["alerted"] is True:
            continue
        bot_id = i['bot_id']
        shard_id = i['shard_id']
        bot_info = bot_info_table.find_one(bot_id=bot_id)
        # offline_shardsカラムにそのシャードを追加
        offline_shards = json.loads(bot_info["offline_shards"]) if bot_info["offline_shards"] else []
        offline_shards.append(i["shard_id"])
        bot_info_table.update(dict(bot_id=bot_id, offline_shards=json.dumps(offline_shards)), ["bot_id"])
        purge_cf_cache([f"https://botdd.alpaca131.com/status/{bot_id}", f"https://botdd.alpaca131.com/api/status/{bot_id}"])
        # Webhook送信処理
        webhook_url = bot_info['webhook_url']
        if bot_info['user_mentions'] is None:
            user_mention_list = []
        else:
            user_mention_list = json.loads(bot_info['user_mentions'])
        if bot_info['role_mentions'] is None:
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
                              "description": "Botがダウンしました。\n"
                                             f"[ダッシュボード](https://botdd.alpaca131.com/status/{bot_id})",
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
        token_table.update(dict(token=i["token"], alerted=True), ["token"])
    return 'succeed', 200


@app.route('/api/status/<int:bot_id>')
def status_api(bot_id: int):
    status_row = bot_info_table.find_one(bot_id=bot_id)
    if status_row is None:
        return "Not found.", 404
    res = {"shard_count": status_row["shard_count"],
           "offline_shards": json.loads(status_row["offline_shards"])}
    return res


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


def get_bot_name(bot_id: int):
    res = requests.get(f"{DISCORD_BASE_URL}users/{bot_id}",
                       headers={'Authorization': f"Bot {settings.BOT_TOKEN}"})
    return res.json()["username"]


def purge_cf_cache(purge_urls: list):
    url = "https://api.cloudflare.com/client/v4/zones/1ffe7e2646237cebde2a711a68c55ba4/purge_cache"

    payload = {
        "files": purge_urls
    }
    headers = {
        "Content-Type": "application/json",
        "X-Auth-Email": settings.CF_EMAIL,
        "X-Auth-Key": settings.CF_TOKEN
    }

    response = requests.request("POST", url, json=payload, headers=headers)
    print(response.text)
    response.raise_for_status()


if __name__ == '__main__':
    app.run(threaded=True, host="127.0.0.2", port=5000)
