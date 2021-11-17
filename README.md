# botDD・SharDDとは？
Botがダウンした際、ユーザー・開発者が気付けるようにするサービスです。

## BotDD・SharDDの違いは？
BotDDは他のBotが落ちていないか確認できるBotで、一般ユーザーがどのBotに対しても利用可能です。  
一方SharDDは開発者向けに提供しているサービスで、ステータスを監視しているBotDDに比べて高精度での監視が可能です。

## SharDDの利用方法
### シャードごとのトークンの発行
1. <https://botdd.alpaca131.com/register>にアクセスし、Discordアカウントへのアクセスを許可します。
2. フォームにBotのID、シャードの数、通知するDiscordのwebhookのURL、メンションするユーザー・ロールのIDを入力します。
3. 一時TOKENが発行され表示されるので、それを<https://discord.com/developers/applications>で自分のBotの説明欄に追記し保存します。
4. BotDDに戻り、「認証」ボタンをクリックして各シャードのトークンが入ったJSONをダウンロードします。
5. もう不要なのでBotの説明欄に追記した一時トークンを削除します。

### Botからheartbeatの送信
- 前回のheartbeatから60秒以上アクセスがない場合、Botがダウンしたとみなします。
- 60秒以内であればアクセス間隔は任意ですが、ネットワークのラグを考慮し60秒ちょうどにすることは推奨しません。
- チェック間隔は60秒なので、最長でも障害発生から120秒以内には通知されます。
- アクセス間隔があまりにも短く、当方が攻撃だと判断した場合は予告なくサービスの利用禁止措置を取ることがありますので、くれぐれも常識的な範囲内でのアクセスをお願いします。

#### heartbeatの送信方法
headerに`{"Authorization": "Bearer TOKEN"}`を指定し、<https://botdd.alpaca131.com/api/heartbeat>にPOSTして下さい。  
シャードごとのマシン名の表示を行いたい場合はPOSTリクエストのjsonに`{"machine_name": "マシン名"}`のように指定してください。
#### サンプルコード(py)
```python
import requests

requests.post("https://botdd.alpaca131.com/api/heartbeat",
              headers={"Authorization": "Bearer TOKEN"},
              json={"machine_name": "レンタルサーバー１"})
```