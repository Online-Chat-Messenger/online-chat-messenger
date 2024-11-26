# Online-Chat-Messenger

# 概要
サーバを介してクライアント間でリアルタイムでメッセージを送受信できるCLIで動くアプリケーションです。
TCPを用いてルーム作成・参加を行い、UDPを用いてメッセージのやり取りをします

# 機能

- チャットルームの作成と管理：新しいチャットルームを作成するか、既存のルームに参加できます。
- リアルタイムでの送受信：ユーザーはリアルタイムでメッセージを送受信することができます
- ユーザー認証：チャットルームへのアクセスにはパスワードが必要です。
- メッセージの暗号化: メッセージはRSAアルゴリズムを用いて暗号化されます
- タイムアウト処理: 一定時間アクティブでないユーザーは、自動的にチャットルームから退出されます。
- ルーム解散機能: ホストが退出したらそのルームの参加者全員が、自動的にチャットルームから退出されます。

# インストール方法
リポジトリをクローンします：

```bash
git clone https://github.com/Online-Chat-Messenger/online-chat-messenger.git
cd online-chat-messenger
```
必要なライブラリをインストールします：

```bash
pip install cryptography
```

# 使い方

- サーバを先に起動します、
```bash
python server.py
```
- その後クライアントを実行し、CREATE(1),JOIN(2),EXIT(3)のいずれかを選びます。
```bash
python client.py
```

- 1を選択した場合、ルーム名、自身のユーザーネーム及びルームパスワードを決めた後、ホストとなってルーム作成することができます。
- 2を選択した場合、ルーム名、自身のユーザーネーム及び正しいルームパスワードを入力することでチャットルームに参加することができます。
- 3を選択し場合、プログラムを終了させることができます。
- チャット時には*LEAVE*と入力することで、ルームから退出することができます。
- ホストが退出した場合、ルームも閉じられます。
- 一定時間メッセージを送信していない場合、参加者はルームから退出させられます

# 技術スタック
- 言語： python
- ソケットプログラミング
- マルチスレッド
- RSA暗号化

# 開発期間 
- 2週間
  
# 注意
- サーバーのアドレス、ポート番号はハードコードされています。状況によって変更してください

# のちに取り掛かるかもしれないこと
- Electron.jsを用いて、デスクトップアプリケーション化するかもしれません
