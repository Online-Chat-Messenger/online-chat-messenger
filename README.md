# Online-Chat-Messenger

# 概要

サーバを介してクライアント間でリアルタイムでメッセージを送受信できるCLIで動くアプリケーションです。

#機能

チャットルームの作成または参加: 新しいチャットルームを作成するか、既存のチャットルームに参加できます。
メッセージの暗号化: メッセージはRSAアルゴリズムを用いて暗号化されます

# インストール方法

1. レポジトリをクローンします。
1. 以下コードを順番に実行します。
    1.```pip install cryptography```
    1. ```cd online-chat-messenger```
    1. ```python server.py```
    1. ```python client.py```

# 使い方

- サーバを先に起動します、
- その後クライアントを実行し、CREATE(1),JOIN(2),EXIT(3)のいずれかを選びます。
- 1を選択した場合、ルーム名、自身のユーザーネーム及びルームパスワードを決めた後、ホストとなってルーム作成することができます。
- 2を選択した場合、ルーム名、自身のユーザーネーム及び正しいルームパスワードを入力することでチャットルームに参加することができます。
- 3を選択し場合、プログラムを終了させることができます。
- チャット時には*LEAVE*と入力することで、ルームから退出することができます。
- ホストが退出した場合、ルームも閉じられます。
- 一定時間メッセージを送信していない場合、参加者はルームから退出させられます

# 技術スタック
- 言語： python

#注意
-サーバアドレス、ポート番号、タイムアウトする時間はハードコードされています。状況によって変更してください

# のちに取り掛かるかもしれないこと
-Electron.jsを用いて、デスクトップアプリケーション化するかもしれません
