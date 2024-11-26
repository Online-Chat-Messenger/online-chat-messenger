# プロジェクト名

online-chat-messenger


# 概要

クライアント間でメッセージを送り合うソフトウェアです。以下の利点を備えています。
- それぞれのクライアントはサーバを介して、メッセージを送ることができます。
- 以下2つの特徴により、クライアント間でチャットの安全性が高まります。
    - ルームに参加する場合、ホストは設定したパスワードが必要です。
    - クライアントが送るメッセージはRSA暗号によって暗号化されています。



# インストール方法

1. online-chat-messengerレポジトリをプルします。
1. python実行可能環境下で、以下コードを順番に実行します。
    1.    ```pip3 install cryptography```
    1. ```cd online-chat-messenger```
    1. ```python3 server.py```
    1. ```python3 client.py```


# 使い方

- サーバ起動後、クライアントは1,2,3のいずれかを選びます。
- 1を選択した場合、ルーム名、自身のユーザーネーム及びルームパスワードを決めた後、ホストとなってルーム作成することができます。
- 2を選択した場合、ルーム名、自身のユーザーネーム及び正しいルームパスワードを入力することでチャットに参加することができます。
- 3を選択し場合、プログラムを終了させることができます。
- チャット時には*LEAVE*と入力することで、ルームから他支出することができます。
- ホストが退出した場合、ルームそのものを閉じ、チャットを終わらせることができます。
- しばらくメッセージを送信していない場合、参加者はルームから退出させられます



# 技術スタック

- python
- Linux(Ubuntu)
- Mac


# 後々取り掛かること

ReactまたはElectron.jsを用いて、デスクトップアプリケーション化します。


# 作成者
- c.c
- hayashi
- ro50s
