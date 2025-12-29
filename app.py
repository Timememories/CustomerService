from flask import Flask
from flask_socketio import SocketIO, join_room, leave_room, send
from flask_migrate import Migrate  # 新增：导入迁移工具
from models import db, Message, ChatSession, User
from routes import init_routes
from bot import analyze_sentiment, generate_bot_response

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
migrate = Migrate(app, db)  # 新增：初始化迁移工具，绑定app和db实例
socketio = SocketIO(app)

init_routes(app)


# 以下SocketIO事件和原有逻辑保持不变
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    send(f"{data['username']} has entered the chat.", to=room)


@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    send(f"{data['username']} has left the chat.", to=room)


@socketio.on('message')
def handle_message(data):
    room = data['room']
    text = data['text']
    sender_id = data['sender_id']
    session_id = int(room)
    sentiment = analyze_sentiment(text)
    msg = Message(session_id=session_id, sender_id=sender_id, text=text, sentiment=sentiment)
    db.session.add(msg)
    db.session.commit()
    send({'msg': text, 'sender': data['username'], 'sentiment': sentiment}, to=room)

    chat_session = ChatSession.query.get(session_id)
    if not chat_session.agent_id:
        user = User.query.filter_by(id=sender_id).first()
        if not(user.role == "admin" or user.role == "agent"):
            bot_response = generate_bot_response(text, sentiment)
            bot_msg = Message(session_id=session_id, sender_id=0, text=bot_response, sentiment=0)
            db.session.add(bot_msg)
            db.session.commit()
            send({'msg': bot_response, 'sender': 'Bot', 'sentiment': 0}, to=room)

            if sentiment < -0.5:
                send({'msg': 'Escalating to an agent...', 'sender': 'System', 'sentiment': 0}, to=room)


if __name__ == '__main__':
    # 注释掉原有的 db.create_all()，改用迁移工具管理表结构
    # with app.app_context():
    #     db.create_all()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, port=5001)