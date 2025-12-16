from flask import Flask
from flask_socketio import SocketIO, join_room, leave_room, send
from models import db, Message, ChatSession
from routes import init_routes
from bot import analyze_sentiment, generate_bot_response

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
socketio = SocketIO(app)

init_routes(app)


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
        bot_response = generate_bot_response(text, sentiment)
        bot_msg = Message(session_id=session_id, sender_id=0, text=bot_response, sentiment=0)
        db.session.add(bot_msg)
        db.session.commit()
        send({'msg': bot_response, 'sender': 'Bot', 'sentiment': 0}, to=room)

        if sentiment < -0.5:
            send({'msg': 'Escalating to an agent...', 'sender': 'System', 'sentiment': 0}, to=room)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        pass
    # socketio.run(app, debug=True)
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
