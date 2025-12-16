from flask import render_template, request, redirect, url_for, session, flash, jsonify
from models import db, User, Service, Appointment, ChatSession, Message
from datetime import datetime


def init_routes(app):
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            # 1. 获取表单数据并做基础校验
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'user').strip()  # 默认普通用户

            # 2. 基础参数校验
            if not username:
                flash('用户名不能为空！', 'error')
                return redirect(url_for('register'))
            if not password:
                flash('密码不能为空！', 'error')
                return redirect(url_for('register'))
            # 校验角色合法性（仅允许 admin/agent/user）
            if role not in ['admin', 'agent', 'user']:
                flash('无效的角色类型！', 'error')
                return redirect(url_for('register'))

            # 3. 检查用户名是否已存在
            if User.query.filter_by(username=username).first():
                flash('用户名已存在，请更换！', 'error')
                return redirect(url_for('register'))

            try:
                # 4. 创建用户（自动触发密码加密，依赖User模型的set_password方法）
                user = User(
                    username=username,
                    password=password,  # 模型内部会自动加密，无需手动处理
                    role=role
                )
                # 5. 提交数据库
                db.session.add(user)
                db.session.commit()
                flash('注册成功！请登录', 'success')
                return redirect(url_for('login'))

            except ValueError as e:
                # 捕获密码强度验证失败的异常（User模型的_validate_password_strength）
                db.session.rollback()  # 回滚事务
                flash(f'注册失败：{str(e)}', 'error')
                return redirect(url_for('register'))

            except Exception as e:
                # 捕获其他数据库异常
                db.session.rollback()
                flash(f'系统错误：{str(e)}', 'error')
                return redirect(url_for('register'))

        # GET请求：渲染注册页面
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # 若用户已登录，直接跳转到仪表盘
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            # 1. 获取并清理表单数据
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            # 2. 基础校验
            if not username or not password:
                flash('Username and password cannot be empty!')
                return redirect(url_for('login'))

            try:
                # 3. 查询用户（仅按用户名查询）
                user = User.query.filter_by(username=username).first()

                # 4. 验证用户和密码（核心修复：密码需用加密校验，而非明文比对）
                if user and user.check_password(password):
                    # 密码验证成功，初始化session
                    session['user_id'] = user.id
                    session['role'] = user.role
                    session['username'] = user.username
                    session.permanent = True  # 设置session持久化（可选，默认浏览器关闭失效）
                    flash(f'Welcome back, {user.username}!')
                    return redirect(url_for('dashboard'))
                else:
                    # 用户名不存在或密码错误
                    flash('Invalid username or password!')

            except Exception as e:
                # 捕获数据库或其他系统异常
                flash(f'System error: {str(e)}')

        # GET请求：渲染登录页面
        return render_template('login.html')

    @app.route('/api/verify-user', methods=['POST'])
    def verify_user():
        try:
            # 1. 获取请求数据并做基础校验
            # 兼容表单提交和JSON提交（适配不同请求方式）
            if request.is_json:
                data = request.get_json()
                username = data.get('username', '').strip()
            else:
                username = request.form.get('username', '').strip()

            # 2. 基础参数校验
            if not username:
                return jsonify({
                    'success': False,
                    'message': '用户名/邮箱不能为空！',
                    'exists': False
                }), 400

            # 3. 检查用户是否存在（支持用户名/邮箱两种查询方式）
            # 注：根据你的User模型字段调整，若有email字段则添加OR条件
            user_exists = User.query.filter(
                User.username == username  # 若有邮箱字段可改为：or_(User.username==username, User.email==username)
            ).first() is not None

            # 4. 返回验证结果
            return jsonify({
                'success': True,
                'message': '用户验证成功' if user_exists else '用户不存在',
                'exists': user_exists
            }), 200

        except Exception as e:
            # 5. 捕获全局异常并返回
            # 记录异常日志（建议添加logging模块）
            print(f"验证用户异常：{str(e)}")  # 生产环境替换为logger.error
            return jsonify({
                'success': False,
                'message': f'系统错误：{str(e)}',
                'exists': False
            }), 500

    # 密码重置页面路由
    @app.route('/reset-password')
    def reset_password():
        username = request.args.get('username', '')
        if not username:
            # 无用户名参数，重定向到登录页
            flash('Invalid reset link!', 'error')
            return redirect(url_for('login'))

        # 验证用户是否存在（二次验证）
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('login'))

        # 渲染重置页面
        return render_template('reset_password.html', username=username)

    # 密码重置接口
    @app.route('/api/reset-password', methods=['POST'])
    def api_reset_password():
        try:
            # 1. 获取表单数据
            username = request.form.get('username', '').strip()
            new_password = request.form.get('newPassword', '').strip()
            confirm_password = request.form.get('confirmPassword', '').strip()

            # 2. 基础校验
            if not username or not new_password or not confirm_password:
                return jsonify({
                    'success': False,
                    'message': 'All fields are required!'
                }), 400

            if new_password != confirm_password:
                return jsonify({
                    'success': False,
                    'message': 'Passwords do not match!'
                }), 400

            if len(new_password) < 8:
                return jsonify({
                    'success': False,
                    'message': 'Password must be at least 8 characters long!'
                }), 400

            # 3. 验证用户是否存在
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({
                    'success': False,
                    'message': 'User not found!'
                }), 404

            # 4. 更新密码（使用User模型的set_password方法，若无则直接加密）
            # 方式1：如果User模型有set_password方法（推荐）
            user.set_password(new_password)

            # 方式2：如果无set_password方法，手动加密
            # user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

            # 5. 提交数据库
            db.session.commit()

            # 6. 返回成功结果
            return jsonify({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'
            }), 200

        except Exception as e:
            # 异常处理
            db.session.rollback()
            print(f"Reset password error: {str(e)}")
            return jsonify({
                'success': False,
                'message': 'System error! Please try again later.'
            }), 500

    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('index'))

    @app.route('/chat_sessions')
    def chat_sessions():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        role = session['role']
        user_id = session['user_id']

        # 根据角色筛选会话
        if role == 'user':
            # 用户只能查看自己发起的会话
            sessions = ChatSession.query.filter_by(user_id=user_id).all()
        elif role == 'agent':
            # 客服查看自己处理的会话 + 未分配的会话
            sessions = ChatSession.query.filter(
                (ChatSession.agent_id == user_id) |
                (ChatSession.agent_id.is_(None))
            ).all()
        else:  # admin
            # 管理员查看所有会话
            sessions = ChatSession.query.all()

        return render_template('chat_sessions.html', sessions=sessions)

    @app.route('/dashboard')
    def dashboard():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        role = session['role']
        if role == 'user':
            services = ChatSession.query.filter_by(user_id=session['user_id']).all()
            return render_template('chat_sessions.html', services=services)
        elif role == 'agent':
            sessions = ChatSession.query \
                .filter(ChatSession.agent_id.is_(None)) \
                .order_by(ChatSession.start_time.desc()) \
                .all()
            return render_template('agent_dashboard.html', sessions=sessions)
        elif role == 'admin':
            users = User.query.all()
            services = Service.query.all()
            sessions = ChatSession.query.all()
            return render_template('admin_dashboard.html', users=users, services=services, sessions=sessions)

    @app.route('/session_management')
    def session_management():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        role = session['role']
        user_id = session['user_id']

        # 不同角色看到的会话不同
        if role == 'user':
            # 用户只能看到自己的会话
            my_sessions = ChatSession.query.filter_by(user_id=user_id).all()
            pending_sessions = []
            agents = []
        elif role == 'agent':
            # 客服看到自己处理的会话和待处理会话
            my_sessions = ChatSession.query.filter_by(agent_id=user_id).all()
            pending_sessions = ChatSession.query.filter(
                ChatSession.agent_id.is_(None),
                ChatSession.end_time.is_(None)
            ).all()
            agents = []
        elif role == 'admin':
            # 管理员看到所有会话
            my_sessions = ChatSession.query.all()
            pending_sessions = ChatSession.query.filter(
                ChatSession.agent_id.is_(None),
                ChatSession.end_time.is_(None)
            ).all()
            agents = User.query.filter_by(role='agent').all()

        # 为每个会话添加额外信息（最后一条消息、平均情绪等）
        for sess in my_sessions + pending_sessions:
            # 获取最后一条消息
            last_msg = Message.query.filter_by(session_id=sess.id).order_by(Message.timestamp.desc()).first()
            sess.last_message = last_msg

            # 获取第一条消息（用于待处理会话）
            first_msg = Message.query.filter_by(session_id=sess.id).order_by(Message.timestamp).first()
            sess.first_message = first_msg

            # 计算平均情绪
            all_msgs = Message.query.filter_by(session_id=sess.id).all()
            if all_msgs:
                sentiment_sum = sum(msg.sentiment for msg in all_msgs)
                sess.average_sentiment = sentiment_sum / len(all_msgs)
            else:
                sess.average_sentiment = 0

        return render_template(
            'session_management.html',
            my_sessions=my_sessions,
            pending_sessions=pending_sessions,
            agents=agents
        )

    @app.route('/end_chat/<int:session_id>')
    def end_chat(session_id):
        if 'user_id' not in session or session['role'] not in ['agent', 'admin']:
            return redirect(url_for('login'))

        chat_session = ChatSession.query.get(session_id)
        if chat_session and (session['role'] == 'admin' or chat_session.agent_id == session['user_id']):
            chat_session.end_time = datetime.now()
            db.session.commit()
            flash('会话已结束', 'success')

        return redirect(url_for('session_management'))

    @app.route('/friends')
    def friends():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 实际项目中应查询用户好友列表
        return render_template('friends.html')

    @app.route('/system_analysis')
    def system_analysis():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 实际项目中应传入分析数据
        return render_template('system_analysis.html')

    @app.route('/user_center')
    def user_center():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        return render_template('user_center.html', user=user)

    @app.route('/book_appointment', methods=['POST'])
    def book_appointment():
        if 'user_id' not in session or session['role'] != 'user':
            return redirect(url_for('login'))
        service_id = request.form['service_id']
        date_str = request.form['date']
        date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        appt = Appointment(user_id=session['user_id'], service_id=service_id, date=date)
        db.session.add(appt)
        db.session.commit()
        flash('Appointment booked')
        return redirect(url_for('dashboard'))

    @app.route('/rate_appointment/<int:appt_id>', methods=['POST'])
    def rate_appointment(appt_id):
        if 'user_id' not in session or session['role'] != 'user':
            return redirect(url_for('login'))
        rating = int(request.form['rating'])
        appt = Appointment.query.get(appt_id)
        if appt and appt.user_id == session['user_id']:
            appt.rating = rating
            db.session.commit()
            flash('Rated successfully')
        return redirect(url_for('dashboard'))

    @app.route('/start_chat', methods=['POST'])
    def start_chat():
        if 'user_id' not in session or session['role'] != 'user':
            return redirect(url_for('login'))
        chat_session = ChatSession(user_id=session['user_id'])
        db.session.add(chat_session)
        db.session.commit()
        session['current_session'] = chat_session.id
        return redirect(url_for('chat', session_id=chat_session.id))

    @app.route('/join_chat/<int:session_id>')
    def join_chat(session_id):
        if 'user_id' not in session or session['role'] != 'agent':
            return redirect(url_for('login'))
        chat_session = ChatSession.query.get(session_id)
        if chat_session and not chat_session.agent_id:
            chat_session.agent_id = session['user_id']
            db.session.commit()
        session['current_session'] = session_id
        return redirect(url_for('chat', session_id=session_id))

    @app.route('/chat/<int:session_id>')
    def chat(session_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        chat_session = ChatSession.query.get(session_id)
        if not chat_session or (session['role'] == 'user' and chat_session.user_id != session['user_id']) or (
                session['role'] == 'agent' and chat_session.agent_id != session['user_id']):
            flash('Access denied')
            return redirect(url_for('dashboard'))
        messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp).all()
        return render_template('chat.html', session_id=session_id, messages=messages, role=session['role'])

    @app.route('/admin/add_service', methods=['POST'])
    def add_service():
        if 'role' not in session or session['role'] != 'admin':
            return redirect(url_for('login'))
        name = request.form['name']
        description = request.form['description']
        service = Service(name=name, description=description)
        db.session.add(service)
        db.session.commit()
        flash('Service added')
        return redirect(url_for('dashboard'))

    @app.route('/admin/delete_user/<int:user_id>')
    def delete_user(user_id):
        if 'role' not in session or session['role'] != 'admin':
            return redirect(url_for('login'))
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
            flash('User deleted')
        return redirect(url_for('dashboard'))
