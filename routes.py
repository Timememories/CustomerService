from flask import render_template, request, redirect, url_for, session, flash, jsonify

from bot import analyze_sentiment, generate_bot_response
from models import db, User, Service, Appointment, ChatSession, Message, FriendRelation
from datetime import datetime, UTC


def init_routes(app):
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('session_management'))
        return render_template('index.html')

    from flask import request, jsonify  # 确保导入这些模块

    # 在现有路由初始化后添加
    @app.route('/api/analyze-emotion', methods=['POST'])
    def analyze_emotion():
        data = request.get_json()
        text = data.get('text', '')

        if not text:
            return jsonify({'error': 'No text provided'}), 400

        # 调用现有情感分析功能
        sentiment = analyze_sentiment(text)

        # 生成情感标签
        if sentiment > 0.6:
            emotion = "Joy"
            intensity = f"{int(sentiment * 100)}%"
        elif sentiment > 0.2:
            emotion = "Contentment"
            intensity = f"{int(sentiment * 100)}%"
        elif sentiment > -0.2:
            emotion = "Neutral"
            intensity = "50%"
        elif sentiment > -0.6:
            emotion = "Discontent"
            intensity = f"{int((1 + sentiment) * 50)}%"
        else:
            emotion = "Distress"
            intensity = f"{int((1 + sentiment) * 50)}%"

        # 生成AI回应
        response = generate_bot_response(text, sentiment)

        return jsonify({
            'emotion': emotion,
            'intensity': intensity,
            'response': response
        })

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
                    session['avatar'] = user.avatar
                    session.permanent = True  # 设置session持久化（可选，默认浏览器关闭失效）
                    flash(f'Welcome back, {user.username}!')
                    return redirect(url_for('session_management'))
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
            a = user.set_password(new_password)

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
            if isinstance(e, ValueError):
                return jsonify({
                    'success': False,
                    'message': f"Reset password error: {str(e)}"
                }), 500
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

    @app.route('/edit-profile', methods=['GET', 'POST'])
    def edit_profile():
        # 验证用户登录状态
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # 获取当前用户信息
        user = User.query.get(session['user_id'])
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            try:
                # 获取表单数据
                real_name = request.form.get('real_name', '').strip()
                email = request.form.get('email', '').strip()
                phone = request.form.get('phone', '').strip()
                avatar_url = request.form.get('avatar_url', '').strip()

                # 验证邮箱唯一性（如果填写了邮箱）
                if email:
                    existing_email = User.query.filter(
                        User.email == email,
                        User.id != user.id
                    ).first()
                    if existing_email:
                        flash('Email already in use', 'error')
                        return render_template('edit_profile.html', user=user)

                # 验证手机号唯一性（如果填写了手机号）
                if phone:
                    existing_phone = User.query.filter(
                        User.phone == phone,
                        User.id != user.id
                    ).first()
                    if existing_phone:
                        flash('Phone number already in use', 'error')
                        return render_template('edit_profile.html', user=user)

                # 更新用户信息
                user.real_name = real_name if real_name else None
                user.email = email if email else None
                user.phone = phone if phone else None
                user.updated_at = datetime.now()  # 更新时间戳
                if avatar_url:  # 只有上传了新头像才更新
                    user.avatar = avatar_url

                db.session.commit()
                flash('Profile updated successfully', 'success')
                return redirect(url_for('user_center'))

            except Exception as e:
                db.session.rollback()
                flash(f'Update failed: {str(e)}', 'error')
                return render_template('edit_profile.html', user=user)
        else:
            flash("")

        # GET 请求：渲染编辑页面
        return render_template('edit_profile.html', user=user)

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

    # 好友管理首页（展示页面）
    # @app.route('/friends_management')
    # def friends_management():
    #     if 'user_id' not in session:
    #         return redirect('/login')
    #     return render_template('friends_management.html')

    # @app.route('/friends_management', methods=['GET'])
    # def get_friends():
    #     if 'user_id' not in session:
    #         return redirect('/login')
    #
    #     current_user_id = session['user_id']
    #     # 查询所有好友关系（包括不同状态）
    #     relations = db.session.query(FriendRelation).filter(
    #         db.or_(
    #             FriendRelation.user_id == current_user_id,
    #             FriendRelation.friend_id == current_user_id
    #         )
    #     ).all()
    #
    #     # 统计各状态数量
    #     status_counts = {
    #         'pending': 0,
    #         'accepted': 0,
    #         'rejected': 0
    #     }
    #     for r in relations:
    #         if r.status in status_counts:
    #             status_counts[r.status] += 1
    #
    #     return render_template(
    #         'friends_management.html',
    #         friend_relations=relations,
    #         current_user_id=current_user_id,
    #         pending_count=status_counts['pending'],
    #         accepted_count=status_counts['accepted'],
    #         rejected_count=status_counts['rejected'],
    #         friend_count=len(relations),
    #         online_users=online_users  # 用于前端显示在线状态
    #     )
    #
    # @app.route('/friends_management/handle_request', methods=['POST'])
    # def handle_request():
    #     """处理好友请求（接受/拒绝）"""
    #     if 'user_id' not in session:
    #         return jsonify({"success": False, "error": "Not logged in"}), 401
    #
    #     data = request.json
    #     friend_id = data.get('friend_id')
    #     action = data.get('action')  # accept/reject
    #     current_user_id = session['user_id']
    #
    #     # 查找对应的好友关系（对方发起的请求）
    #     relation = FriendRelation.query.filter_by(
    #         user_id=friend_id,
    #         friend_id=current_user_id,
    #         status='pending'
    #     ).first()
    #
    #     if not relation:
    #         return jsonify({"success": False, "error": "Request not found"}), 404
    #
    #     # 更新状态
    #     relation.status = 'accepted' if action == 'accept' else 'rejected'
    #     relation.updated_at = datetime.now(UTC)
    #     db.session.commit()
    #
    #     return jsonify({
    #         "success": True,
    #         "message": f"Request {action}ed successfully"
    #     })
    #
    # @app.route('/friends_management/cancel_request', methods=['POST'])
    # def cancel_request():
    #     """取消已发送的请求"""
    #     if 'user_id' not in session:
    #         return jsonify({"success": False, "error": "Not logged in"}), 401
    #
    #     friend_id = request.json.get('friend_id')
    #     current_user_id = session['user_id']
    #
    #     # 删除或更新状态为rejected
    #     relation = FriendRelation.query.filter_by(
    #         user_id=current_user_id,
    #         friend_id=friend_id,
    #         status='pending'
    #     ).first()
    #
    #     if not relation:
    #         return jsonify({"success": False, "error": "Request not found"}), 404
    #
    #     db.session.delete(relation)
    #     db.session.commit()
    #
    #     return jsonify({"success": True, "message": "Request canceled"})
    #
    # # 保留原有的add_friend和delete_friend接口，稍作修改
    # @app.route('/friends_management/add', methods=['POST'])
    # def add_friend():
    #     if 'user_id' not in session:
    #         return jsonify({"success": False, "error": "Not logged in"}), 401
    #
    #     data = request.json
    #     target_username = data.get('target_username')
    #     if not target_username:
    #         return jsonify({"success": False, "error": "Username is required"}), 400
    #
    #     target_user = User.query.filter_by(username=target_username).first()
    #     if not target_user:
    #         return jsonify({"success": False, "error": f"User '{target_username}' does not exist"}), 404
    #
    #     current_user_id = session['user_id']
    #     # if target_user.id == current_user_id:
    #     #     return jsonify({"success": False, "error": "Cannot add yourself as friend"}), 400
    #
    #     # 检查是否已有关系（无论状态）
    #     existing = FriendRelation.query.filter(
    #         db.or_(
    #             (FriendRelation.user_id == current_user_id) & (FriendRelation.friend_id == target_user.id),
    #             (FriendRelation.user_id == target_user.id) & (FriendRelation.friend_id == current_user_id)
    #         )
    #     ).first()
    #
    #     if existing:
    #         return jsonify({
    #             "success": False,
    #             "error": f"Already have a relation with {target_username} (status: {existing.status})"
    #         }), 400
    #
    #     # 创建新请求
    #     new_relation = FriendRelation(
    #         user_id=current_user_id,
    #         friend_id=target_user.id,
    #         status='pending',
    #         created_at=datetime.now(UTC)
    #     )
    #     db.session.add(new_relation)
    #     db.session.commit()
    #
    #     return jsonify({"success": True, "message": f"Friend request sent to {target_username}"})

    # 好友管理页面
    @app.route('/friends_management')
    def get_friends():
        # 获取当前登录用户ID（根据你的认证方式调整）
        current_user_id = session.get('user_id')
        if not current_user_id:
            return redirect('/login')

        # 查询当前用户的所有好友关系
        friend_relations = FriendRelation.query.filter(
            db.or_(
                FriendRelation.user_id == current_user_id,
                FriendRelation.friend_id == current_user_id
            )
        ).all()

        # 统计不同状态的数量
        friend_count = len(friend_relations)
        pending_count = len([r for r in friend_relations if r.status == 'pending'])
        accepted_count = len([r for r in friend_relations if r.status == 'accepted'])
        rejected_count = len([r for r in friend_relations if r.status == 'rejected'])

        # 渲染模板，确保传递所有必要变量
        return render_template(
            'friends_management.html',
            friend_relations=friend_relations,
            current_user_id=current_user_id,
            friend_count=friend_count,
            pending_count=pending_count,
            accepted_count=accepted_count,
            rejected_count=rejected_count
        )

    # 添加好友接口
    @app.route('/friends_management/add', methods=['POST'])
    def add_friend():
        data = request.get_json()
        current_user_id = session.get('user_id')

        if not current_user_id:
            return jsonify({'success': False, 'error': 'Please login first'})

        target_username = data.get('target_username')
        if not target_username:
            return jsonify({'success': False, 'error': 'Username is required'})

        # 查找目标用户
        target_user = User.query.filter_by(username=target_username).first()
        if not target_user:
            return jsonify({'success': False, 'error': 'User not found'})

        # # 不能添加自己
        if target_user.id == current_user_id:
            return jsonify({'success': False, 'error': 'Cannot add yourself as friend'})

        # 检查是否已发送过请求
        existing_relation = FriendRelation.query.filter(
            db.or_(
                db.and_(
                    FriendRelation.user_id == current_user_id,
                    FriendRelation.friend_id == target_user.id
                ),
                db.and_(
                    FriendRelation.user_id == target_user.id,
                    FriendRelation.friend_id == current_user_id
                )
            )
        ).first()

        if existing_relation:
            return jsonify({
                'success': False,
                'error': f'Friend request already exists (status: {existing_relation.status})'
            })

        # 创建新的好友请求
        new_relation = FriendRelation(
            user_id=current_user_id,
            friend_id=target_user.id,
            status='pending',
            created_at=datetime.now(UTC)
        )

        db.session.add(new_relation)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Friend request sent successfully',
            'relation': new_relation.to_dict()
        })

    # 处理好友请求（接受/拒绝）
    @app.route('/friends_management/handle_request', methods=['POST'])
    def handle_friend_request():
        data = request.get_json()
        current_user_id = session.get('user_id')

        if not current_user_id:
            return jsonify({'success': False, 'error': 'Please login first'})

        friend_id = data.get('friend_id')
        action = data.get('action')  # accept/reject

        if not friend_id or action not in ['accept', 'reject']:
            return jsonify({'success': False, 'error': 'Invalid parameters'})

        # 查找对应的好友关系
        relation = FriendRelation.query.filter(
            db.and_(
                FriendRelation.friend_id == current_user_id,
                FriendRelation.user_id == friend_id,
                FriendRelation.status == 'pending'
            )
        ).first()

        if not relation:
            return jsonify({'success': False, 'error': 'Friend request not found'})

        # 更新状态
        relation.status = 'accepted' if action == 'accept' else 'rejected'
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Friend request {action}ed successfully'
        })

    # 取消好友请求
    @app.route('/friends_management/cancel_request', methods=['POST'])
    def cancel_friend_request():
        data = request.get_json()
        current_user_id = session.get('user_id')

        if not current_user_id:
            return jsonify({'success': False, 'error': 'Please login first'})

        friend_id = data.get('friend_id')

        # 查找自己发起的未处理请求
        relation = FriendRelation.query.filter(
            db.and_(
                FriendRelation.user_id == current_user_id,
                FriendRelation.friend_id == friend_id,
                FriendRelation.status == 'pending'
            )
        ).first()

        if not relation:
            return jsonify({'success': False, 'error': 'Pending request not found'})

        # 删除请求或更新状态
        db.session.delete(relation)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Friend request canceled successfully'
        })

    # 删除好友
    @app.route('/friends_management/delete', methods=['POST'])
    def delete_friend():
        data = request.get_json()
        current_user_id = session.get('user_id')

        if not current_user_id:
            return jsonify({'success': False, 'error': 'Please login first'})

        friend_id = data.get('friend_id')

        # 查找好友关系（双向都要考虑）
        relation = FriendRelation.query.filter(
            db.or_(
                db.and_(
                    FriendRelation.user_id == current_user_id,
                    FriendRelation.friend_id == friend_id
                ),
                db.and_(
                    FriendRelation.user_id == friend_id,
                    FriendRelation.friend_id == current_user_id
                )
            )
        ).first()

        if not relation:
            return jsonify({'success': False, 'error': 'Friend relation not found'})

        # 删除好友关系
        db.session.delete(relation)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Friend removed successfully'
        })

    @app.route('/profile')
    def profile():
        user_id = request.args.get('user_id')
        if not user_id:
            flash('User ID is required', 'error')
            return redirect(url_for('dashboard'))

        user = User.query.get(user_id)
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('dashboard'))

        return render_template('profile.html', user=user)
