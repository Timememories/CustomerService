from flask import redirect, url_for, flash, request, jsonify, session, render_template
# from flask_socketio import emit, SocketIO

from bot import generate_bot_response, analyze_sentiment, extract_keywords, generate_summary
from models import db, User, Service, Appointment, ChatSession, Message, FriendRelation
from datetime import UTC, datetime


def init_routes(app):
    # socketio = SocketIO(app)

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('session_management'))
        return render_template('index.html')

    # 在现有路由初始化后添加
    # Added after initial route initialization
    @app.route('/api/analyze-emotion', methods=['POST'])
    def analyze_emotion():
        data = request.get_json()
        text = data.get('text', '')

        if not text:
            return jsonify({'error': 'No text provided'}), 400  # 未提供文本

        # 调用现有情感分析功能
        # Call existing sentiment analysis function
        sentiment = analyze_sentiment(text)

        # 生成情感标签
        # Generate emotion labels
        if sentiment > 0.6:
            emotion = "Joy"  # 喜悦
            intensity = f"{int(sentiment * 100)}%"
        elif sentiment > 0.2:
            emotion = "Contentment"  # 满足
            intensity = f"{int(sentiment * 100)}%"
        elif sentiment > -0.2:
            emotion = "Neutral"  # 中性
            intensity = "50%"
        elif sentiment > -0.6:
            emotion = "Discontent"  # 不满
            intensity = f"{int((1 + sentiment) * 50)}%"
        else:
            emotion = "Distress"  # 痛苦
            intensity = f"{int((1 + sentiment) * 50)}%"

        # 生成AI回应
        # Generate AI response
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
            # 1. Get form data and perform basic validation
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'user').strip()  # 默认普通用户 / default to regular user

            # 2. 基础参数校验
            # 2. Basic parameter validation
            if not username:
                flash('The username cannot be empty！', 'error')  # 用户名不能为空！
                return redirect(url_for('register'))
            if not password:
                flash('Password cannot be empty！', 'error')  # 密码不能为空！
                return redirect(url_for('register'))
            # 校验角色合法性（仅允许 admin/agent/user）
            # Validate role legality (only admin/agent/user allowed)
            if role not in ['admin', 'agent', 'user']:
                flash('Invalid role type！', 'error')  # 无效的角色类型！
                return redirect(url_for('register'))

            # 3. 检查用户名是否已存在
            # 3. Check if username already exists
            if User.query.filter_by(username=username).first():
                flash('The username already exists, please change it!', 'error')  # 用户名已存在，请更换！
                return redirect(url_for('register'))

            try:
                # 4. 创建用户（自动触发密码加密，依赖User模型的set_password方法）
                # 4. Create user (automatically triggers password encryption, depends on User model's set_password method)
                user = User(
                    username=username,
                    password=password,  # 模型内部会自动加密，无需手动处理 / Model will automatically encrypt, no manual handling needed
                    role=role
                )
                # 5. 提交数据库
                # 5. Submit to database
                db.session.add(user)
                db.session.commit()
                flash('registered successfully Please log in.', 'success')  # 注册成功，请登录。
                return redirect(url_for('login'))

            except ValueError as e:
                # 捕获密码强度验证失败的异常（User模型的_validate_password_strength）
                # Catch exception for failed password strength verification (User model's _validate_password_strength)
                db.session.rollback()  # 回滚事务 / Rollback transaction
                flash(f'Registration failed：{str(e)}', 'error')  # 注册失败：
                return redirect(url_for('register'))

            except Exception as e:
                # 捕获其他数据库异常
                # Catch other database exceptions
                db.session.rollback()  # 回滚事务 / Rollback transaction
                flash(f'System error：{str(e)}', 'error')  # 系统错误：
                return redirect(url_for('register'))

        # GET请求：渲染注册页面
        # GET request: render registration page
        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # 若用户已登录，直接跳转到仪表盘
        # If user is already logged in, redirect directly to dashboard
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            # 1. 获取并清理表单数据
            # 1. Get and clean form data
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()

            # 2. 基础校验
            # 2. Basic validation
            if not username or not password:
                flash('Username and password cannot be empty!')  # 用户名和密码不能为空！
                return redirect(url_for('login'))

            try:
                # 3. 查询用户（仅按用户名查询）
                # 3. Query user (only by username)
                user = User.query.filter_by(username=username).first()

                # 4. 验证用户和密码（核心修复：密码需用加密校验，而非明文比对）
                # 4. Verify user and password (core fix: password needs to be verified with encryption, not plain text comparison)
                if user and user.check_password(password):
                    # 密码验证成功，初始化session
                    # Password verification successful, initialize session
                    session['user_id'] = user.id
                    session['role'] = user.role
                    session['username'] = user.username
                    session['avatar'] = user.avatar
                    session.permanent = True  # 设置session持久化（可选，默认浏览器关闭失效） / Set session persistence (optional, expires when browser closes by default)
                    flash(f'Welcome back, {user.username}!')  # 欢迎回来，{user.username}！
                    return redirect(url_for('session_management'))
                else:
                    # 用户名不存在或密码错误
                    # Username does not exist or password is incorrect
                    flash('Invalid username or password!')  # 无效的用户名或密码！

            except Exception as e:
                # 捕获数据库或其他系统异常
                # Catch database or other system exceptions
                flash(f'System error: {str(e)}')  # 系统错误:

        # GET请求：渲染登录页面
        # GET request: render login page
        return render_template('login.html')

    @app.route('/api/verify-user', methods=['POST'])
    def verify_user():
        try:
            # 1. 获取请求数据并做基础校验
            # 1. Get request data and perform basic validation
            # 兼容表单提交和JSON提交（适配不同请求方式）
            # Compatible with form submission and JSON submission (adapts to different request methods)
            if request.is_json:
                data = request.get_json()
                username = data.get('username', '').strip()
            else:
                username = request.form.get('username', '').strip()

            # 2. 基础参数校验
            # 2. Basic parameter validation
            if not username:
                return jsonify({
                    'success': False,
                    'message': 'Username/email cannot be empty!',  # 用户名/邮箱不能为空！
                    'exists': False
                }), 400

            # 3. 检查用户是否存在（支持用户名/邮箱两种查询方式）
            # 3. Check if user exists (supports username/email query methods)
            # 注：根据你的User模型字段调整，若有email字段则添加OR条件
            # Note: Adjust according to your User model fields, add OR condition if there is an email field
            user_exists = User.query.filter(
                User.username == username  # 若有邮箱字段可改为：or_(User.username==username, User.email==username) / If there is an email field, can be changed to: or_(User.username==username, User.email==username)
            ).first() is not None

            # 4. 返回验证结果
            # 4. Return verification result
            return jsonify({
                'success': True,
                'message': 'User verification successful' if user_exists else 'User does not exist',  # 用户验证成功 / 用户不存在
                'exists': user_exists
            }), 200

        except Exception as e:
            # 5. 捕获全局异常并返回
            # 5. Catch global exceptions and return
            # 记录异常日志（建议添加logging模块）
            # Record exception logs (recommended to add logging module)
            print(f"验证用户异常：{str(e)}")  # 生产环境替换为logger.error / Replace with logger.error in production environment
            return jsonify({
                'success': False,
                'message': f'System error：{str(e)}',  # 系统错误：
                'exists': False
            }), 500

    # 密码重置页面路由
    # Password reset page route
    @app.route('/reset-password')
    def reset_password():
        username = request.args.get('username', '')
        if not username:
            # 无用户名参数，重定向到登录页
            # No username parameter, redirect to login page
            flash('Invalid reset link!', 'error')  # 无效的重置链接！
            return redirect(url_for('login'))

        # 验证用户是否存在（二次验证）
        # Verify if user exists (secondary verification)
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('User not found!', 'error')  # 未找到用户！
            return redirect(url_for('login'))

        # 渲染重置页面
        # Render reset page
        return render_template('reset_password.html', username=username)

    # 密码重置接口
    # Password reset interface
    @app.route('/api/reset-password', methods=['POST'])
    def api_reset_password():
        try:
            # 1. 获取表单数据
            # 1. Get form data
            username = request.form.get('username', '').strip()
            new_password = request.form.get('newPassword', '').strip()
            confirm_password = request.form.get('confirmPassword', '').strip()

            # 2. 基础校验
            # 2. Basic validation
            if not username or not new_password or not confirm_password:
                return jsonify({
                    'success': False,
                    'message': 'All fields are required!'  # 所有字段都是必填的！
                }), 400

            if new_password != confirm_password:
                return jsonify({
                    'success': False,
                    'message': 'Passwords do not match!'  # 密码不匹配！
                }), 400

            if len(new_password) < 8:
                return jsonify({
                    'success': False,
                    'message': 'Password must be at least 8 characters long!'  # 密码长度至少为8个字符！
                }), 400

            # 3. 验证用户是否存在
            # 3. Verify if user exists
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({
                    'success': False,
                    'message': 'User not found!'  # 未找到用户！
                }), 404

            # 4. 更新密码（使用User模型的set_password方法，若无则直接加密）
            # 4. Update password (use User model's set_password method, encrypt directly if not available)
            # 方式1：如果User模型有set_password方法（推荐）
            # Method 1: If User model has set_password method (recommended)
            user.set_password(new_password)

            # 方式2：如果无set_password方法，手动加密
            # Method 2: If no set_password method, encrypt manually
            # user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

            # 5. 提交数据库
            # 5. Submit to database
            db.session.commit()

            # 6. 返回成功结果
            # 6. Return success result
            return jsonify({
                'success': True,
                'message': 'Password reset successfully! You can now login with your new password.'  # 密码重置成功！您现在可以使用新密码登录。
            }), 200

        except Exception as e:
            # 异常处理
            # Exception handling
            db.session.rollback()
            if isinstance(e, ValueError):
                return jsonify({
                    'success': False,
                    'message': f"Reset password error: {str(e)}"  # 重置密码错误：
                }), 500
            print(f"Reset password error: {str(e)}")  # 重置密码错误：
            return jsonify({
                'success': False,
                'message': 'System error! Please try again later.'  # 系统错误！请稍后再试。
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
        # Filter sessions by role
        if role == 'user':
            # 用户只能查看自己发起的会话
            # Users can only view sessions they initiated
            sessions = ChatSession.query.filter_by(user_id=user_id).all()
        elif role == 'agent':
            # 客服查看自己处理的会话 + 未分配的会话
            # Agents view their handled sessions + unassigned sessions
            sessions = ChatSession.query.filter(
                (ChatSession.agent_id == user_id) |
                (ChatSession.agent_id.is_(None))
            ).all()
        else:  # admin
            # 管理员查看所有会话
            # Admins view all sessions
            sessions = ChatSession.query.all()

        return render_template('chat_sessions.html', sessions=sessions)

    @app.route('/session_management')
    def session_management():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        role = session['role']
        user_id = session['user_id']

        # 不同角色看到的会话不同
        # Different roles see different sessions
        if role == 'user':
            # 用户只能看到自己的会话
            # Users can only see their own sessions
            my_sessions = ChatSession.query.filter(
                db.or_(db.and_(ChatSession.user_id == user_id), db.and_(ChatSession.agent_id == user_id))).all()
            pending_sessions = []
            agents = []
        elif role == 'agent':
            # 客服看到自己处理的会话和待处理会话
            # Agents see their handled sessions and pending sessions
            my_sessions = ChatSession.query.filter_by(agent_id=user_id).all()
            pending_sessions = ChatSession.query.filter(
                ChatSession.agent_id.is_(None),
                ChatSession.end_time.is_(None)
            ).all()
            agents = []
        elif role == 'admin':
            # 管理员看到所有会话
            # Admins see all sessions
            my_sessions = ChatSession.query.all()
            pending_sessions = ChatSession.query.filter(
                ChatSession.agent_id.is_(None),
                ChatSession.end_time.is_(None)
            ).all()
            agents = User.query.filter_by(role='agent').all()

        # 为每个会话添加额外信息（最后一条消息、平均情绪等）
        # Add additional information for each session (last message, average sentiment, etc.)
        for sess in my_sessions + pending_sessions:
            # 获取最后一条消息
            # Get last message
            last_msg = Message.query.filter_by(session_id=sess.id).order_by(Message.timestamp.desc()).first()
            sess.last_message = last_msg

            # 获取第一条消息（用于待处理会话）
            # Get first message (for pending sessions)
            first_msg = Message.query.filter_by(session_id=sess.id).order_by(Message.timestamp).first()
            sess.first_message = first_msg

            # 计算平均情绪
            # Calculate average sentiment
            all_msgs = Message.query.filter_by(session_id=sess.id).all()
            if all_msgs:
                sentiment_sum = sum(msg.sentiment for msg in all_msgs)
                sess.average_sentiment = sentiment_sum / len(all_msgs)
            else:
                sess.average_sentiment = 0
        friend_relations = FriendRelation.query.filter(
            db.or_(
                FriendRelation.user_id == user_id,
                FriendRelation.friend_id == user_id,
                FriendRelation.status == 'accepted'
            )
        ).all()
        relation_dicts = []
        for rel in friend_relations:
            # 提取需要返回的字段，处理特殊类型（如datetime）
            # Extract fields to return, handle special types (e.g., datetime)
            rel_dict = {
                'id': rel.id,
                'user_id': rel.user_id,
                'friend_id': rel.friend_id,
                'status': rel.status,
                'user_name': rel.user.username,
                'friend_name': rel.friend.username
            }
            # 额外优化：识别“好友ID”（区分当前用户是user_id还是friend_id）
            # Additional optimization: Identify "friend ID" (distinguish whether current user is user_id or friend_id)
            rel_dict['friend_id_target'] = rel.friend_id if rel.user_id == user_id else rel.user_id
            relation_dicts.append(rel_dict)
        print(pending_sessions)
        print(my_sessions)
        print(agents)
        print(relation_dicts)
        print(friend_relations)
        return render_template(
            'session_management.html',
            my_sessions=my_sessions,
            pending_sessions=pending_sessions,
            agents=agents,
            friends=friend_relations,  # 将关系列表转换为JSON字符串 / Convert relationship list to JSON string
        )

    @app.route('/end_chat/<int:session_id>')
    def end_chat(session_id):
        if 'user_id' not in session or session['role'] not in ['agent', 'admin']:
            return redirect(url_for('login'))

        chat_session = ChatSession.query.get(session_id)
        if chat_session and (session['role'] == 'admin' or chat_session.agent_id == session['user_id']):
            chat_session.end_time = datetime.now()
            db.session.commit()
            flash('The session has ended', 'success')  # 会话已结束

        return redirect(url_for('session_management'))

    @app.route('/friends')
    def friends():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 实际项目中应查询用户好友列表
        # In actual projects, should query user's friend list
        return render_template('friends.html')

    @app.route('/system_analysis')
    def system_analysis():
        if 'user_id' not in session:
            return redirect(url_for('login'))
        # 实际项目中应传入分析数据
        # In actual projects, should pass in analysis data
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
        # Verify user login status
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # 获取当前用户信息
        # Get current user information
        user = User.query.get(session['user_id'])
        if not user:
            flash('User not found', 'error')  # 未找到用户
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            try:
                # 获取表单数据
                # Get form data
                real_name = request.form.get('real_name', '').strip()
                email = request.form.get('email', '').strip()
                phone = request.form.get('phone', '').strip()
                avatar_url = request.form.get('avatar_url', '').strip()

                # 验证邮箱唯一性（如果填写了邮箱）
                # Verify email uniqueness (if email is filled)
                if email:
                    existing_email = User.query.filter(
                        User.email == email,
                        User.id != user.id
                    ).first()
                    if existing_email:
                        flash('Email already in use', 'error')  # 邮箱已被使用
                        return render_template('edit_profile.html', user=user)

                # 验证手机号唯一性（如果填写了手机号）
                # Verify phone number uniqueness (if phone number is filled)
                if phone:
                    existing_phone = User.query.filter(
                        User.phone == phone,
                        User.id != user.id
                    ).first()
                    if existing_phone:
                        flash('Phone number already in use', 'error')  # 手机号已被使用
                        return render_template('edit_profile.html', user=user)

                # 更新用户信息
                # Update user information
                user.real_name = real_name if real_name else None
                user.email = email if email else None
                user.phone = phone if phone else None
                user.updated_at = datetime.now()  # 更新时间戳 / Update timestamp
                if avatar_url:  # 只有上传了新头像才更新 / Only update if new avatar is uploaded
                    user.avatar = avatar_url

                db.session.commit()
                flash('Profile updated successfully', 'success')  # 资料更新成功
                return redirect(url_for('user_center'))

            except Exception as e:
                db.session.rollback()
                flash(f'Update failed: {str(e)}', 'error')  # 更新失败：
                return render_template('edit_profile.html', user=user)
        else:
            flash("")

        # GET 请求：渲染编辑页面
        # GET request: render edit page
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
        flash('Appointment booked')  # 预约已成功
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
            user.is_deleted = True
            user.updated_at = datetime.now()
            if user_id == session['user_id']:
                return redirect(url_for('user_management'))
            db.session.commit()
            flash('User deleted')
        return redirect(url_for('user_management'))

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
            if existing_relation.status == "rejected":
                existing_relation.status = 'pending'
                db.session.commit()
                return jsonify({
                    'success': True,
                    'message': 'Friend request resent successfully',
                    'relation': existing_relation.to_dict()
                })
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

    @app.route('/api/friends/list')
    def get_friends_list():
        # 获取当前登录用户ID（根据你的认证方式调整）
        current_user_id = session.get('user_id')
        if not current_user_id:
            return redirect('/login')

        # 查询当前用户的所有好友关系
        friend_relations = FriendRelation.query.filter(
            db.or_(
                FriendRelation.user_id == current_user_id,
                FriendRelation.friend_id == current_user_id,
                FriendRelation.status == 'accepted'
            )
        ).all()
        relation_dicts = []
        for rel in friend_relations:
            # 提取需要返回的字段，处理特殊类型（如datetime）
            rel_dict = {
                'id': rel.id,
                'user_id': rel.user_id,
                'friend_id': rel.friend_id,
                'status': rel.status,
                'user_name': rel.user.username,
                'friend_name': rel.friend.username
            }
            # 额外优化：识别“好友ID”（区分当前用户是user_id还是friend_id）
            rel_dict['friend_id_target'] = rel.friend_id if rel.user_id == current_user_id else rel.user_id
            relation_dicts.append(rel_dict)
        # 渲染模板，确保传递所有必要变量
        return jsonify({
            'success': True,
            "friend_relations": relation_dicts,
            "current_user_id": current_user_id
        }), 200

    @app.route('/start_chat', methods=['GET', 'POST'])
    def start_chat():
        if 'user_id' not in session:
            flash('Please login first!', 'error')
            return redirect(url_for('login'))

        # 支持GET参数（如/start_chat?type=system）和表单提交两种方式
        chat_type = request.args.get('type', request.form.get('type', 'system'))
        user_id = session['user_id']
        new_session = None

        try:
            if chat_type == 'system':
                # 创建系统聊天会话（客服处理）
                new_session = ChatSession(
                    user_id=user_id,
                    agent_id=None,  # 初始无客服分配
                    start_time=datetime.now(UTC),
                    end_time=None,
                    status='active'
                )
                db.session.add(new_session)
                db.session.commit()

                # 系统自动发送欢迎消息
                welcome_msg = Message(
                    session_id=new_session.id,
                    sender_id=0,  # 系统消息标识
                    receiver_id=None,
                    text="Hello! How can we assist you today?",
                    timestamp=datetime.now(UTC),
                    sentiment=1.0,
                    message_type='text'
                )
                db.session.add(welcome_msg)
                db.session.commit()

            elif chat_type == 'friend':
                # 从GET参数获取好友ID（兼容表单提交）
                friend_id = request.args.get('friend_id', request.form.get('friend_id'))
                if not friend_id:
                    flash('Friend ID is required!', 'error')
                    return redirect(url_for('session_management'))

                try:
                    friend_id = int(friend_id)
                except ValueError:
                    flash('Invalid friend ID format!', 'error')
                    return redirect(url_for('session_management'))

                # 验证好友关系
                friend_relation = FriendRelation.query.filter(
                    db.or_(
                        db.and_(
                            FriendRelation.user_id == user_id,
                            FriendRelation.friend_id == friend_id,
                            FriendRelation.status == 'accepted'
                        ),
                        db.and_(
                            FriendRelation.user_id == friend_id,
                            FriendRelation.friend_id == user_id,
                            FriendRelation.status == 'accepted'
                        )
                    )
                ).first()

                if not friend_relation:
                    flash('You are not friends with this user!', 'error')
                    return redirect(url_for('session_management'))

                # 检查是否已有活跃会话
                existing_session = ChatSession.query.filter(
                    db.or_(
                        db.and_(
                            ChatSession.user_id == user_id,
                            ChatSession.agent_id == friend_id,
                            ChatSession.end_time.is_(None)
                        ),
                        db.and_(
                            ChatSession.user_id == friend_id,
                            ChatSession.agent_id == user_id,
                            ChatSession.end_time.is_(None)
                        )
                    )
                ).first()

                if existing_session:
                    friend_relation.session_id = existing_session.id
                    db.session.commit()
                    return redirect(url_for('chat', session_id=existing_session.id))

                # 创建好友会话（用agent_id存储好友ID）
                new_session = ChatSession(
                    user_id=user_id,
                    agent_id=friend_id,
                    start_time=datetime.now(UTC),
                    end_time=None,
                    status='active'
                )
                db.session.add(new_session)
                db.session.commit()
                friend_relation.session_id = new_session.id
                db.session.commit()

            else:
                flash('Invalid chat type!', 'error')
                return redirect(url_for('session_management'))

            # 关键：创建成功后跳转到聊天页面
            return redirect(url_for('chat', session_id=new_session.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Failed to start chat: {str(e)}', 'error')
            return redirect(url_for('session_management'))

    # 聊天页面路由（确保已实现）
    @app.route('/chat/<int:session_id>')
    def chat(session_id):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # 验证会话存在性和访问权限
        chat_session = ChatSession.query.get(session_id)
        if not chat_session:
            flash('Chat session not found!', 'error')
            return redirect(url_for('session_management'))

        user_id = session['user_id']
        # 检查权限：用户必须是会话发起者或客服/好友
        if not (chat_session.user_id == user_id or chat_session.agent_id == None or chat_session.agent_id == user_id):
            flash('You have no permission to access this session!', 'error')
            return redirect(url_for('session_management'))

        # 获取会话消息
        messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp).all()
        return render_template('chat.html', session_id=session_id, messages=messages)


    # AI分析页面路由（展示分析结果）
    @app.route('/ai_analysis')
    def ai_analysis():
        if 'user_id' not in session:
            return redirect(url_for('login'))

        # 获取可选参数：session_id（指定分析某个会话）
        session_id = request.args.get('session_id')
        analysis_data = {}

        if session_id:
            # 分析指定会话的消息
            from models import ChatSession, Message
            chat_session = ChatSession.query.get(session_id)
            if chat_session:
                # 校验权限（仅会话参与者/管理员可查看）
                user_id = session['user_id']
                if not (chat_session.user_id == user_id or chat_session.agent_id == user_id or session[
                    'role'] == 'admin'):
                    flash('No permission to view this session analysis', 'error')
                    return redirect(url_for('dashboard'))

                # 获取该会话所有消息
                messages = Message.query.filter_by(session_id=session_id).order_by(Message.timestamp).all()
                if messages:
                    # 提取所有消息文本
                    all_text = ' '.join([msg.text for msg in messages])
                    # 计算整体情感均值
                    avg_sentiment = sum([msg.sentiment for msg in messages]) / len(messages)
                    # 提取关键词
                    keywords = extract_keywords(all_text)
                    # 生成会话摘要
                    summary = generate_summary(all_text)

                    analysis_data = {
                        'session_id': session_id,
                        'session_start': chat_session.start_time.strftime('%Y-%m-%d %H:%M:%S'),
                        'message_count': len(messages),
                        'avg_sentiment': round(avg_sentiment, 2),
                        'keywords': keywords,
                        'summary': summary,
                        'sentiment_trend': [{'time': msg.timestamp.strftime('%H:%M'), 'value': msg.sentiment} for msg in
                                            messages]
                    }

        return render_template('ai_analysis.html', analysis_data=analysis_data)

    # AI分析接口（供前端AJAX调用）
    @app.route('/api/ai_analysis', methods=['POST'])
    def api_ai_analysis():
        try:
            data = request.json
            text = data.get('text', '')
            if not text:
                return jsonify({'success': False, 'message': 'Text is required'}), 400

            # 执行AI分析
            sentiment = analyze_sentiment(text)
            keywords = extract_keywords(text)

            return jsonify({
                'success': True,
                'sentiment': round(sentiment, 2),
                'keywords': keywords,
                'sentiment_label': get_sentiment_label(sentiment)
            })
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)}), 500

    # 辅助函数：将情感值转换为标签
    def get_sentiment_label(sentiment):
        if sentiment > 0.5:
            return 'Positive'
        elif sentiment > 0:
            return 'Slightly Positive'
        elif sentiment < -0.5:
            return 'Negative'
        elif sentiment < 0:
            return 'Slightly Negative'
        else:
            return 'Neutral'

    # Socket.IO AI分析事件（实时分析）

    @app.route('/user_management')
    def user_management():
        if 'user_id' not in session or session['role'] != 'admin':
            flash('Permission denied', 'error')
            return redirect(url_for('login'))
        users = User.query.filter(User.is_deleted==False).all()
        return render_template('user_management.html', users=users)

    # 用户管理相关路由 - 仅管理员可访问
    @app.route('/admin/users/add', methods=['GET', 'POST'])
    def admin_add_user():
        # 权限验证
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Permission denied!', 'error')
            return redirect(url_for('login'))

        if request.method == 'POST':
            # 获取表单数据
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'user').strip()

            # 基础验证
            if not username or not password:
                flash('Username and password are required!', 'error')
                return render_template('admin/add_user.html')

            if role not in ['admin', 'agent', 'user']:
                flash('Invalid role type!', 'error')
                return render_template('admin/add_user.html')

            # 检查用户名是否已存在
            if User.query.filter_by(username=username).first():
                flash('Username already exists!', 'error')
                return render_template('admin/add_user.html')

            try:
                # 创建新用户
                new_user = User(
                    username=username,
                    password=password,  # 假设模型内部会自动加密
                    role=role
                )
                db.session.add(new_user)
                db.session.commit()
                flash(f'User {username} added successfully!', 'success')
                return redirect(url_for('dashboard'))  # 重定向到管理员面板
            except Exception as e:
                db.session.rollback()
                flash(f'Error adding user: {str(e)}', 'error')

        # GET请求：显示添加用户表单
        return render_template('admin/add_user.html')

    @app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
    def admin_edit_user(user_id):
        # 权限验证
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Permission denied!', 'error')
            return redirect(url_for('login'))

        # 获取用户信息
        user = User.query.get_or_404(user_id)

        # 不允许修改当前登录管理员自己的角色
        if user_id == session['user_id'] and request.method == 'POST' and request.form.get('role') != 'admin':
            flash("You can't change your own role to non-admin!", 'error')
            return url_for('user_management')

        if request.method == 'POST':
            # 获取表单数据
            new_username = request.form.get('username', '').strip()
            new_email = request.form.get('email', '').strip()
            new_role = request.form.get('role', 'user').strip()
            new_password = request.form.get('password', '').strip()

            # 验证角色
            if new_role not in ['admin', 'agent', 'user']:
                flash('Invalid role type!', 'error')
                return redirect(url_for('user_management'))

            try:
                # 更新用户名（如果有变化且不重复）
                if new_username and new_username != user.username:
                    if User.query.filter_by(username=new_username).first():
                        flash('Username already exists!', 'error')
                        return redirect(url_for('user_management'))
                    user.username = new_username

                # 更新角色
                user.role = new_role
                user.email = new_email

                # 更新密码（如果提供了新密码）
                if new_password:
                    user.set_password(new_password)  # 假设模型有此方法

                user.updated_at = datetime.now()
                db.session.commit()
                flash('User updated successfully!', 'success')
                return redirect(url_for('user_management'))
            except Exception as e:
                db.session.rollback()
                flash(f'Error updating user: {str(e)}', 'error')

        # GET请求：显示编辑表单
        return redirect(url_for('user_management'))

    # API: 获取所有用户数据（用于前端表格）
    @app.route('/api/admin/users')
    def api_get_users():
        if 'user_id' not in session or session.get('role') != 'admin':
            return jsonify({'error': 'Permission denied!'}), 403

        users = User.query.all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'role': user.role,
            'created_at': user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else None,
            'updated_at': user.updated_at.strftime('%Y-%m-%d %H:%M:%S') if user.updated_at else None
        } for user in users])

    @app.route('/api/sessions')
    def api_get_sessions():
        # 验证用户登录状态
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401

        # 获取查询参数
        status = request.args.get('status', 'all')  # active/ended/all
        role_filter = request.args.get('role')  # 可选角色筛选
        user_id_filter = request.args.get('user_id')  # 可选用户ID筛选

        # 基础查询
        query = ChatSession.query

        # 状态筛选
        if status == 'active':
            query = query.filter(ChatSession.end_time.is_(None))
        elif status == 'ended':
            query = query.filter(ChatSession.end_time.isnot(None))

        # 角色筛选（限制只能查看有权访问的会话）
        current_role = session['role']
        current_user_id = session['user_id']

        if current_role == 'user':
            # 普通用户只能查看自己的会话
            query = query.filter(ChatSession.user_id == current_user_id)
        elif current_role == 'agent':
            # 客服可以查看自己处理的和未分配的会话
            query = query.filter(
                (ChatSession.agent_id == current_user_id) |
                (ChatSession.agent_id.is_(None))
            )

        # 额外的用户ID筛选（如果提供）
        if user_id_filter and current_role in ['admin', 'agent']:
            query = query.filter(ChatSession.user_id == user_id_filter)

        # 角色筛选（如果提供且当前用户有权限）
        if role_filter and current_role == 'admin':
            # 管理员可以按用户角色筛选会话
            # 先获取该角色的所有用户ID
            role_user_ids = [user.id for user in User.query.filter_by(role=role_filter).all()]
            query = query.filter(ChatSession.user_id.in_(role_user_ids))

        # 按创建时间倒序排序
        query = query.order_by(ChatSession.start_time.desc())

        # 执行查询
        sessions = query.all()

        # 构建响应数据
        result = []
        for sess in sessions:
            # 获取最后一条消息
            last_msg = Message.query.filter_by(session_id=sess.id).order_by(Message.timestamp.desc()).first()

            # 获取用户信息
            user = User.query.get(sess.user_id) if sess.user_id else None
            agent = User.query.get(sess.agent_id) if sess.agent_id else None

            result.append({
                'id': sess.id,
                'user_id': sess.user_id,
                'user_name': user.username if user else None,
                'agent_id': sess.agent_id,
                'agent_name': agent.username if agent else None,
                'start_time': sess.start_time.isoformat() if sess.start_time else None,
                'end_time': sess.end_time.isoformat() if sess.end_time else None,
                'status': 'active' if not sess.end_time else 'ended',
                'last_message': last_msg.text if last_msg else None,
                'last_message_time': last_msg.timestamp.isoformat() if last_msg else None
            })

        return jsonify(result)