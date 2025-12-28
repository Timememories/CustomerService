from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, UTC
from werkzeug.security import generate_password_hash, check_password_hash
import re
from typing import Optional

# 初始化数据库实例
db = SQLAlchemy()


class User(db.Model):
    """
    用户模型（扩充版）
    包含：基础字段、密码加密、时间审计、权限控制、数据验证、常用方法
    """
    __tablename__ = 'users'  # 显式指定表名（复数，避免歧义）

    # 核心字段（基础扩充）
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False, comment='用户名（唯一）')
    password = db.Column(db.String(255), nullable=False, comment='加密后的密码')
    role = db.Column(db.String(10), nullable=False, default='user', comment='角色：admin/agent/user')

    # 扩展字段（实际业务常用）
    email = db.Column(db.String(120), unique=True, nullable=True, comment='邮箱（可选，唯一）')
    phone = db.Column(db.String(11), unique=True, nullable=True, comment='手机号（可选，唯一）')
    real_name = db.Column(db.String(30), nullable=True, comment='真实姓名')
    avatar = db.Column(db.String(255), nullable=True, comment='头像URL')
    is_active = db.Column(db.Boolean, default=True, comment='是否激活（禁用/启用）')
    is_deleted = db.Column(db.Boolean, default=False, comment='软删除标记')

    # 时间审计字段（修复 utcnow 弃用警告）
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), comment='创建时间（UTC）')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC),
                           comment='更新时间')
    last_login_at = db.Column(db.DateTime, nullable=True, comment='最后登录时间')

    # 关联关系（明确外键，消除歧义）
    # 1. 用户发起的聊天会话（关联 ChatSession.user_id）
    initiated_chat_sessions = db.relationship(
        'ChatSession',
        foreign_keys='ChatSession.user_id',
        back_populates='initiator',
        lazy=True,
        cascade='all, delete-orphan'
    )
    # 2. 用户作为客服处理的会话（关联 ChatSession.agent_id）
    handled_chat_sessions = db.relationship(
        'ChatSession',
        foreign_keys='ChatSession.agent_id',
        back_populates='handler',
        lazy=True,
        cascade='all, delete-orphan'
    )
    # 3. 用户发起的预约
    applied_appointments = db.relationship(
        'Appointment',
        foreign_keys='Appointment.user_id',
        back_populates='applicant',
        lazy=True
    )
    # 4. 用户作为客服被分配的预约
    assigned_appointments = db.relationship(
        'Appointment',
        foreign_keys='Appointment.agent_id',
        back_populates='assigned_agent',
        lazy=True
    )
    # 5. 好友关系 - 我发起的好友请求
    friend_requests_sent = db.relationship(
        'FriendRelation',
        foreign_keys='FriendRelation.user_id',
        back_populates='user',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )
    # 6. 好友关系 - 我收到的好友请求
    friend_requests_received = db.relationship(
        'FriendRelation',
        foreign_keys='FriendRelation.friend_id',
        back_populates='friend',
        lazy='dynamic',
        cascade='all, delete-orphan'
    )

    def __init__(self, username: str, password: str, role: str = 'user',
                 email: Optional[str] = None, phone: Optional[str] = None, **kwargs):
        """初始化用户（自动加密密码）"""
        self.username = username
        self.set_password(password)
        self.role = role
        self.email = email
        self.phone = phone
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def set_password(self, password: str) -> None:
        """设置密码（加密存储+强度验证）"""
        self._validate_password_strength(password)
        self.password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    def check_password(self, password: str) -> bool:
        """验证密码是否正确"""
        return check_password_hash(self.password, password)

    def _validate_password_strength(self, password: str) -> None:
        """密码强度验证（自定义规则）"""
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r'[0-9]', password):
            raise ValueError("Password must contain at least one numeric digit")

    def update_last_login(self) -> None:
        """更新最后登录时间"""
        self.last_login_at = datetime.now(UTC)
        db.session.commit()

    def is_admin(self) -> bool:
        """判断是否为管理员"""
        return self.role == 'admin' and self.is_active and not self.is_deleted

    def is_agent(self) -> bool:
        """判断是否为客服人员"""
        return self.role == 'agent' and self.is_active and not self.is_deleted

    def soft_delete(self) -> None:
        """软删除用户（不物理删除）"""
        self.is_deleted = True
        self.is_active = False
        db.session.commit()

    def to_dict(self) -> dict:
        """将用户信息转为字典（用于接口返回，隐藏敏感字段）"""
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'email': self.email,
            'phone': self.phone,
            'real_name': self.real_name,
            'avatar': self.avatar,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'last_login_at': self.last_login_at.strftime('%Y-%m-%d %H:%M:%S') if self.last_login_at else None
        }

    def __repr__(self) -> str:
        """模型字符串表示（便于调试）"""
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=True, comment='服务名称（唯一）')
    description = db.Column(db.Text, comment='服务描述')
    code = db.Column(db.String(50), unique=True, nullable=False, comment='服务编码（如：SV_001）')
    type = db.Column(db.String(20), default='consult', comment='服务类型：consult/reserve/complaint')
    status = db.Column(db.String(10), default='online', comment='状态：online/offline/maintenance')
    duration = db.Column(db.Integer, default=30, comment='服务时长（分钟）')
    price = db.Column(db.Float, default=0.0, comment='服务价格（元）')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), comment='创建时间')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC),
                           comment='更新时间')

    # 关联关系：双向匹配，无重复 backref
    chat_sessions = db.relationship(
        'ChatSession',
        back_populates='service',
        lazy=True
    )
    appointments = db.relationship(
        'Appointment',
        back_populates='service',
        lazy=True
    )

    def is_online(self) -> bool:
        """判断服务是否在线"""
        return self.status == 'online'

    def update_status(self, new_status: str) -> None:
        """更新服务状态（含合法性校验）"""
        valid_status = ['online', 'offline', 'maintenance']
        if new_status not in valid_status:
            raise ValueError(f"无效状态！仅支持：{valid_status}")
        self.status = new_status
        db.session.commit()

    def to_dict(self) -> dict:
        """模型转字典（接口返回）"""
        return {
            'id': self.id,
            'name': self.name,
            'code': self.code,
            'description': self.description,
            'type': self.type,
            'status': self.status,
            'duration': self.duration,
            'price': self.price
        }

    def __repr__(self) -> str:
        return f"<Service(id={self.id}, name='{self.name}', status='{self.status}')>"


class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, comment='预约用户ID')
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=False, comment='服务ID')
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, comment='分配的客服ID')
    date = db.Column(db.DateTime, nullable=False, comment='预约时间')
    status = db.Column(db.String(20), default='pending', comment='状态：pending/confirmed/canceled/completed')
    rating = db.Column(db.Integer, nullable=True, comment='评分（1-5分）')
    remark = db.Column(db.Text, nullable=True, comment='预约备注')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), comment='创建时间')
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC),
                           comment='更新时间')

    # 关联关系：双向匹配，无重复
    applicant = db.relationship('User', foreign_keys=[user_id], back_populates='applied_appointments', lazy=True)
    service = db.relationship('Service', back_populates='appointments', lazy=True)
    assigned_agent = db.relationship('User', foreign_keys=[agent_id], back_populates='assigned_appointments', lazy=True)
    chat_session = db.relationship(
        'ChatSession',
        back_populates='appointment',
        lazy=True,
        uselist=False
    )

    def update_status(self, new_status: str, agent_id: Optional[int] = None) -> None:
        """更新预约状态（含合法性校验）"""
        valid_status = ['pending', 'confirmed', 'canceled', 'completed']
        if new_status not in valid_status:
            raise ValueError(f"无效状态！仅支持：{valid_status}")

        if new_status == 'confirmed' and not agent_id:
            raise ValueError("确认预约时必须指定客服ID")

        self.status = new_status
        if agent_id:
            self.agent_id = agent_id
        db.session.commit()

    def set_rating(self, rating: int) -> None:
        """设置评分（1-5分验证）"""
        if not (1 <= rating <= 5):
            raise ValueError("评分必须为1-5分")
        self.rating = rating
        db.session.commit()

    def is_valid_date(self) -> bool:
        """检查预约时间是否为未来时间"""
        return self.date > datetime.now(UTC)

    def to_dict(self) -> dict:
        """模型转字典（接口返回）"""
        return {
            'id': self.id,
            'user': self.applicant.to_dict() if self.applicant else None,
            'service': self.service.to_dict() if self.service else None,
            'agent': self.assigned_agent.to_dict() if self.assigned_agent else None,
            'date': self.date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status,
            'rating': self.rating,
            'remark': self.remark
        }

    def __repr__(self) -> str:
        return f"<Appointment(id={self.id}, user_id={self.user_id}, status='{self.status}')>"


class ChatSession(db.Model):
    __tablename__ = 'chat_sessions'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, comment='发起会话的用户ID')
    agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, comment='处理会话的客服ID')
    service_id = db.Column(db.Integer, db.ForeignKey('services.id'), nullable=True, comment='关联服务ID')
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointments.id'), nullable=True, comment='关联预约ID')
    start_time = db.Column(db.DateTime, default=lambda: datetime.now(UTC), comment='会话开始时间')
    end_time = db.Column(db.DateTime, nullable=True, comment='会话结束时间')
    status = db.Column(db.String(20), default='active', comment='状态：active/closed/timeout')
    last_message_time = db.Column(db.DateTime, nullable=True, comment='最后消息时间')

    # 关联关系：双向匹配，无重复
    initiator = db.relationship('User', foreign_keys=[user_id], back_populates='initiated_chat_sessions')
    handler = db.relationship('User', foreign_keys=[agent_id], back_populates='handled_chat_sessions')
    service = db.relationship('Service', back_populates='chat_sessions', lazy=True)
    appointment = db.relationship('Appointment', back_populates='chat_session', lazy=True)
    messages = db.relationship('Message', backref='chat_session', lazy=True, cascade='all, delete-orphan')

    def close_session(self) -> None:
        """结束会话"""
        self.status = 'closed'
        self.end_time = datetime.now(UTC)
        db.session.commit()

    def update_last_message_time(self) -> None:
        """更新最后消息时间"""
        self.last_message_time = datetime.now(UTC)
        db.session.commit()

    def get_duration(self) -> Optional[float]:
        """计算会话时长（分钟）"""
        if not self.end_time:
            return None
        duration = (self.end_time - self.start_time).total_seconds() / 60
        return round(duration, 2)

    def to_dict(self) -> dict:
        """模型转字典（接口返回）"""
        return {
            'id': self.id,
            'user': self.initiator.to_dict() if self.initiator else None,
            'agent': self.handler.to_dict() if self.handler else None,
            'service': self.service.to_dict() if self.service else None,
            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
            'status': self.status,
            'duration': self.get_duration(),
            'message_count': len(list(self.messages))  # 显式转列表，消除IDE类型警告
        }

    def __repr__(self) -> str:
        return f"<ChatSession(id={self.id}, user_id={self.user_id}, status='{self.status}')>"


class Message(db.Model):
    """消息模型（增强）"""
    __tablename__ = 'messages'  # 复数表名
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_sessions.id'), nullable=False, comment='会话ID')
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, comment='发送者ID')
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, comment='接收者ID')
    text = db.Column(db.Text, nullable=False, comment='消息内容')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC), comment='发送时间')
    sentiment = db.Column(db.Float, nullable=True, comment='情感分析得分（-1~1）')
    message_type = db.Column(db.String(10), default='text', comment='消息类型：text/image/file')
    is_read = db.Column(db.Boolean, default=False, comment='是否已读')
    file_url = db.Column(db.String(255), nullable=True, comment='文件/图片URL（非文本消息）')

    # 关联关系（明确外键）
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages', lazy=True)
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages', lazy=True)

    def mark_as_read(self) -> None:
        """标记消息已读"""
        self.is_read = True
        db.session.commit()

    def is_agent_message(self) -> bool:
        """判断是否为客服发送的消息"""
        return self.sender.role == 'agent' and self.sender.is_active

    def to_dict(self) -> dict:
        """模型转字典（接口返回）"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'sender': self.sender.to_dict() if self.sender else None,
            'receiver': self.receiver.to_dict() if self.receiver else None,
            'text': self.text,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'sentiment': self.sentiment,
            'message_type': self.message_type,
            'is_read': self.is_read,
            'file_url': self.file_url
        }

    def __repr__(self) -> str:
        return f"<Message(id={self.id}, session_id={self.session_id}, is_read={self.is_read})>"


class FriendRelation(db.Model):
    __tablename__ = 'friend_relations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending/accepted/rejected
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC))

    # 关键：添加双向关联关系
    user = db.relationship(
        'User',
        foreign_keys=[user_id],
        back_populates='friend_requests_sent',
        lazy=True
    )
    friend = db.relationship(
        'User',
        foreign_keys=[friend_id],
        back_populates='friend_requests_received',
        lazy=True
    )

    def to_dict(self):
        """转换为字典格式"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'friend_id': self.friend_id,
            'status': self.status,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
            'user': self.user.to_dict() if self.user else None,
            'friend': self.friend.to_dict() if self.friend else None
        }

    def __repr__(self):
        return f"<FriendRelation(id={self.id}, user_id={self.user_id}, friend_id={self.friend_id}, status='{self.status}')>"