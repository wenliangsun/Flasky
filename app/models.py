#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'swl'
__mtime__ = '8/6/18'
"""

import hashlib
import bleach

from datetime import datetime
from flask_login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app, request
from markdown import markdown

from . import db

from . import login_manager


@login_manager.user_loader  # 实现一个回调函数，使用指定的标识符加载用户。
def load_user(user_id):
    return User.query.get(int(user_id))  # 接收以Unicode字符串形式表示的用户标识符。如果能找到用户，返回用户对象，否则，返回None


class Permission:  # 权限常亮 (程序的权限)
    FOLLOW = 0x01  # 0b00000001 关注其他用户
    COMMENT = 0x02  # 0b00000010 在他人撰写的文章中发布评论
    WRITE_ARTICLES = 0x04  # 0b00000100 写原创文章
    MODERATE_COMMENTS = 0x08  # 0b00001000 查处他人发表的不当评论
    ADMINISTER = 0x80  # 0b10000000 管理网站


class Role(db.Model):
    __tablename__ = "roles"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship("User", backref='role', lazy='dynamic')

    # def __init__(self, **kwargs):
    #     super(Role, self).__init__(**kwargs)
    #     if self.permissions is None:
    #         self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |  # 普通用户
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |  # 中等权限用户
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)  # 管理员
        }
        # default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            # role.reset_permissions()
            # for perm in roles[r]:
            #     role.add_permission(perm)
            # role.default = role.name == default_role
            db.session.add(role)
        db.session.commit()

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def reset_permission(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    def __repr__(self):
        return "<User %r>" % self.name


class Follow(db.Model):  # 关注关联表的模型实现
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)  # 用户id
    email = db.Column(db.String(64), unique=True, index=True)  # 用户邮箱
    username = db.Column(db.String(64), unique=True, index=True)  # 用户名
    password_hash = db.Column(db.String(128))  # 加密的密码
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    name = db.Column(db.String(64))  # 真实姓名
    location = db.Column(db.String(64))  # 所在地
    about_me = db.Column(db.Text())  # 自我介绍
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)  # 注册时间
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)  # 最后访问日期
    avatar_hash = db.Column(db.String(32))  # 头像的hash值
    posts = db.relationship('Post', backref='author', lazy='dynamic')
    confirmed = db.Column(db.Boolean, default=False)  # 是否确认

    followed = db.relationship('Follow', foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all,delete-orphan')
    followers = db.relationship('Follow', foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all,delete-orphan')

    comments = db.relationship("Comment", backref='author', lazy='dynamic')

    def __init__(self, **kwargs):  # 定义默认的用户角色
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
            if self.email is not None and self.avatar_hash is None:
                self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
            # TODO 这儿有BUG，待解决！！！
            # self.follow(self)

    @staticmethod
    def add_self_follows():  # 更新数据库，把用户设为自己的关注者
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def can(self, permissions):
        return self.role is not None and (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verity_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def ping(self):
        """
        每次收到用户的请求时都要调用 ping() 方法。由于 auth 蓝本中的 before_app_request
        处理程序会在每次请求前运行,所以能很轻松地实现这个需求
        """
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = "https://secure.gravatar.com/avatar"
        else:
            url = 'http://www.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    @property
    def followed_posts(self):  # 获取所关注用户的文章
        return Post.query.join(Follow, Follow.followed_id == Post.author_id).filter(Follow.follower_id == self.id)

    @staticmethod
    def generate_fake(count=100):  # 生成虚拟用户和博客文章
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password=forgery_py.lorem_ipsum.word(),
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(follower_id=user.id).first() is not None

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):  # 是的匿名用户的操作与登录用户一致
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Post(db.Model):  # 文章模型
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    comments = db.relationship("Comment", backref='post', lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Post(body=forgery_py.lorem_ipsum.sentences(randint(1, 3)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    # TODO 这个函数不清楚！！！
    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p']
        target.body_html = bleach.linkify(bleach.clean(markdown(value, output_format='html'),
                                                       tags=allowed_tags, strip=True))


db.event.listen(Post.body, 'set', Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)  # 协管理员通过这个字段查禁不当评论
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'))

    # TODO 这个函数不清楚！！！
    @staticmethod
    def on_change_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code',
                        'em', 'i', 'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'), tags=allowed_tags, strip=True))


db.event.listen(Comment.body, 'set', Comment.on_change_body)
