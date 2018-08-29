#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
__title__ = ''
__author__ = 'swl'
__mtime__ = '8/6/18'
"""

from flask import render_template, redirect, request, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User, db
from .forms import LoginForm, RegistrationForm, ChangeEmailForm, ChangePasswordForm, PassworResetForm, \
    PasswordResetRequestForm
from . import auth
from ..email import send_email_async


@auth.route('/login', methods=['GET', 'POST'])
def login():  # 登入用户
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verity_password(form.password.data):
            login_user(user, form.remember_me.data)
            # 用户访问未授权的URL时会显示登录表单，Flask-Login会把原地址保存在查询字符串
            # 的next参数中，这个参数可以从request.args字典中读取。
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():  # 登出用户
    logout_user()  # 删除并重设用户会话
    flash("You have been logged out.")
    return redirect(url_for("main.index"))


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,
                    username=form.username.data,
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()  # 提交数据库之后才能赋予新用户id值,而确认令牌需要用到id,所以不能延后提交。
        token = user.generate_confirmation_token()
        send_email_async(user.email, 'Confirm Your Account',
                         'auth/email/confirm', user=user, token=token)
        flash("A confirmation email has been sent to you by email.")
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')  # 确认用户的账户
@login_required  # Flask-Login提供的login_required修饰器会保护这个路由，需要用户先登录，才能访问这个路由
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash("You have confirmed your account.Thanks!")
    else:
        flash("The confirmation link is invalid or has expired.")
    return redirect(url_for('main.index'))


@auth.before_app_request  # 在before_app_request 处理程序中过滤未确认的账户
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed and \
                request.endpoint[:5] != 'auth.' and \
                request.endpoint != 'static':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email_async(current_user.email, 'Confirm Your Account',
                     'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verity_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            db.session.commit()
            flash("Your password has been updated.")
            return redirect(url_for('main.index'))
        else:
            flash("Invalid password.")
    return render_template("auth/change_password.html", form=form)


@auth.route('/reset', methods=['GET', 'POST'])
@login_required
def password_reset_request():
    # if not current_user.is_anonymous:
    #    return redirect(url_for('main.index'))
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email_async(user.email, 'Reset Your Password',
                             'auth/email/reset_password', user=user, token=token)
        flash("An Email with instructions to reset your password has been sent to you.")
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])
@login_required
def password_reset(token):
    if not current_user.is_anonymous:
        return redirect(url_for('main.index'))
    form = PassworResetForm()
    if form.validate_on_submit():
        if User.reset_password(token, form.password.data):
            db.session.commit()
            flash("Your password has been updated.")
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email_request():
    form = ChangeEmailForm()
    if form.validate_on_submit():
        if current_user.verity_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_email_change_token(new_email)
            send_email_async(new_email, 'Confirm your email address',
                             'auth/email/change_email', user=current_user, token=token)
            flash("An email with instructions to confirm your new address has been sent to you.")
            return redirect(url_for('main.index'))
        else:
            flash("Invalid email or password.")
    return render_template("auth/change_email.html", form=form)


@auth.route('/change_email/<token>', methods=['GET', 'POST'])
@login_required
def change_email(token):
    if current_user.change_email(token):
        db.session.commit()
        flash("Your email address has been update.")
    else:
        flash("Invalid request.")
    return redirect(url_for('main.index'))
