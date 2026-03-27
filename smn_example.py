import logging
import os
import urllib
import base64
from logging.handlers import RotatingFileHandler

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from flask import Flask, request, jsonify

app = Flask(__name__)
LOG_DIR = os.getcwd()
LOG_FORMAT = '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - ' \
             'IP:%(remote_addr)s - Path:%(path)s - Method:%(method)s - %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
# 3. 配置日志处理器（按大小分割，避免日志文件过大）
# 日志文件路径：/opt/logs/api.log
log_handler = RotatingFileHandler(
    filename=os.path.join(LOG_DIR, 'api.log'),
    maxBytes=10 * 1024 * 1024,  # 单个日志文件最大 10MB
    backupCount=5,  # 最多保留 5 个备份文件
    encoding='utf-8'  # 支持中文，避免乱码
)
log_handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))

# 4. 配置日志级别（INFO：记录访问+错误；DEBUG：更详细；ERROR：仅错误）
app.logger.setLevel(logging.INFO)
app.logger.addHandler(log_handler)
# 给root logger也添加相同处理器，兼容logging.info()调用
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(log_handler)

endpoint = "https://smn.sa-fb-1.eihcs02.com"


@app.route('/api/notification', methods=['POST'])
def notification():
    """
    接收 SMN 通知的核心接口
    入参：JSON 格式，包含 subscribe_url、signature、topic_urn 等字段
    返回：统一格式的 JSON 响应
    """
    # 1. 构造日志上下文参数
    logging.info(request.get_json())
    extra_params = {
        'path': request.path,
        'method': request.method
    }

    try:
        # 2. 校验请求体是否为 JSON 格式
        if not request.is_json:
            error_msg = "请求体格式错误，必须为 JSON 格式"
            app.logger.error(error_msg, extra=extra_params)
            return jsonify({
                'code': 400,
                'message': error_msg,
                'data': None
            }), 400

        # 3. 解析 JSON 入参
        req_data = request.get_json()
        app.logger.info(f"接收 notification 入参：{req_data}", extra=extra_params)

        # 4. （可选）关键参数校验（按需添加）
        required_fields = ['type', 'topic_urn', 'timestamp']  # 必传字段示例
        missing_fields = [field for field in required_fields if field not in req_data]
        if missing_fields:
            error_msg = f"缺少必传字段：{','.join(missing_fields)}"
            app.logger.error(error_msg, extra=extra_params)
            return jsonify({
                'code': 400,
                'message': error_msg,
                'data': None
            }), 400

        # 5. 业务逻辑处理（此处可扩展：如验证签名、访问 subscribe_url 等）
        # 示例：提取关键字段
        notification_type = req_data.get('type')
        topic_urn = req_data.get('topic_urn')
        app.logger.info(f"处理 {notification_type} 类型通知，topic_urn：{topic_urn}", extra=extra_params)

        # 处理消息
        subscribe_url = req_data.get('subscribe_url')
        if notification_type == 'SubscriptionConfirmation':
            app.logger.info(f"开始访问订阅确认URL: {subscribe_url}", extra=extra_params)
            # 使用不校验SSL证书的方式发起GET请求
            response = requests.get(
                subscribe_url,
                verify=False,  # 关键参数：禁用SSL证书验证
                timeout=10  # 设置超时时间，避免长时间阻塞
            )
            app.logger.info(f"订阅确认URL访问成功，状态码: {response.status_code}", extra=extra_params)
        elif notification_type == 'Notification':
            # TODO
            app.logger.info(f"重新组织消息", extra=extra_params)

        # 6. 返回成功响应
        return jsonify({
            'code': 200,
            'message': 'notification 接收成功',
            'data': {
                'type': notification_type,
                'topic_urn': topic_urn,
                'message_id': req_data.get('message_id')
            }
        })

    except Exception as e:
        # 7. 捕获所有异常，记录详细日志
        error_msg = f"处理 notification 异常：{str(e)}"
        app.logger.error(error_msg, extra=extra_params, exc_info=True)  # 记录异常栈
        return jsonify({
            'code': 500,
            'message': '服务器内部错误',
            'data': None
        }), 500

def is_message_valid(signing_cert_url, signature, message):
    """
    验证消息签名有效性
    :param signing_cert_url: 证书URL地址
    :param signature: 待验证的Base64编码签名
    :param message: 消息字典
    :return: 验证成功返回True，失败返回False
    """
    try:
        # 从URL下载证书
        with urllib.request.urlopen(signing_cert_url) as response:
            cert_data = response.read()

        # 加载X.509证书
        cert = load_pem_x509_certificate(cert_data)

        # 获取证书公钥
        public_key = cert.public_key()

        # 构建待签名消息
        sign_message = build_sign_message(message)

        # 解码Base64签名
        sig_bytes = base64.b64decode(signature)

        # 使用SHA256withRSA/PSS进行验证
        public_key.verify(
            sig_bytes,
            sign_message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Verify success")
        return True

    except InvalidSignature:
        print("Verify failed")
        return False


def build_sign_message(msg):
    """
    根据消息类型构建签名消息
    :param msg: 消息字典
    :return: 格式化后的消息字符串
    """
    msg_type = msg.get("type")
    message = None

    if msg_type == "Notification":
        message = build_notification_message(msg)
    elif msg_type in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
        message = build_subscription_message(msg)

    return message


def build_subscription_message(msg):
    """
    构建订阅确认消息的签名字符串
    :param msg: 消息字典
    :return: 格式化后的消息字符串
    """
    # 使用列表收集字符串片段，效率高于字符串拼接
    message_parts = [
        "message",
        msg.get("message", ""),
        "message_id",
        msg.get("message_id", ""),
        "subscribe_url",
        msg.get("subscribe_url", ""),
        "timestamp",
        msg.get("timestamp", ""),
        "topic_urn",
        msg.get("topic_urn", ""),
        "type",
        msg.get("type", "")
    ]

    return "\n".join(message_parts) + "\n"


def build_notification_message(msg):
    """
    构建通知消息的签名字符串
    :param msg: 消息字典
    :return: 格式化后的消息字符串
    """
    message_parts = [
        "message",
        msg.get("message", ""),
        "message_id",
        msg.get("message_id", "")
    ]

    # 条件性添加subject字段（如果存在且不为空）
    subject = msg.get("subject")
    if subject:
        message_parts.extend(["subject", subject])

    # 添加固定字段
    message_parts.extend([
        "timestamp",
        msg.get("timestamp", ""),
        "topic_urn",
        msg.get("topic_urn", ""),
        "type",
        msg.get("type", "")
    ])

    return "\n".join(message_parts) + "\n"

if __name__ == '__main__':
    pass
