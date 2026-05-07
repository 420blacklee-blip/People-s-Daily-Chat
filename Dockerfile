FROM python:3.10-slim

# 创建非 root 用户 
RUN useradd -m -u 1000 user
USER user

# [关键修复] 设置环境变量，让系统能找到 uvicorn
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# 复制文件
COPY --chown=user . $HOME/app

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口并启动
EXPOSE 7860
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]