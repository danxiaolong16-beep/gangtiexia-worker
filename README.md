# 免费分担计划 - 给钢铁侠加算力

目标：不用绑卡，先薅到 AI 电脑 + 一台 24小时小服务器，帮钢铁侠分担 GitHub 学习 / 跑脚本的活。

## 1. AI 电脑（不用卡，马上能试）
- Google Colab：上传 `colab-gpu-test.ipynb`，运行时选 GPU (T4)，跑通 `nvidia-smi` + torch 就算成功。每周 15-30 小时。
- Kaggle：上传同名笔记本，Settings 里开 GPU，每周固定 30 小时。注意开 GPU 时默认断网，先把依赖和模型下好再开。

## 2. 24小时小服务器（不用卡）
- Render 免费版：用 GitHub 账号登录，把这个文件夹推到 GitHub，Render 选 Web Service，自动认 `render.yaml`。
- 每月 750 小时免费，闲置 15 分钟会休眠，第一次访问唤醒约 1 分钟。适合挂轻量服务、定时触发，不适合一直高负载。
- 已备好 `app.py`：`/` 是状态页，`/health` 是健康检查，`/run` 是测试任务入口。

## 3. 注册顺序（我帮你走浏览器也行）
1. Google 账号 -> Colab / Kaggle，验证 GPU
2. GitHub 账号 -> Render，部署 app.py
3. 跑通后记下来：哪个账号、哪个区、剩余额度，下次直接用

## 4. 备选（有卡再说）
Oracle Always Free 永久 2核12GB，但要卡做 $1 验证，热门区经常没库存，闲置 7 天可能被回收。
