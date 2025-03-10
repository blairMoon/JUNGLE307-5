import jwt  # PyJWT: JWT 토큰 생성 및 검증
import flask  # Flask: 웹 프레임워크
from flask import Flask, render_template, request, jsonify  
from pymongo import MongoClient  # MongoDB 연결
from PIL import Image  # Pillow: 이미지 처리
import io  # 이미지 파일 처리를 위한 io 모듈

app = Flask(__name__)  # Flask 앱 생성

# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")  # 로컬 MongoDB 연결
db = client["week00"]  # 사용할 데이터베이스 선택

@app.route("/")
def home():
    return render_template("index.html", title="week00", message="Flask + Jinja2")

if __name__ == "__main__":
    app.run(debug=True)
