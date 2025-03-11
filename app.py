import re
import datetime 
import os
import bcrypt # 비밀번호 암호화
from bson import ObjectId
import jwt  # PyJWT: JWT 토큰 생성 및 검증
from functools import wraps
from flask import Flask, render_template, request, jsonify , redirect, url_for ,send_from_directory
from pymongo import MongoClient  # MongoDB 연결
from PIL import Image  # Pillow: 이미지 처리
from werkzeug.utils import secure_filename  # 파일 명 암호화

app = Flask(__name__)  # Flask 앱 생성
app.config["SECRET_KEY"] = "JUNGLEKRAFTONWEEKZEROJUNGLEKRAFTONWEEKZERO"
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# ✅ 파일 확장자 검증 함수
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ JSON & FormData 요청을 처리하는 함수
def parse_request_data():
    #  JSON 및 FormData 요청을 자동으로 처리하여 딕셔너리 반환 #
    if request.content_type.startswith("application/json"):
        data = request.get_json()
    elif request.content_type.startswith("multipart/form-data"):
        data = {key: request.form.get(key, "").strip() for key in request.form}
    else:
        return None, jsonify({"message": "지원되지 않는 요청 형식입니다."}), 400

    # ✅ status 값 변환 (JSON에서도 문자열로 올 수 있음)
    data["status"] = str(data.get("status", "true")).lower() == "true"


     # ✅ 필수 필드 검사를 먼저 수행한 후, price 변환 진행
    if not data.get("title") and not data.get("category") and not data.get("description") and not data.get("image_url") and not data.get("price"):
        return None, jsonify({"message": "모든 필드를 입력해주세요."}), 400

    # ✅ price 값 변환 (필수 필드 검사 이후 실행)
    price_value = data.get("price", "").strip()
    if price_value:
        try:
            price_value = int(price_value)
            if price_value < 0:
                return None, jsonify({"message": "가격은 0 이상의 숫자로 입력해야 합니다."}), 400
        except ValueError:
            return None, jsonify({"message": "가격은 숫자로 입력해야 합니다."}), 400
    else:
        price_value = 0  # 기본값 설정

    data["price"] = price_value  # 변환된 값 적용

    return data, None, None  # 정상적인 데이터 반환



# MongoDB 연결
client = MongoClient("mongodb://localhost:27017/")  # 로컬 MongoDB 연결
db = client["week00"]  # 사용할 데이터베이스 선택
users_collection = db["users"]  # 회원가입에 필요한 유저 테이블
posts_collection = db["posts"]  # 게시글 테이블
comments_collection = db["comments"]  # 댓글 테이블

# 기수명 정규식 패턴
GISU_PATTERN = re.compile(r"^[0-9]{1,2}기-[0-9]{2}$")

# 패스워드 정규식 패턴
PASSWORD_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$")


# JWT 발급
def generate_jwt(student_name):
    payload = {
        "username": student_name,
        "exp": datetime.datetime.now() + datetime.timedelta(hours=1)  # 만료 시간 지정
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")  # HS256 알고리즘 사용
    return token

# JWT 인증 데코레이터 추가
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("Authorization")  # JWT를 Authorization 헤더에서 가져옴
        if not token:
            return jsonify({"message": "인증이 필요합니다. 로그인 후 이용해주세요."}), 401

        try:
            token = token.split(" ")[1]  # "Bearer {token}" 형태에서 토큰만 추출
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user = payload  #  현재 사용자 정보 저장
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "토큰이 만료되었습니다. 다시 로그인하세요."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "유효하지 않은 토큰입니다."}), 401

        return f(*args, **kwargs)
    
    return decorated_function



# 메인 페이지
@app.route("/")
def home():
    return render_template("index.html", title="week00", message="MainPage")

# 회원가입 메소드
@app.route("/api/auth/signup", methods=["POST"])
def register():
    data = request.get_json()  # 안전하게 JSON 데이터 가져오기
    lab_name = data.get("lab_name") # 랩 명
    cohort_name = data.get("cohort_name") # 기수 명(번호)
    password = data.get("password") # 비밀번호
    password_confirm = data.get("password_confirm")  # 추가된 필드
    student_name = data.get("student_name") # 이름

    # 필수 데이터 확인
    if not (lab_name and cohort_name and password and password_confirm and student_name):
        return jsonify({"message": "모든 필드를 입력해주세요"}), 400
    
    # 이름 필드 확인
    if not student_name:
        return jsonify({"message": "이름을 입력해주세요"}), 400

    # 비밀번호 & 비밀번호 확인 일치 여부 체크
    if password != password_confirm:
        return jsonify({"message": "비밀번호가 일치하지 않습니다."}), 400

    # 기수명(cohort_name) 형식 검증
    if not GISU_PATTERN.match(cohort_name):
        return jsonify({"message": "유효하지 않은 기수명 형식입니다."}), 400
    
    # 비밀번호 형식 검증
    if not PASSWORD_PATTERN.match(password):
        return jsonify({"message": "비밀번호는 영문 + 숫자 조합 8자 이상이어야 합니다."}), 400

    
    # 유저 중복 확인 (닉네임 중복 체크)
    nickname = f"{lab_name} {cohort_name}"  # 닉네임 생성
    if users_collection.find_one({"nickname": nickname}):
        return jsonify({"message": "이미 사용중인 닉네임(기수명)입니다"}), 400
    
    # 비밀번호 해싱 (bcrypt 사용)
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # MongoDB 저장
    user_data= {
        "lab_name" : lab_name,
        "cohort_name" : cohort_name,
        "student_name" : student_name,
        "nickname": nickname,
        "password" : hashed_password
    }
    users_collection.insert_one(user_data)

    return jsonify({"message" : "회원가입 성공 !"}), 200
    


# 로그인 메소드
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()  # 요청에서 JSON 데이터 가져오기
    lab_name = data.get("lab_name")
    cohort_name = data.get("cohort_name")
    password = data.get("password")

    # 유저 검색 (userId = userType + userNumber)
    user = users_collection.find_one({"lab_name": lab_name, "cohort_name": cohort_name})
    
    # 랩 명 입력값 확인
    if not lab_name:
        return jsonify({"message": "랩 명을 선택해주세요"}), 400
    
    # 기수명 입력값 확인
    if not cohort_name:
        return jsonify({"message": "기수명을 입력해주세요. 기수명 형식은 (숫자)+기- +(숫자) 입니다"}), 400

    # 기수명(cohort_name) 형식 검증
    if not GISU_PATTERN.match(cohort_name):
        return jsonify({"message": "유효하지 않은 기수명 형식입니다."}), 400
    
    # 유저 검증
    if not user:
        return jsonify({"message": "존재하지 않는 계정입니다"}), 401
    
    # 패스워드 입력값 검증
    if not password:
        return jsonify({"message": "비밀번호를 입력해주세요"}), 401

    # 비밀번호 검증
    if not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return jsonify({"message": "비밀번호가 틀렸습니다"}), 401

    # JWT 토큰 생성
    payload = {
        "userId": str(user["_id"]),  # 고유한 사용자 ID (MongoDB ObjectId)
        "nickname": f"{lab_name} {cohort_name}",  # 사용자의 표시 이름 (닉네임)
        "student_name": user["student_name"],  # 사용자 이름
        "exp": datetime.datetime.now() + datetime.timedelta(hours=1)  # 토큰 만료 시간
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"message": "로그인 성공!", "token": token}), 200



if __name__ == "__main__":
    app.run(debug=True, port=5001)
