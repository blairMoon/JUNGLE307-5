import re
import datetime 
import os
import bcrypt # 비밀번호 암호화
from bson import ObjectId
import jwt  # PyJWT: JWT 토큰 생성 및 검증
from functools import wraps
from flask import Flask, render_template, request, jsonify , redirect, url_for ,send_from_directory, make_response
# from routes import routes 
from pymongo import MongoClient  # MongoDB 연결
from werkzeug.utils import secure_filename  # 파일 명 암호화
import re
from flask import flash, get_flashed_messages
from flask_cors import CORS

app = Flask(__name__)  # Flask 앱 생성
CORS(app, supports_credentials=True)
app.config["SECRET_KEY"] = "JUNGLEWEEKZEROJUNGLEWEEKZEROJUNGLEWEEKZERO"
# Blueprint 등록
@app.route("/")
def home():
    access_token = request.cookies.get("access_token")

    if access_token:
        try:
            jwt.decode(access_token, app.config["SECRET_KEY"], algorithms=["HS256"])
            return redirect(url_for("main_page"))
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            response = make_response(render_template("auth/login.html"))
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return response

    return render_template("auth/login.html")

    # ❌ 토큰이 없으면 로그인 페이지 보여주기
    return render_template("auth/login.html")
COHORT_PATTERN = re.compile(r'^[0-9]{1,2}기-(?:[1-9]|[1-9][0-9]|[1-9][0-9]{2})$')

PASSWORD_PATTERN = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$')
UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
# @app.route("/list")
# def post_list():
#     return render_template("post/list.html")
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

# JWT 인증 데코레이터
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get("access_token")  # ✅ 쿠키에서 JWT 가져오기
        if not token:
            return jsonify({"message": "로그인이 필요합니다."}), 401

        try:
            payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            request.user = payload  # ✅ 현재 사용자 정보 저장
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "토큰이 만료되었습니다. 다시 로그인하세요."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "유효하지 않은 토큰입니다."}), 401

        return f(*args, **kwargs)
    return decorated_function

# ✅ 현재 로그인한 사용자 정보 가져오기
def get_jwt_identity():
    return request.user["userId"] if hasattr(request, "user") else None


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



# SSR 사용 : 게시글 조회, 로그인, 회원가입, 상세페이지 조회, 마이페이지 조회
# CSR 사용 : 댓글, 대댓글
# token : refreshToken, AccessToken 사용 

# @app.route("/mypage")
# def mypage():
#     return render_template("/mypage/mypage.html")
################################################################################
# @app.route("/register-success")
# def register_success():
#     return render_template("register_success.html")
################################################################################

@app.route("/posts/new")
@jwt_required
def create_post_page():
    return render_template("post/create.html")

# 로그인 알림 페이지 라우트
@app.route("/login-alert")
def login_alert():
    return render_template("loginAlert.html")

# Base
@app.route("/base")
def base():
    return render_template("base.html")

######################################## 회원가입 & 로그인 (SSR) ########################################

# ✅ 회원가입 페이지 렌더링
# @app.route("/signup")
# def signup_page():
#     return render_template("/auth/signup.html")

# ✅ 로그인 페이지 렌더링
# @app.route("/login")
# def login_page():
#     return render_template("auth/login.html")

# ✅ 회원가입 (SSR)

@app.route("/register", methods=["GET", "POST"])

def register():
    access_token = request.cookies.get("access_token")

    # ✅ 로그인 되어 있으면 회원가입 페이지 접근 못하게 막기
    if access_token:
        try:
            jwt.decode(access_token, app.config["SECRET_KEY"], algorithms=["HS256"])
            return redirect(url_for("main_page"))  # 이미 로그인했으니까 메인으로 보내버려!
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass
    if request.method == "GET":
        return render_template("auth/register.html")

    # ✅ POST 요청일 때만 실행
    lab_name = request.form.get("lab_name")
    cohort_name = request.form.get("cohort_name")
    student_name = request.form.get("student_name")
    password = request.form.get("password")
    password_confirm = request.form.get("password_confirm")

    # ✅ 필수 값 검사
    if not all([lab_name, cohort_name, student_name, password, password_confirm]):
        flash("❌ 모든 필드를 입력해주세요.")
        return redirect(url_for("register"))

    # ✅ 정규식 검사
    if not COHORT_PATTERN.match(cohort_name):
        flash("❌ 기수명 형식이 올바르지 않습니다. 예: 8기-76")
        return redirect(url_for("register"))

    if not PASSWORD_PATTERN.match(password):
        flash("❌ 비밀번호는 영문 + 숫자 조합 8자 이상이어야 합니다.")
        return redirect(url_for("register"))

    # ✅ 비밀번호 일치 검사
    if password != password_confirm:
        flash("❌ 비밀번호가 일치하지 않습니다.")
        return redirect(url_for("register"))

    # ✅ 닉네임 중복 검사
    nickname = f"{lab_name} {cohort_name}"
    if users_collection.find_one({"nickname": nickname}):
        flash("❌ 이미 사용중인 닉네임(기수명)입니다.")
        return redirect(url_for("register"))

    # ✅ DB 저장
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users_collection.insert_one({
        "lab_name": lab_name,
        "cohort_name": cohort_name,
        "student_name": student_name,
        "nickname": nickname,
        "password": hashed_password
    })

    flash("✅ 회원가입이 완료되었습니다! 로그인해주세요.")
    return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("register.html")  # 처음 진입 시 폼 보여주기

    # ✅ POST일 때만 아래 코드 실행!
    lab_name = request.form.get("lab_name")
    cohort_name = request.form.get("cohort_name")
    student_name = request.form.get("student_name")
    password = request.form.get("password")
    password_confirm = request.form.get("password_confirm")

    if not all([lab_name, cohort_name, student_name, password, password_confirm]):
        return render_template("register.html", error="❌ 모든 필드를 입력해주세요.")

    if not COHORT_PATTERN.match(cohort_name):
        return render_template("register.html", error="❌ 기수명 형식이 올바르지 않습니다. 예: 8기-76")

    if not PASSWORD_PATTERN.match(password):
        return render_template("register.html", error="❌ 비밀번호는 영문 + 숫자 조합 8자 이상이어야 합니다.")

    if password != password_confirm:
        return render_template("register.html", error="❌ 비밀번호가 일치하지 않습니다.")

    nickname = f"{lab_name} {cohort_name}"
    if users_collection.find_one({"nickname": nickname}):
        return render_template("register.html", error="❌ 이미 사용중인 닉네임(기수명)입니다.")

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users_collection.insert_one({
        "lab_name": lab_name,
        "cohort_name": cohort_name,
        "student_name": student_name,
        "nickname": nickname,
        "password": hashed_password
    })
    
    return redirect(url_for("login"))

    lab_name = request.form.get("lab_name")
    cohort_name = request.form.get("cohort_name")
    student_name = request.form.get("student_name")
    password = request.form.get("password")
    password_confirm = request.form.get("password_confirm")

    # ✅ 필수 값 검사
    if not all([lab_name, cohort_name, student_name, password, password_confirm]):
        return render_template("register.html", error="❌ 모든 필드를 입력해주세요.")

    # ✅ 정규식 검사
    if not COHORT_PATTERN.match(cohort_name):
        return render_template("register.html", error="❌ 기수명 형식이 올바르지 않습니다. 예: 8기-76")

    if not PASSWORD_PATTERN.match(password):
        return render_template("register.html", error="❌ 비밀번호는 영문 + 숫자 조합 8자 이상이어야 합니다.")

    # ✅ 비밀번호 일치 검사
    if password != password_confirm:
        return render_template("register.html", error="❌ 비밀번호가 일치하지 않습니다.")

    # ✅ 중복 닉네임 검사
    nickname = f"{lab_name} {cohort_name}"
    if users_collection.find_one({"nickname": nickname}):
        return render_template("register.html", error="❌ 이미 사용중인 닉네임(기수명)입니다.")

    # ✅ DB 저장
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    users_collection.insert_one({
        "lab_name": lab_name,
        "cohort_name": cohort_name,
        "student_name": student_name,
        "nickname": nickname,
        "password": hashed_password
    })

    return redirect(url_for("register"))
# ✅ 로그인 (SSR)
@app.route("/login", methods=["GET", "POST"])
def login():
    access_token = request.cookies.get("access_token")
    if access_token:
        try:
            jwt.decode(access_token, app.config["SECRET_KEY"], algorithms=["HS256"])
            return redirect(url_for("main_page"))
        except jwt.ExpiredSignatureError:
            pass
        except jwt.InvalidTokenError:
            pass
    if request.method == "GET":
        return render_template("auth/login.html")
    
    # POST 요청
    lab_name = request.form.get("lab_name")
    cohort_name = request.form.get("cohort_name")
    password = request.form.get("password")

    # ✅ 필수 입력 검사
    if not all([lab_name, cohort_name, password]):
        flash("❌ 모든 필드를 입력해주세요.")
        return redirect(url_for("login"))

    # ✅ 사용자 조회
    user = users_collection.find_one({
        "lab_name": lab_name,
        "cohort_name": cohort_name
    })

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        flash("❌ 아이디 또는 비밀번호가 잘못되었습니다.")
        return redirect(url_for("login"))

    # ✅ JWT 발급
    access_payload = {
        "userId": str(user["_id"]),
        "nickname": f"{lab_name} {cohort_name}",
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    }
    refresh_payload = {
        "userId": str(user["_id"]),
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)
    }

    access_token = jwt.encode(access_payload, app.config["SECRET_KEY"], algorithm="HS256")
    refresh_token = jwt.encode(refresh_payload, app.config["SECRET_KEY"], algorithm="HS256")

    # ✅ Refresh 토큰 DB에 저장
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"refresh_token": refresh_token}}
    )

    # ✅ 쿠키에 저장 후 list 페이지 이동
    response = make_response(redirect(url_for("main_page")))

    response.set_cookie("access_token", access_token, httponly=True, max_age=36000)
    response.set_cookie("refresh_token", refresh_token, httponly=True, max_age=604800)

    return response

    lab_name = request.form.get("lab_name")
    cohort_name = request.form.get("cohort_name")
    password = request.form.get("password")

    user = users_collection.find_one({"lab_name": lab_name, "cohort_name": cohort_name})
    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return render_template("auth/login.html", error="❌ 아이디 또는 비밀번호가 잘못되었습니다.")

    # ✅ JWT 토큰 생성 (직접 생성)
    access_payload = {
        "userId": str(user["_id"]),
        "nickname": f"{lab_name} {cohort_name}",
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)  # AccessToken: 1시간
    }
    refresh_payload = {
        "userId": str(user["_id"]),
        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=7)  # RefreshToken: 7일
    }

    access_token = jwt.encode(access_payload, app.config["SECRET_KEY"], algorithm="HS256")
    refresh_token = jwt.encode(refresh_payload, app.config["SECRET_KEY"], algorithm="HS256")

    # ✅ RefreshToken을 DB에 저장
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {"refresh_token": refresh_token}}
    )

    # ✅ 응답에 쿠키 저장 (HTTP-Only)
    response = make_response(redirect(url_for("main_page")))
    response.set_cookie("access_token", access_token, httponly=True, max_age=3600)
    response.set_cookie("refresh_token", refresh_token, httponly=True, max_age=604800)

    return response

@app.route("/api/check-duplicate", methods=["POST"])
def check_duplicate():
    try:
        data = request.get_json()
        lab_name = (data.get("lab_name") or "").strip()
        cohort_name = (data.get("cohort_name") or "").strip()

        # ✅ 필수 입력값 확인
        if not (lab_name and cohort_name):
            return jsonify({"error": "❌ 랩 이름과 기수명을 입력하세요."}), 400

        # ✅ 중복 검사
        nickname = f"{lab_name} {cohort_name}"
        is_duplicate = users_collection.find_one({"nickname": nickname}) is not None

        return jsonify({"is_duplicate": is_duplicate})

    except Exception as e:
        print(f"❌ [ERROR] 중복 검사 실패: {str(e)}")
        return jsonify({"error": "❌ 서버 오류 발생"}), 500


### ✅ 로그아웃 (쿠키 삭제)
@app.route("/logout", methods=["POST"])
def logout():
    response = make_response(jsonify({"message": "로그아웃 성공!"}), 200)
    response.set_cookie("access_token", "", expires=0)
    response.set_cookie("refresh_token", "", expires=0)
    return response


### ✅ 토큰 인증 미들웨어 (SSR에서 사용)
def get_current_user():
    token = request.cookies.get("access_token")
    if not token:
        return None

    try:
        decoded = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        user = users_collection.find_one({"_id": ObjectId(decoded["userId"])})
        return user
    except jwt.ExpiredSignatureError:
        return None  # 토큰 만료
    except jwt.InvalidTokenError:
        return None  # 유효하지 않은 토큰


@app.route("/list")
def main_page():
    try:
        # ✅ 로그인 여부 확인 (쿠키에서 access_token 가져오기)
        access_token = request.cookies.get("access_token")
        user_info = None

        if access_token:
            try:
                payload = jwt.decode(access_token, app.config["SECRET_KEY"], algorithms=["HS256"])
                user_info = {
                    "nickname": payload.get("nickname","익명"),
                    "userId": payload["userId"]
                }
            except jwt.ExpiredSignatureError:
                user_info = None  # 토큰 만료 시 로그아웃 처리

        # ✅ 카테고리 필터링 및 페이지네이션 처리
        category = request.args.get("category", "전체")  # 기본값: 전체
        page = int(request.args.get("page", 1))
        limit = 12
        skip = (page - 1) * limit

        query = {} if category == "전체" else {"category": category}  # ✅ 한글 필드 유지
        posts_cursor = posts_collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
        total_count = posts_collection.count_documents(query)

        posts = []
        print(posts_cursor)
        for post in posts_cursor:
            posts.append({
                "id": str(post["_id"]),
                "title": post["title"],
                "image_url": post.get("image_url", "/static/images/noimage.png"),  # 기본 이미지 적용
                "category": post["category"],  # ✅ 한글 그대로 사용
                "status": post["status"],
                "price": "무료" if post["price"] == 0 else f"{post['price']}원",
                "created_at": post["created_at"].strftime("%Y-%m-%d"),
                "nick_name": post["nickname"]
            })
        print(f"💥 카테고리: {category}, 페이지: {page}")

        return render_template(
            "post/list.html",
            posts=posts,
            total_count=total_count,
            current_category=category,  # ✅ 한글 카테고리 그대로 사용
            user_info=user_info
        )

    except Exception as e:
        print(f"❌ [ERROR] 메인 페이지 로드 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류 발생", "details": str(e)}), 500
    
@app.route("/posts/<post_id>")
@jwt_required  # ✅ 직접 구현한 JWT 인증 데코레이터 사용
def get_post_detail(post_id):
    try:
        user_id = get_jwt_identity()
        user = None
        user_info = None
        if user_id:  # 🔥 user_id가 None이 아닐 경우에만 조회
            user = users_collection.find_one({"_id": ObjectId(user_id)})
            if user:
                user_info = {
                    "nickname": user.get("nickname", "알 수 없음"),
                    "userId": str(user["_id"])
                }

        # ✅ 게시글 조회
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 댓글 조회 (로그인하지 않은 경우에도 볼 수 있도록 수정)
        comments_cursor = comments_collection.find({"post_id": ObjectId(post_id)})
        comments = []
        for comment in comments_cursor:
            comment_author = users_collection.find_one({"_id": comment["author_id"]}) if "author_id" in comment else None

            # ✅ 대댓글 조회 (replies 리스트가 있는 경우 가져오기)
            replies = []
            for reply in comment.get("replies", []):
                reply_author = users_collection.find_one({"_id": reply["author_id"]}) if "author_id" in reply else None
                replies.append({
                    "id": str(reply.get("_id")),
                   "writer": comment.get("writer", "익명"),
                    "content": reply.get("content", ""),
                    "created_at": reply.get("created_at", "").strftime("%Y-%m-%d"),
                    "is_author": str(reply.get("author_id")) == str(user_id) if user_id else False
                })
            print("🔥 comments 리스트:", comments)
            print(post)
            comments.append({
                "id": str(comment["_id"]),
                "writer": comment.get("writer", "익명"),
                "content": comment["content"],
                "created_at": comment["created_at"].strftime("%Y-%m-%d"),
                "is_author": str(comment["author_id"]) == str(user_id) if user_id else False , # ✅ 로그인하지 않은 경우에도 안전 처리
                "replies" : replies
            })

        return render_template(
            "post/detail.html",
            post={
                "id": str(post["_id"]),
                "title": post["title"],
                "image_url": post.get("image_url", "/static/images/noimage.png"),
                "category": post["category"],
                "status": "진행 중" if post["status"] else "완료",
                "price": "무료" if post["price"] == 0 else f"{post['price']}원",
                "description": post["description"],
                "created_at": post["created_at"].strftime("%Y-%m-%d"),
                "nick_name": post["nickname"]
            },
            comments=comments,
            user_info=user_info,  # ✅ user_info가 None이면 로그인되지 않은 상태
            is_author=str(post["author_id"]) == str(user_id) if user_id else False  # ✅ 로그인하지 않은 경우에도 False 처리
        )

    except Exception as e:
        print(f"❌ [ERROR] 상세페이지 조회 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류 발생", "details": str(e)}), 500
    

@app.route("/api/posts/<post_id>", methods=["PUT"])
@jwt_required
def edit_post(post_id):
    try:
        data = request.get_json()
        new_title = data.get("title", "").strip()
        new_description = data.get("description", "").strip()
        new_price = data.get("price", "").strip()

        # ✅ 최소 한 개의 필드라도 입력해야 함
        if not new_title and not new_description and not new_price:
            return jsonify({"error": "수정할 내용을 입력하세요."}), 400

        # ✅ 현재 로그인한 사용자 확인
        current_user_id = get_jwt_identity()

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 본인 게시글인지 확인
        if str(post["author_id"]) != str(current_user_id):
            return jsonify({"error": "권한이 없습니다."}), 403

        # ✅ 업데이트할 데이터 준비
        update_data = {}
        if new_title:
            update_data["title"] = new_title
        if new_description:
            update_data["description"] = new_description
        if new_price:
            try:
                price_value = int(new_price)
                if price_value < 0:
                    return jsonify({"error": "가격은 0 이상의 숫자로 입력해야 합니다."}), 400
                update_data["price"] = price_value
            except ValueError:
                return jsonify({"error": "가격은 숫자로 입력해야 합니다."}), 400

        # ✅ 게시글 업데이트 실행
        posts_collection.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": update_data}
        )

        return jsonify({"message": "게시글이 수정되었습니다."}), 200

    except Exception as e:
        print(f"❌ [ERROR] 게시글 수정 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류"}), 500

@app.route("/api/posts/<post_id>", methods=["DELETE"])
@jwt_required
def delete_post(post_id):
    try:
        # ✅ 현재 로그인한 사용자 확인
        current_user_id = get_jwt_identity()

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"error": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 본인 게시글인지 확인
        if str(post["author_id"]) != str(current_user_id):
            return jsonify({"error": "권한이 없습니다."}), 403

        # ✅ 게시글 삭제
        posts_collection.delete_one({"_id": ObjectId(post_id)})

        return jsonify({"message": "게시글이 삭제되었습니다."}), 200

    except Exception as e:
        print(f"❌ [ERROR] 게시글 삭제 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류"}), 500


### ✅ 마이페이지 (SSR 렌더링)
@app.route("/mypage")
@jwt_required
def mypage():
    try:
        user = get_current_user()
        if not user:
            return redirect(url_for("login_page"))  # 로그인 안 된 경우 로그인 페이지로 이동

        # ✅ 사용자가 작성한 게시글 목록 가져오기
        user_posts = list(posts_collection.find({"author_id": str(user["_id"])}).sort("created_at", -1))
        for post in user_posts:
            post["id"] = str(post["_id"])
            post["created_at"] = post["created_at"].strftime("%Y-%m-%d")

        post_count = len(user_posts)

        # ✅ 사용자가 작성한 댓글 목록 가져오기 (선택 사항)
        user_comments = list(comments_collection.find({"author_id": str(user["_id"])}).sort("created_at", -1))
        for comment in user_comments:
            comment["id"] = str(comment["_id"])
            comment["created_at"] = comment["created_at"].strftime("%Y-%m-%d")

        return render_template(
            "mypage/mypage.html",
            user=user,
            posts=user_posts,
            comments=user_comments,  # 필요 없으면 제외 가능
            post_count = post_count
        )

    except Exception as e:
        print(f"❌ [ERROR] 마이페이지 조회 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류 발생", "details": str(e)}), 500


######################################## 회원가입, 로그인  ########################################

######################################## 게시글  ########################################
# @app.route('/create')
# def create_post_route():
#     return render_template('post/create.html')



# ✅ JWT 인증 필요: 게시글 생성 (POST)
@app.route("/api/posts", methods=["POST"])
@jwt_required  
def create_post():
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({"message": "로그인이 필요합니다."}), 401

    nickname = request.user.get("nickname", "알 수 없음")  # 닉네임 기본값 설정
    # ✅ 요청 데이터 파싱
    data, error_response, error_status = parse_request_data()
    if error_response:
        print(f"❌ [ERROR] 요청 데이터 파싱 실패: {error_response}")  # 오류 로그 추가
        return error_response, error_status  # 오류 응답 반환
    
    print(f"✅ [DEBUG] 요청 데이터: {data}")  # ✅ 요청 데이터 로그 추가
    print(f"✅ [DEBUG] status 값: {data.get('status')}")
    print(f"✅ [DEBUG] price 값: {data.get('price')}")

    # ✅ 필수 필드 검증
    title = data.get("title", "").strip()
    category = data.get("category", "").strip()
    description = data.get("description", "").strip()
    price = data.get("price", 0) # 기본값 0 설정
    

    # ✅ 모든 필드가 비어 있는 경우 예외 처리
    if not title and not category and not description and not data.get("image_url") and price == 0:
        return jsonify({"message": "모든 필드를 입력해주세요."}), 400


    if not title:
        return jsonify({"message": "제목을 입력해주세요."}), 400
    if not category or category not in ["나눔해요", "필요해요"]:
        return jsonify({"message": "유효한 카테고리를 선택해주세요."}), 400
    if not description:
        return jsonify({"message": "내용을 입력해주세요."}), 400

    # ✅ 이미지 업로드 처리
    image_url = None
    if "image" in request.files:
        image = request.files["image"]
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(image_path)
            image_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"

    # ✅ 게시글 데이터 저장
    post = {
        "title": title,
        "image_url": image_url,
        "category": category,
        "status": True,
        "price": data.get("price", 0),
        "description": description,
        "created_at": datetime.datetime.now(),
        "nickname": nickname,
        "author_id": user_id,
        "comments": []
    }

    post_id = posts_collection.insert_one(post).inserted_id

    return jsonify({
        "message": "게시글이 등록되었습니다!"
    }), 201

# ✅ 업로드된 이미지 서빙 (Flask에서 정적 파일로 제공)
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)



@app.route("/create")
def create_page():
    mode = request.args.get("mode")
    post_id = request.args.get("id")

    post_data = None

    if mode == "edit" and post_id:
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return "게시글을 찾을 수 없습니다.", 404
        
        # 게시글 데이터를 템플릿에 넘길 수 있도록 변환
        post_data = {
            "id": str(post["_id"]),
            "title": post["title"],
            "category": post["category"],
            "price": post["price"],
            "description": post["description"],
            "image_url": post.get("image_url")
        }
    print("🌟 post_data:", post_data)
    print("🌟 mode:", mode)
    # 👉 post와 mode를 넘겨줘야 템플릿에서 사용할 수 있어!
    return render_template("post/create.html", post=post_data, mode=mode)
@app.route("/api/posts/<post_id>", methods=["PATCH"])
@jwt_required
def update_post(post_id):
    user_id = get_jwt_identity()

    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({"message": "게시글이 존재하지 않습니다."}), 404

    if str(post["author_id"]) != str(user_id):
        return jsonify({"message": "수정 권한이 없습니다."}), 403

    # 요청 파싱
    data, error_response, error_status = parse_request_data()
    if error_response:
        return error_response, error_status

    title = data.get("title", "").strip()
    category = data.get("category", "").strip()
    description = data.get("description", "").strip()
    price = data.get("price", 0)

    update_data = {
        "title": title,
        "category": category,
        "description": description,
        "price": price,
    }

    # 이미지가 있을 경우만 업데이트
    if "image" in request.files:
        image = request.files["image"]
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(image_path)
            image_url = f"/{app.config['UPLOAD_FOLDER']}/{filename}"
            update_data["image_url"] = image_url

    posts_collection.update_one({"_id": ObjectId(post_id)}, {"$set": update_data})

    return jsonify({"message": "게시글이 수정되었습니다!"}), 200
    
######################################## 게시글  ########################################    

########################################  댓글, 대댓글  ########################################

# ✅ 댓글 작성
@app.route("/api/posts/<post_id>/comments", methods=["POST"])
@jwt_required
def add_comment(post_id):
    user_id = get_jwt_identity()
    if not user_id:
        return jsonify({"message": "로그인이 필요합니다."}), 401

    user = users_collection.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({"message": "사용자 정보를 찾을 수 없습니다."}), 404

    # ✅ 해당 게시글 가져오기
    post = posts_collection.find_one({"_id": ObjectId(post_id)})
    if not post:
        return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

    data = request.get_json()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"message": "댓글 내용을 입력해주세요."}), 400
    
    # ✅ 현재 사용자가 게시글 작성자인지 확인
    is_author = str(post["author_id"]) == str(user["_id"])

    # ✅ `writer` 값을 "작성자" 또는 본인 닉네임으로 설정
    writer = "작성자"  if is_author else user["nickname"]

    comment = {
        "post_id": ObjectId(post_id),
        "author_id": ObjectId(user_id),
        "writer": writer,  # ✅ 닉네임 추가
        "content": content,
        "isAuthor": is_author,  # ✅ 게시글 작성자인지 여부 추가
        "created_at": datetime.datetime.now(),
        "replies": []  # 🔥 대댓글 리스트 추가
    }

    comments_collection.insert_one(comment)
    return jsonify({"message": "댓글이 등록되었습니다!"}), 201


# ✅ 대댓글 작성
@app.route("/api/posts/<post_id>/comments/<comment_id>/replies", methods=["POST"])
@jwt_required
def add_reply(post_id, comment_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get("content", "").strip()

    if not content:
        return jsonify({"message": "대댓글 내용을 입력해주세요."}), 400

    reply = {
        "author_id": ObjectId(user_id),
        "content": content,
        "created_at": datetime.datetime.now()
    }

    comments_collection.update_one(
        {"_id": ObjectId(comment_id)},
        {"$push": {"replies": reply}}  # 🔥 대댓글 리스트에 추가
    )

    return jsonify({"message": "대댓글이 등록되었습니다!"}), 201


########################################  댓글, 대댓글  ########################################

########################################  마이페이지  ########################################


# #  게시글 상태 진행중 -> 완료 메소드
@app.route("/api/posts/<post_id>/complete", methods=["PUT"])
@jwt_required
def complete_post(post_id):
    try:
        user_id = get_jwt_identity()  # ✅ 현재 로그인한 사용자 확인

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 본인 게시글인지 확인
        if str(post["author_id"]) != str(user_id):
            return jsonify({"message": "본인 게시글만 완료 처리할 수 있습니다."}), 403

        # ✅ 이미 완료된 경우 예외 처리
        if not post["status"]:
            return jsonify({"message": "이미 완료된 게시글입니다."}), 400

        # ✅ 게시글 상태를 '완료'로 변경
        posts_collection.update_one(
            {"_id": ObjectId(post_id)},
            {"$set": {"status": False}}
        )

        return jsonify({"message": "게시글이 완료되었습니다."}), 200

    except Exception as e:
        print(f"❌ [ERROR] 게시글 완료 처리 실패: {str(e)}")
        return jsonify({"error": "서버 내부 오류 발생", "details": str(e)}), 500


########################################  마이페이지  ########################################

if __name__ == "__main__":
    app.run('0.0.0.0', debug=True, port=5001)