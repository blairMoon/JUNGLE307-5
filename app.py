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
    return render_template("index.html")

######################################## 회원가입, 로그인  ########################################

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

######################################## 회원가입, 로그인  ########################################

######################################## 게시글 작성  ########################################

# ✅ JWT 인증 필요: 게시글 생성 (POST)
@app.route("/api/posts", methods=["POST"])
@jwt_required  
def create_post():
    user_id = request.user["userId"]  # JWT에서 사용자 ID 가져오기
    nickname = request.user["nickname"]  # JWT에서 가져온 닉네임

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
        "message": "게시글이 등록되었습니다!",
        "post_id": str(post_id)
    }), 201


# ✅ 게시글 목록 조회 (전체 조회)
@app.route("/api/posts", methods=["GET"])
def get_posts():
    posts = posts_collection.find().sort("created_at", -1)  # 최신순 정렬
    post_list = []

    for post in posts:
        post_price = "무료나눔" if post["price"] == 0 else post["price"]
        post_status = "진행 중" if post["status"] else "완료"

        post_list.append({
            "id": str(post["_id"]),
            "title": post["title"],
            "image_url": post.get("image_url", None),
            "category": post["category"],
            "status": post_status,
            "price": post_price,
            "created_at": post["created_at"].isoformat(),
            "nick_name": post["nickname"]
        })

    return jsonify(post_list), 200

# ✅ 업로드된 이미지 서빙 (Flask에서 정적 파일로 제공)
@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ✅ 특정 게시글 조회 (상세 조회 + 댓글 포함)
@app.route("/api/posts/<post_id>", methods=["GET"])
@jwt_required
def get_post_detail(post_id):
    try:
        # ✅ 유효한 ObjectId인지 확인
        if not ObjectId.is_valid(post_id):
            return jsonify({"message": "잘못된 게시글 ID입니다."}), 400

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 현재 로그인한 사용자 정보 가져오기
        current_user_id = request.user["userId"]
        is_author = str(post["author_id"]) == str(current_user_id)

        post_price = "무료나눔" if post["price"] == 0 else post["price"]
        post_status = "진행 중" if post["status"] else "완료"  # ✅ 상태 변환

        # ✅ 댓글 조회
        comments = comments_collection.find({"post_id": ObjectId(post_id)})
        comment_list = []
        for comment in comments:
            comment_list.append({
                "id": comment["id"],
                "writer": comment["writer"],
                "content": comment["content"],
                "created_at": comment["created_at"],
                "isAuthor": comment["isAuthor"],
                "replies": [
                    {
                        "id": reply["id"],
                        "writer": reply["writer"],
                        "content": reply["content"],
                        "created_at": reply["created_at"],
                        "isAuthor": reply["isAuthor"]
                    }
                    for reply in comment.get("replies", [])
                ]
            })

        # ✅ 게시글 데이터 반환
        response = {
            "id": str(post["_id"]),
            "title": post["title"],
            "image_url": post.get("image_url", None),
            "category": post["category"],
            "status": post_status,
            "price": post_price,
            "description": post["description"],
            "created_at": post["created_at"].isoformat(),
            "nick_name": post["nickname"],
            "isAuthor": is_author,
            "comments": comment_list
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"❌ [ERROR] 게시글 조회 실패: {str(e)}")  # ✅ 오류 메시지 출력
        return jsonify({"error": "서버 내부 오류가 발생했습니다.", "details": str(e)}), 500
    
# ✅ 게시글 수정 API (본인만 가능)
@app.route("/api/posts/<post_id>", methods=["PUT"])
@jwt_required
def update_post(post_id):
    try:
        # ✅ 현재 로그인한 사용자 정보 가져오기
        user_id = request.user["userId"]

        # ✅ 요청 데이터 파싱
        data, error_response, error_status = parse_request_data()
        if error_response:
            return error_response, error_status  # 오류 응답 반환

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 작성자 확인 (본인만 수정 가능)
        if str(post["author_id"]) != str(user_id):
            return jsonify({"message": "본인 게시글만 수정할 수 있습니다."}), 403

        # ✅ 수정할 필드만 업데이트 (입력된 값만 적용)
        update_data = {}
        if "title" in data:
            update_data["title"] = data["title"]
        if "category" in data:
            update_data["category"] = data["category"]
        if "status" in data:
            update_data["status"] = data["status"]
        if "price" in data:
            update_data["price"] = data["price"]
        if "description" in data:
            update_data["description"] = data["description"]

        # ✅ 데이터 업데이트 실행
        posts_collection.update_one({"_id": ObjectId(post_id)}, {"$set": update_data})

        return jsonify({"message": "게시글이 수정되었습니다."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ✅ 게시글 삭제 API (본인만 가능)
@app.route("/api/posts/<post_id>", methods=["DELETE"])
@jwt_required
def delete_post(post_id):
    try:
        # ✅ 현재 로그인한 사용자 정보 가져오기
        user_id = request.user["userId"]

        # ✅ 게시글 찾기
        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 작성자 확인 (본인만 삭제 가능)
        if str(post["author_id"]) != str(user_id):
            return jsonify({"message": "본인 게시글만 삭제할 수 있습니다."}), 403

        # ✅ 게시글 삭제
        posts_collection.delete_one({"_id": ObjectId(post_id)})

        # ✅ 해당 게시글의 모든 댓글 삭제
        comments_collection.delete_many({"post_id": ObjectId(post_id)})

        return jsonify({"message": "게시글이 삭제되었습니다."}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
######################################## 게시글 작성  ########################################    

########################################  댓글 작성  ########################################

# 댓글 작성 API
@app.route("/api/posts/<post_id>/comments", methods=["POST"])
@jwt_required
def add_comment(post_id):
    try:
        # ✅ 게시글 존재 확인
        if not ObjectId.is_valid(post_id):
            return jsonify({"message": "잘못된 게시글 ID입니다."}), 400

        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        # ✅ 요청 데이터 검증
        data = request.get_json()
        content = data.get("content", "").strip()
        if not content:
            return jsonify({"message": "댓글 내용을 입력해주세요."}), 400

        # ✅ 현재 로그인한 사용자 정보 가져오기
        user_id = request.user["userId"]
        nickname = request.user["nickname"]

        # ✅ 게시글 작성자인지 확인
        is_author = str(post["author_id"]) == str(user_id)

        # ✅ 현재 댓글 개수 조회 후, 새로운 ID 생성
        last_comment = comments_collection.find_one(
            {"post_id": ObjectId(post_id)}, sort=[("id", -1)]
        )
        new_comment_id = last_comment["id"] + 1 if last_comment else 1

        # ✅ 댓글 저장
        comment = {
            "id": new_comment_id,  # 고유 숫자 ID
            "post_id": ObjectId(post_id),
            "writer": "작성자" if is_author else nickname,
            "content": content,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d"),
            "isAuthor": is_author,
            "replies": []  # 대댓글 리스트
        }

        comments_collection.insert_one(comment)

        return jsonify({
            "message": "댓글이 등록되었습니다!",
            "comment_id": new_comment_id
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

#  대댓글 추가 API
@app.route("/api/posts/<post_id>/comments/<int:comment_id>/replies", methods=["POST"])
@jwt_required
def add_reply(post_id, comment_id):
    try:
        # ✅ 게시글 & 댓글 존재 확인
        if not ObjectId.is_valid(post_id):
            return jsonify({"message": "잘못된 게시글 ID입니다."}), 400

        post = posts_collection.find_one({"_id": ObjectId(post_id)})
        if not post:
            return jsonify({"message": "게시글을 찾을 수 없습니다."}), 404

        comment = comments_collection.find_one({"post_id": ObjectId(post_id), "id": comment_id})
        if not comment:
            return jsonify({"message": "댓글을 찾을 수 없습니다."}), 404

        # ✅ 요청 데이터 검증
        data = request.get_json()
        content = data.get("content", "").strip()
        if not content:
            return jsonify({"message": "대댓글 내용을 입력해주세요."}), 400

        # ✅ 현재 로그인한 사용자 정보 가져오기
        user_id = request.user["userId"]
        nickname = request.user["nickname"]

        # ✅ 게시글 작성자인지 확인
        is_author = str(post["author_id"]) == str(user_id)

        # ✅ 현재 대댓글 개수 조회 후, 새로운 ID 생성
        last_reply = max([reply["id"] for reply in comment["replies"]], default=0)
        new_reply_id = last_reply + 1

        # ✅ 대댓글 데이터
        reply = {
            "id": new_reply_id,  # 고유 숫자 ID
            "writer": "작성자" if is_author else nickname,
            "content": content,
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d"),
            "isAuthor": is_author
        }

        # ✅ 대댓글 추가
        comments_collection.update_one(
            {"post_id": ObjectId(post_id), "id": comment_id},
            {"$push": {"replies": reply}}
        )

        return jsonify({"message": "대댓글이 등록되었습니다!", "reply_id": new_reply_id}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500


########################################  댓글 작성  ########################################

if __name__ == "__main__":
    app.run(debug=True, port=5001)
