import csv
import pymongo
from datetime import datetime

# ✅ MongoDB 연결
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["week00"]
collection = db["posts"]

# # 모든 문서 삭제
# collection.delete_many({})

# print("모든 데이터가 삭제되었습니다.")

# ✅ CSV 파일 열기
with open("imgmock_data.csv", newline="", encoding="utf-8") as csvfile:
    reader = csv.DictReader(csvfile)
    
    data_to_insert = []
    for row in reader:
        # ✅ 데이터 변환 (필요한 경우)
        row["status"] = row["status"].lower() == "true"  # 문자열을 Boolean으로 변환
        row["price"] = int(row["price"])  # 가격을 숫자로 변환
        row["created_at"] = datetime.fromisoformat(row["created_at"])  # 날짜 변환
        row["comments"] = []  # 댓글을 리스트로 변환

        data_to_insert.append(row)

    # ✅ MongoDB에 데이터 삽입
    collection.insert_many(data_to_insert)

print("✅ CSV 데이터를 MongoDB에 성공적으로 삽입했습니다!")
