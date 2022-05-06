from flask import Flask, render_template, jsonify, request, session, redirect, url_for

app = Flask(__name__)

from pymongo import MongoClient

client = MongoClient('mongodb://3.34.44.93', 27017, username="sparta", password="woowa")
db = client.dbsparta_plus_week4

# jwt 키를 복호화 하기 위한 암호키
# 보여주면 안됨
SECRET_KEY = 'rainbow'

# jwt 토큰을 쓰기 위한 라이브러리
# 다운로드할 패키지 이름은 PyJWT
import jwt

# 시간 관련 라이브러리
import datetime

# 암호화 기본 라이브러리
import hashlib



@app.route('/')
def home():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        user_info = db.user.find_one({"id": payload['id']})
        return render_template('index.html', nickname=user_info["nick"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))


@app.route('/login')
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)


# 회원가입 API
#
#   1. 회원가입페이지 보여주기 render_template
@app.route('/register')
def register():
    return render_template('register.html')

#   2. 회원가입 저장 API
#
#   사용자 요청
#
#       아이디, 패스워드, 닉네임
#       id_give, pw_give, nickname_give
#
#   처리
#
#       변수로 사용자 요청 값 저장(아이디, 패스워드, 닉네임)
#       비밀번호 암호화
#       딕셔너리 형태로 사용자 요청 값 도큐먼트화
#       db insert 메서드
#
#   데이터 응답
#
#       결과는 성공, '회원가입에 성공했습니다' 메시지

@app.route('/api/register', methods=['POST'])
def api_register():
    # 사용자 요청
    # 변수 지정
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    nickname_receive = request.form['nickname_give']
    # 암호화 메서드(import hashlib)
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()
    # 데이터베이스에 아이디, 비밀번호, 닉네임 저장
    db.user.insert_one({'id': id_receive, 'pw': pw_hash, 'nick': nickname_receive})
    # 응답데이터 리턴
    return jsonify({'result': 'success', 'msg': '회원가입에 성공했습니다!'})




# 로그인 API
#
#   로그인이 POST 타입이어야 하는 이유
#
#       GET 타입이라면 브라우저 주소에 데이터 전부 노출되어 버림!
#
#   사용자 요청
#
#       아이디, 비밀번호
#       id_give, pw_give
#
#   처리
#
#       대조 : 원래 갖고 있던 것과 사용자가 입력한 것을
#       비밀번호 요청 변수 암호화
#       db.find_one 메서드 이용
#       토큰 페이로드
#
#   데이터 응답
#
#       성공: 로그인에 성공했습니다 메시지 / 닉네임 / 토큰 / 메인 창 이동
#       실패: 다시 로그인 정보를 입력해주세요

@app.route('/api/login', methods=['POST'])
def api_login():
    # 사용자 요청 값 변수 선언
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 암호화 변수 담기
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # 유저 DB에서 아이디와 패스워드가 동시에 일치하는 데이터를 찾기
    # 찾는 값은 괄호 안에 하나로 묶여 있어야 함!
    result = db.user.find_one({'id': id_receive, 'pw': pw_hash})

    # 결과의 내용이 있다면,
    if result is not None:
        # jwt 페이로드 선언
        # 담고 싶은 내용을 담을 수 있음
        payload = {
            # 사용자 식별 정보
            'id': id_receive,
            # 토큰 유효 기간
            # 국제 시간 (utcnow 활용)
            # 24시간 만료(timedelta second 활용)
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=60 * 60 * 24)
        }
        # 토큰발행
        # 시크릿키, HS256암호화 알고리즘을 사용해 암호화
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        # 성공 데이터 응답 : 성공 메시지와 토큰
        return jsonify({'result': 'success', 'token': token})
    # 실패 데이터 응답
    else:
        # 아이디 비밀번호가 일치하지 않습니다 메시지
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})


# 닉네임 불러오기 API
# 닉네임 뿐만 아니라, 데이터베이스 내부 정보를 모두 불러올 수 있음!
#
#   사용자 요청
#
#       토큰 : 저장된 쿠키에 있는 토큰을 가져옴!
#       token_receive
#
#   처리
#
#       토큰을 복호화해서 페이로드에 있는 아이디로 닉네임 데이터베이스에 조회, 변수 선언
#       db.find_one 활용해서 닉네임 변수 선언
#       조건 : 닉네임 변수가 None이 아니라면
#
#   데이터 응답
#
#       성공 : 닉네임, 팔로우, 팔로잉, 피드 등
#       실패 : 서버오류 - 몽고DB 401
#       만료 : 만료된 토큰입니다
@app.route('/api/nick', methods=['GET'])
def api_valid():
    # 사용자 요청
    token_receive = request.cookies.get('mytoken')

    # try 구문
    # 에러와 예외처리에 용이
    # 에러가 발생할 것 같은 코드를 사용할 때, 에러를 정해두면 프로그램이 멈추지 않고 처리
    # 경우에 따라 if,else 사용할 수 있음
    try:
        # 페이로드 복호화
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)

        # 페이로드의 아이디에 관련된 데이터를 변수 선언
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': False})

        # 성공 데이터 응답: 성공결과, 닉네임 정보
        return jsonify({'result': 'success', 'nickname': userinfo['nick']})

    # 에러 : 토큰 만료 - 실패결과, 메시지
    except jwt.ExpiredSignatureError:
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})
    # 에러 : 토큰이 없는 경우 - 실패결과, 메시지 / ? 401처리(추후논의)
    except jwt.exceptions.DecodeError:
        return jsonify({'result': 'fail', 'msg': '로그인 정보가 존재하지 않습니다.'})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)