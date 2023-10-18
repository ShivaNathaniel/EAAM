import hashlib
import random

class User:
    def __init__(self, username, password):   #tạo class User với khởi tạo username và password
        self.username = username
        self.password = password
        self.public_key = random.randint(1, 10000)  #public_key của User
        self.secret_key = hashlib.sha256(self.password.encode()).hexdigest() #secret_key của User được tạo đơn giản

    def register(self, registration_center):
        registration_center.register_user(self.username, self.public_key)  #để user đăng ký lên RC, RC sẽ có thông tin username và PK

    def authenticate(self, server):
        request_message = {
            "public_key": self.public_key,
            "challenge": random.randint(1, 10000)  #hoạt động giống như 1 OTP
        }

        response_message = server.authenticate_user(request_message)

        if not response_message:
            raise Exception("Authentication failed") #không nhận được request, sẽ trả về failed

        signature = response_message["signature"]         #trả về User chữ ký, PK và Challenge
        user_public_key = response_message["public_key"]
        challenge = response_message["challenge"]

        if not self.verify_signature(signature, user_public_key, challenge):    #nếu xác nhận chữ ký không đúng, sẽ invalid
            raise Exception("Invalid signature")

        return True

    def verify_signature(self, signature, public_key, challenge): #so sánh chữ ký
        message = str(public_key) + str(challenge)
        hashed_message = hashlib.sha256(message.encode()).hexdigest()

        return signature == self.sign_message(hashed_message)

    def sign_message(self, message):
        return hashlib.sha256((self.secret_key + message).encode()).hexdigest()

class Server:
    def __init__(self, registration_center):
        self.registration_center = registration_center
        self.public_key = random.randint(1, 10000)

    def authenticate_user(self, request_message):     #nhận request từ User
        user_public_key = request_message["public_key"]
        challenge = request_message["challenge"]

        user = self.registration_center.get_user(user_public_key)    #lấy thông tin User từ RC
        if not user:
            return None

        response_message = {                            #đáp lại User
            "public_key": self.public_key,
            "challenge": challenge,
            "signature": user.sign_message(str(self.public_key) + str(challenge))
        }

        return response_message

if __name__ == "__main__":
    registration_center = {}

    user = User("alice", "password")
    user.register(registration_center)

    server = Server(registration_center)

    if user.authenticate(server):
        print("Authentication successful!")
    else:
        print("Authentication failed")
