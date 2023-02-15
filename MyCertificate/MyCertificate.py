import hashlib
import json
import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# =========================== ฟังก์ชันสร้าง hash ของข้อมูล =========================== #
# เป็นการสร้างแฮชของข้อมูลที่กำหนดโดยการเข้ารหัสในรูปแบบ JSON ก่อน
# จากนั้นจึงใช้อัลกอริทึมการแฮช SHA-512 เพื่อสร้าง digest
def generate_hash(data):
    data_json = json.dumps(data).encode('utf-8')
    digest = hashlib.sha512(data_json).hexdigest()
    return digest

# =========================== ฟังก์ชัน sign hash ด้วย private key =========================== #
# เป็นการ sign hash ของข้อมูลที่กำหนดโดยใช้ private key ของอัลกอริทึม digital signature
def sign_data(data, private_key):
    data_hash = generate_hash(data)
    signature = private_key.sign(
        data_hash.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# =========================== ฟังก์ชันตรวจสอบ signature ด้วย public key =========================== #
# ตรวจสอบลายเซ็น (signature) ของข้อมูลที่กำหนดโดยใช้ public key ของอัลกอริทึม digital signature 
def verify_signature(data, signature, public_key):
    data_hash = generate_hash(data)
    try:
        public_key.verify(
            signature,
            data_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

# =========================== ฟังก์ชันการออกใบรับรอง =========================== #
def issue_certificate():

    # ป้อนข้อมูลเกี่ยวกับใบรับรองจาก command line  
    name = input("Enter Your Name: ")
    student_id = input("Enter Student ID: ")
    project_name = input("Enter Project Name: ")
    expiration_date = input("Enter Certificate expiration date (YYYY-MM-DD): ")
    grade = input("Enter Grades (A to C): ")
    difficulty_in_making = input("Enter Difficulty in making (0 - 100): ")

    # สร้างแฮชของข้อมูล
    data = {
        "name": name,
        "student_id": student_id,
        "project_name": project_name,
        "expiration_date": expiration_date,
        "grade": grade,
        "difficulty_in_making": difficulty_in_making
    }

    # เซ็นแฮชด้วยคีย์ส่วนตัว(privateKey.pem)
    private_key = serialization.load_pem_private_key(
        open('privateKey.pem', 'rb').read(),
        password=None,
        backend=default_backend()
    )

    # บันทึกข้อมูลใบรับรอง(Certificate.txt) และลายเซ็น(Signature.txt)ในไฟล์แยกต่างหาก
    signature = sign_data(data, private_key)
    with open('Certificate.txt', 'w') as f:
        json.dump(data, f)
    with open('Signature.txt', 'w') as f:
        f.write(signature.hex())

# =========================== ฟังก์ชันตรวจสอบใบรับรอง =========================== #
def verify_certificate():
    # โหลดข้อมูลใบรับรอง(Certificate.txt) และลายเซ็น(Signature.txt)
    with open('Certificate.txt', 'r') as f:
        data = json.load(f)
    with open('Signature.txt', 'r') as f:
        signature = bytes.fromhex(f.read())
    
    # ตรวจสอบลายเซ็นโดยใช้คีย์สาธารณะ และตรวจสอบว่าใบรับรองหมดอายุหรือไม่
    public_key = serialization.load_pem_public_key(
        open('publicKey.pem', 'rb').read(),
        backend=default_backend()
    )
    expiration_date = datetime.datetime.strptime(data['expiration_date'], '%Y-%m-%d').date()
    if expiration_date < datetime.datetime.now().date():
        print("Certificate has expired.")
        return
    if not verify_signature(data, signature, public_key):
        print("Certificate is invalid.")
        return
    print("Certificate is valid.")

# =========================== Main program =========================== #
if __name__ == '__main__':
    while True:
        print("Select an operation:")
        print("1. Issue a certificate")
        print("2. Verify a certificate")
        print("0. Exit")
        print("==============================")
        choice = input("Enter Your Choice : ")
        if choice == '1':
            print("Enter certificate information\n")
            issue_certificate()
            print("==============================\n")
        elif choice == '2':
            print("\nVerify Certificate >>> ", end='')
            verify_certificate()
            print("==============================\n")
        elif choice == '0':
            print("\nExiting program...")
            break
        else:
            print("Invalid choice. Please try again.")
            print("==============================\n")
