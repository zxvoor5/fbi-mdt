# FBI MDT (Node.js + MySQL)

1) mysql -u root -p < schema.sql
2) أنشئ مستخدم MySQL:
   CREATE USER 'fbi_user'@'localhost' IDENTIFIED BY 'كلمة_مرور_قوية';
   GRANT ALL ON fbi_mdt.* TO 'fbi_user'@'localhost';
3) cp .env.example .env  (عدّل بيانات الاتصال)
4) npm install
5) npm start  ->  http://localhost:3000
أول من يفتح الصفحة ينشئ حساب المدير.
