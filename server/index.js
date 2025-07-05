// Import các thư viện cần thiết
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); // Cho phép frontend gọi API từ một địa chỉ khác
const bcrypt = require('bcryptjs'); // Thư viện để mã hóa mật khẩu

// Khởi tạo ứng dụng Express
const app = express();
const PORT = process.env.PORT || 3001;

// --- Middlewares ---

// SỬA LỖI CORS: Đặt cors() làm middleware đầu tiên.
// Điều này đảm bảo mọi request đến đều được xử lý CORS trước tiên.
app.use(cors());

// Cho phép Express đọc dữ liệu JSON từ body của request
app.use(express.json());

// --- Kết nối tới MongoDB ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("SUCCESS: Connected to MongoDB!"))
  .catch((err) => console.error("ERROR: MongoDB connection failed.", err));

// --- Định nghĩa Schema (Cấu trúc dữ liệu cho User) ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    risk: { type: String, default: 'Safe' },
    frozen: { type: Boolean, default: false },
    suspiciousCount: { type: Number, default: 0 },
    history: { type: Array, default: [] }
});

// Tạo Model từ Schema. Mongoose sẽ tạo collection tên là 'users' trong DB.
const UserModel = mongoose.model("User", UserSchema);


// --- API Endpoints (Routes) ---

// 1. API Đăng ký người dùng mới
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "Tên tài khoản và mật khẩu không được để trống." });
        }
        const existingUser = await UserModel.findOne({ username: username.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ message: "Tên tài khoản này đã tồn tại." });
        }

        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        const newUser = new UserModel({
            username: username.toLowerCase(),
            password: hashedPassword,
        });
        await newUser.save();
        res.status(201).json({ message: "Đăng ký thành công!" });
    } catch (error) {
        console.error("Register Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});

// 2. API Đăng nhập
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await UserModel.findOne({ username: username.toLowerCase() });
        if (!user) {
            return res.status(400).json({ message: "Sai tên tài khoản hoặc mật khẩu." });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Sai tên tài khoản hoặc mật khẩu." });
        }
        res.status(200).json({
            message: "Đăng nhập thành công!",
            user: {
                username: user.username,
            }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});

// 3. API lấy toàn bộ thông tin của một người dùng
app.get('/user/:username', async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();
        const user = await UserModel.findOne({ username: username }).select('-password');
        if (!user) {
            return res.status(404).json({ message: "Không tìm thấy người dùng." });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error("Get User Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});

// 4. API để cập nhật thông tin người dùng
app.post('/update-user', async (req, res) => {
    try {
        const { username, risk, suspiciousCount, newTransaction } = req.body;
        const updatedUser = await UserModel.findOneAndUpdate(
            { username: username.toLowerCase() },
            {
                $set: { risk: risk, suspiciousCount: suspiciousCount },
                $push: { history: newTransaction }
            },
            { new: true }
        ).select('-password');
        if (!updatedUser) {
            return res.status(404).json({ message: "Không tìm thấy người dùng để cập nhật." });
        }
        res.status(200).json({ message: "Cập nhật thành công!", user: updatedUser });
    } catch (error) {
        console.error("Update User Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});

// --- Khởi động Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
