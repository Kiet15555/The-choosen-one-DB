    // Import các thư viện cần thiết
    require('dotenv').config();
    const express = require('express');
    const mongoose = require('mongoose');
    const cors = require('cors');
    const bcrypt = require('bcryptjs');
    const nodemailer = require('nodemailer');
    
    // Khởi tạo ứng dụng Express
    const app = express();
    
    // --- Middlewares ---
    
    // SỬA LỖI CORS: Cho phép TẤT CẢ các yêu cầu từ bên ngoài.
    app.use(cors());
    
    // Cho phép Express đọc dữ liệu JSON từ body của request
    app.use(express.json());
    
    // --- Kết nối tới MongoDB ---
    mongoose.connect(process.env.MONGODB_URI)
      .then(() => console.log("SUCCESS: Connected to MongoDB!"))
      .catch((err) => console.error("ERROR: MongoDB connection failed.", err));
    
    // --- Cấu hình gửi Email với Resend ---
    const transporter = nodemailer.createTransport({
        host: 'smtp.resend.com',
        secure: true,
        port: 465,
        auth: {
            user: 'resend',
            pass: process.env.RESEND_API_KEY,
        },
    });
    
    // --- Định nghĩa Schema (Cấu trúc dữ liệu cho User) ---
    const UserSchema = new mongoose.Schema({
        username: { type: String, required: true, unique: true, lowercase: true }, // Sẽ lưu email
        password: { type: String, required: true },
        isVerified: { type: Boolean, default: false },
        otp: { type: String },
        otpExpires: { type: Date },
        risk: { type: String, default: 'Safe' },
        frozen: { type: Boolean, default: false },
        suspiciousCount: { type: Number, default: 0 },
        history: { type: Array, default: [] }
    });
    
    const UserModel = mongoose.model("User", UserSchema);
    
    
    // --- API Endpoints (Routes) ---
    
    // API Đăng ký
    app.post('/register', async (req, res) => {
        try {
            const { username: email, password } = req.body;
            if (!email || !password) {
                return res.status(400).json({ message: "Email và mật khẩu không được để trống." });
            }
    
            const existingUser = await UserModel.findOne({ username: email.toLowerCase() });
            if (existingUser && existingUser.isVerified) {
                return res.status(400).json({ message: "Email này đã được sử dụng." });
            }
    
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const hashedOtp = await bcrypt.hash(otp, salt);
            const otpExpires = Date.now() + 10 * 60 * 1000;
    
            if (existingUser) {
                existingUser.password = hashedPassword;
                existingUser.otp = hashedOtp;
                existingUser.otpExpires = otpExpires;
                await existingUser.save();
            } else {
                const newUser = new UserModel({
                    username: email.toLowerCase(),
                    password: hashedPassword,
                    otp: hashedOtp,
                    otpExpires: otpExpires,
                });
                await newUser.save();
            }
            
            await transporter.sendMail({
                from: '"Detectus App" <noreply@detectus.xyz>',
                to: email,
                subject: 'Mã Kích Hoạt Tài Khoản Detectus',
                html: `<p>Chào bạn,</p><p>Mã OTP để kích hoạt tài khoản của bạn là: <strong>${otp}</strong></p><p>Mã này sẽ hết hạn sau 10 phút.</p>`
            });
    
            res.status(201).json({ message: "Đăng ký thành công! Vui lòng kiểm tra email để lấy mã OTP." });
    
        } catch (error) {
            console.error("Register/Send OTP Error:", error);
            res.status(500).json({ message: "Lỗi server khi gửi email xác thực." });
        }
    });
    
    // API Xác thực OTP
    app.post('/verify-otp', async (req, res) => {
        try {
            const { email, otp } = req.body;
            const user = await UserModel.findOne({ username: email.toLowerCase() });
    
            if (!user) return res.status(400).json({ message: "Email không tồn tại." });
            if (user.isVerified) return res.status(400).json({ message: "Tài khoản đã được xác thực." });
            if (!user.otp || !user.otpExpires) return res.status(400).json({ message: "Tài khoản này không đang chờ xác thực." });
            
            if (Date.now() > user.otpExpires) return res.status(400).json({ message: "Mã OTP đã hết hạn." });
    
            const isMatch = await bcrypt.compare(otp, user.otp);
            if (!isMatch) return res.status(400).json({ message: "Mã OTP không chính xác." });
    
            user.isVerified = true;
            user.otp = undefined;
            user.otpExpires = undefined;
            await user.save();
    
            res.status(200).json({ message: "Xác thực tài khoản thành công! Giờ bạn có thể đăng nhập." });
        } catch (error) {
            console.error("Verify OTP Error:", error);
            res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
        }
    });
    
    
    // API Đăng nhập
    app.post('/login', async (req, res) => {
        try {
            const { username: email, password } = req.body;
            const user = await UserModel.findOne({ username: email.toLowerCase() });
    
            if (!user) return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
            if (!user.isVerified) return res.status(403).json({ message: "Tài khoản chưa được kích hoạt." });
    
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
            
            res.status(200).json({
                message: "Đăng nhập thành công!",
                user: { username: user.username }
            });
        } catch (error) {
            console.error("Login Error:", error);
            res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
        }
    });
    
    // API lấy thông tin người dùng
    app.get('/user/:username', async (req, res) => {
        try {
            const username = req.params.username.toLowerCase();
            const user = await UserModel.findOne({ username: username }).select('-password');
            if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });
            res.status(200).json(user);
        } catch (error) {
            console.error("Get User Error:", error);
            res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
        }
    });
    
    // API cập nhật thông tin người dùng
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
            if (!updatedUser) return res.status(404).json({ message: "Không tìm thấy người dùng để cập nhật." });
            res.status(200).json({ message: "Cập nhật thành công!", user: updatedUser });
        } catch (error) {
            console.error("Update User Error:", error);
            res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
        }
    });
    
    // THAY ĐỔI QUAN TRỌNG CHO VERCEL: Export 'app' để Vercel sử dụng
    module.exports = app;
    