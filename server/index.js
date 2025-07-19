// Import các thư viện cần thiết
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer'); // Thư viện để gửi email

// Khởi tạo ứng dụng Express
const app = express();
const PORT = process.env.PORT || 3001;

// --- Middlewares ---

// Cho phép TẤT CẢ các yêu cầu từ bên ngoài để khắc phục lỗi "Failed to fetch"
app.use(cors());

// Cho phép Express đọc dữ liệu JSON từ body của request
app.use(express.json());

// --- Kết nối tới MongoDB ---
// Chuỗi kết nối sẽ được đọc từ biến môi trường trên Render
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("SUCCESS: Connected to MongoDB!"))
  .catch((err) => console.error("ERROR: MongoDB connection failed.", err));

// --- Cấu hình gửi Email với Resend ---
// API Key sẽ được đọc từ biến môi trường trên Render
const transporter = nodemailer.createTransport({
    host: 'smtp.resend.com',
    secure: true,
    port: 465,
    auth: {
        user: 'resend',
        pass: process.env.RESEND_API_KEY,
    },
});

// --- Định nghĩa Schemas (Cấu trúc dữ liệu) ---

// --- SỬA ĐỔI: Chỉnh sửa UserSchema để liên kết với Wallet ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true }, // Sẽ lưu email ở đây
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false }, // Trạng thái xác thực
    otp: { type: String }, // Lưu mã OTP đã được mã hóa
    otpExpires: { type: Date }, // Thời gian hết hạn của OTP
    // Các trường risk, frozen, suspiciousCount, history có thể được di chuyển sang WalletSchema nếu muốn
    // Ở đây ta giữ lại để tương thích, nhưng thêm trường wallets để liên kết
    risk: { type: String, default: 'Safe' },
    frozen: { type: Boolean, default: false },
    suspiciousCount: { type: Number, default: 0 },
    history: { type: Array, default: [] },
    wallets: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Wallet' }] // Mảng chứa ID của các ví thuộc về user
});

// --- THÊM MỚI: Định nghĩa Schema cho Wallet Collection ---
const WalletSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true }, // Địa chỉ ví
    trustScore: { type: Number, default: 500 }, // Điểm tin cậy
    frozen: { type: Boolean, default: false }, // Trạng thái đóng băng
    history: { type: Array, default: [] }, // Lịch sử giao dịch của riêng ví này
    owner_username: { type: String, required: true, lowercase: true } // Email của người dùng sở hữu để tham chiếu
});


// --- Tạo Models từ Schemas ---
const UserModel = mongoose.model("User", UserSchema);
const WalletModel = mongoose.model("Wallet", WalletSchema); // --- THÊM MỚI ---


// --- API Endpoints (Routes) ---
app.get('/bot', async (req, res) => {
    return res.status(200).json({message: "ok"})
})

// 1. API Đăng ký người dùng mới (Gửi OTP)
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
        const otpExpires = Date.now() + 10 * 60 * 1000; // OTP hết hạn sau 10 phút

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

// 2. API Xác thực OTP
app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        const user = await UserModel.findOne({ username: email.toLowerCase() });

        if (!user) return res.status(400).json({ message: "Email không tồn tại." });
        if (user.isVerified) return res.status(400).json({ message: "Tài khoản đã được xác thực." });
        if (!user.otp || !user.otpExpires) return res.status(400).json({ message: "Tài khoản này không đang chờ xác thực." });
        
        const isExpired = Date.now() > user.otpExpires;
        if (isExpired) return res.status(400).json({ message: "Mã OTP đã hết hạn." });

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


// 3. API Đăng nhập
app.post('/login', async (req, res) => {
    try {
        const { username: email, password } = req.body;
        const user = await UserModel.findOne({ username: email.toLowerCase() });

        if (!user) {
            return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
        }
        
        if (!user.isVerified) {
            return res.status(403).json({ message: "Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email để xác thực." });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
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

// 4. API lấy toàn bộ thông tin của một người dùng
app.get('/user/:username', async (req, res) => {
    try {
        const username = req.params.username.toLowerCase();
        // --- SỬA ĐỔI: Lấy thông tin cả các ví liên kết ---
        const user = await UserModel.findOne({ username: username }).populate('wallets').select('-password');
        if (!user) {
            return res.status(404).json({ message: "Không tìm thấy người dùng." });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error("Get User Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});

// --- THÊM MỚI: API để kết nối ví và lưu vào DB ---
app.post('/wallet/connect', async (req, res) => {
    try {
        const { username, walletAddress } = req.body;
        if (!username || !walletAddress) {
            return res.status(400).json({ message: "Thiếu username hoặc walletAddress." });
        }

        const user = await UserModel.findOne({ username: username.toLowerCase() });
        if (!user) {
            return res.status(404).json({ message: "Không tìm thấy người dùng." });
        }

        // 1. Tìm hoặc Tạo ví mới trong collection "wallets"
        let wallet = await WalletModel.findOne({ address: walletAddress });
        if (!wallet) {
            wallet = new WalletModel({
                address: walletAddress,
                trustScore: 500, // Điểm khởi tạo
                owner_username: user.username
            });
            await wallet.save();
        }

        // 2. Liên kết ví với người dùng (nếu chưa được liên kết)
        if (!user.wallets.includes(wallet._id)) {
            user.wallets.push(wallet._id);
            await user.save();
        }

        res.status(200).json({ message: "Kết nối và liên kết ví thành công!", wallet });

    } catch (error) {
        console.error("Connect Wallet DB Error:", error);
        res.status(500).json({ message: "Lỗi server khi kết nối ví." });
    }
});

// --- THÊM MỚI: API để cập nhật giao dịch cho một ví cụ thể ---
app.post('/wallet/update-transaction', async (req, res) => {
    try {
        const { walletAddress, newTransaction, newTrustScore } = req.body;

        const updatedWallet = await WalletModel.findOneAndUpdate(
            { address: walletAddress },
            {
                $push: { history: newTransaction }, // Thêm giao dịch mới vào mảng history
                $set: { trustScore: newTrustScore }  // Cập nhật điểm tin cậy mới
            },
            { new: true } // Trả về document đã được cập nhật
        );

        if (!updatedWallet) {
            return res.status(404).json({ message: "Không tìm thấy ví để cập nhật." });
        }
        res.status(200).json({ message: "Cập nhật giao dịch và điểm cho ví thành công!", wallet: updatedWallet });
    } catch (error) {
        console.error("Update Transaction Error:", error);
        res.status(500).json({ message: "Lỗi server khi cập nhật giao dịch." });
    }
});


// API cũ để cập nhật user, có thể không cần dùng nữa hoặc chỉ dùng cho các mục đích khác
app.post('/update-user', async (req, res) => {
    // Logic cũ, có thể bạn muốn giữ lại để cập nhật các thông tin khác của user
    res.status(400).json({ message: "Endpoint này không còn được sử dụng để cập nhật giao dịch. Vui lòng dùng /wallet/update-transaction."})
});

// --- Khởi động Server ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
