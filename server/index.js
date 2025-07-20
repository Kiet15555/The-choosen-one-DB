// Import các thư viện cần thiết
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');

// Khởi tạo ứng dụng Express
const app = express();
const PORT = process.env.PORT || 3001;

// --- Middlewares ---
app.use(cors());
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

// --- Định nghĩa Schemas ---

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    isVerified: { type: Boolean, default: false },
    otp: { type: String },
    otpExpires: { type: Date },
    wallets: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Wallet' }]
});

const WalletSchema = new mongoose.Schema({
    address: { type: String, required: true, unique: true },
    trustScore: { type: Number, default: 500 },
    riskLevel: { type: String, default: 'An Toàn' },
    unblacklistCount: { type: Number, default: 0 },
    frozen: { type: Boolean, default: false },
    whitelist: { type: Boolean, default: false },
    history: { type: Array, default: [] },
    owner_username: { type: String, required: true, lowercase: true }
});

// --- Tạo Models ---
const UserModel = mongoose.model("User", UserSchema);
const WalletModel = mongoose.model("Wallet", WalletSchema);

// --- API Endpoints ---

// ... (Các API cũ giữ nguyên)
app.get('/bot', (req, res) => res.status(200).json({message: "ok"}));
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
            await UserModel.create({
                username: email.toLowerCase(),
                password: hashedPassword,
                otp: hashedOtp,
                otpExpires: otpExpires,
            });
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
app.post('/login', async (req, res) => {
    try {
        const { username: email, password } = req.body;
        const user = await UserModel.findOne({ username: email.toLowerCase() });
        if (!user) return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
        if (!user.isVerified) return res.status(403).json({ message: "Tài khoản chưa được kích hoạt." });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Sai email hoặc mật khẩu." });
        res.status(200).json({ message: "Đăng nhập thành công!", user: { username: user.username } });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});
app.get('/user/:username', async (req, res) => {
    try {
        const user = await UserModel.findOne({ username: req.params.username.toLowerCase() }).populate('wallets').select('-password');
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });
        res.status(200).json(user);
    } catch (error) {
        console.error("Get User Error:", error);
        res.status(500).json({ message: "Đã có lỗi xảy ra ở server." });
    }
});
app.post('/wallet/connect', async (req, res) => {
    try {
        const { username, walletAddress } = req.body;
        if (!username || !walletAddress) return res.status(400).json({ message: "Thiếu username hoặc walletAddress." });
        const user = await UserModel.findOne({ username: username.toLowerCase() });
        if (!user) return res.status(404).json({ message: "Không tìm thấy người dùng." });
        let wallet = await WalletModel.findOne({ address: walletAddress });
        if (!wallet) {
            wallet = await WalletModel.create({
                address: walletAddress,
                owner_username: user.username
            });
        }
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
app.post('/wallet/update-transaction', async (req, res) => {
    try {
        const { walletAddress, newTransaction, newTrustScore, newRiskLevel } = req.body;
        const updatedWallet = await WalletModel.findOneAndUpdate(
            { address: walletAddress },
            {
                $push: { history: newTransaction },
                $set: { 
                    trustScore: newTrustScore,
                    riskLevel: newRiskLevel
                }
            },
            { new: true }
        );
        if (!updatedWallet) return res.status(404).json({ message: "Không tìm thấy ví để cập nhật." });
        res.status(200).json({ message: "Cập nhật giao dịch và điểm cho ví thành công!", wallet: updatedWallet });
    } catch (error) {
        console.error("Update Transaction Error:", error);
        res.status(500).json({ message: "Lỗi server khi cập nhật giao dịch." });
    }
});
app.post('/wallet/unblacklist', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: 'Thiếu địa chỉ ví.' });
        }
        const updatedWallet = await WalletModel.findOneAndUpdate(
            { address: walletAddress },
            {
                $set: {
                    trustScore: 500,
                    riskLevel: 'An Toàn'
                },
                $inc: { unblacklistCount: 1 }
            },
            { new: true }
        );
        if (!updatedWallet) return res.status(404).json({ message: 'Không tìm thấy ví.' });
        res.status(200).json({ message: 'Kháng cáo thành công! Điểm đã được khôi phục về 500.', wallet: updatedWallet });
    } catch (error) {
        console.error("Unblacklist Error:", error);
        res.status(500).json({ message: 'Lỗi server khi thực hiện kháng cáo.' });
    }
});
app.post('/admin/update-wallet', async (req, res) => {
    try {
        const { walletAddress, trustScore, riskLevel, frozen, whitelist } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: "Thiếu địa chỉ ví." });
        }

        const updateData = {};
        if (trustScore !== undefined) updateData.trustScore = trustScore;
        if (riskLevel !== undefined) updateData.riskLevel = riskLevel;
        if (frozen !== undefined) updateData.frozen = frozen;
        if (whitelist !== undefined) updateData.whitelist = whitelist;

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ message: "Không có dữ liệu để cập nhật." });
        }

        const updatedWallet = await WalletModel.findOneAndUpdate(
            { address: walletAddress },
            { $set: updateData },
            { new: true }
        );

        if (!updatedWallet) {
            return res.status(404).json({ message: "Không tìm thấy ví trong DB để cập nhật." });
        }

        res.status(200).json({ message: "Admin cập nhật DB thành công!", wallet: updatedWallet });

    } catch (error) {
        console.error("Admin Update Wallet Error:", error);
        res.status(500).json({ message: "Lỗi server khi admin cập nhật ví." });
    }
});

// --- THÊM MỚI: API cho chức năng phân tích AI ---
app.post('/wallet/analyze', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: "Thiếu địa chỉ ví." });
        }

        const wallet = await WalletModel.findOne({ address: walletAddress });
        if (!wallet || wallet.history.length === 0) {
            return res.status(200).json({ analysis: "Không có đủ dữ liệu giao dịch để phân tích." });
        }
        
        // --- Mô phỏng quá trình phân tích của AI ---
        // Trong một ứng dụng thật, đây là nơi bạn sẽ gọi đến API của một mô hình AI
        // và gửi dữ liệu `wallet.history` để xử lý.

        const txCount = wallet.history.length;
        const totalSent = wallet.history.reduce((sum, tx) => sum + parseFloat(tx.amount), 0);
        const uniqueRecipients = new Set(wallet.history.map(tx => tx.recipient)).size;
        
        let analysisText = `**Báo cáo Phân tích AI cho ví:**\n\n`;
        analysisText += `- **Tổng quan:** Ví này đã thực hiện **${txCount}** giao dịch được ghi nhận với tổng khối lượng là **${totalSent.toFixed(4)} ETH**.\n`;
        analysisText += `- **Hành vi:** Giao dịch đã được gửi đến **${uniqueRecipients}** địa chỉ ví khác nhau.\n`;
        
        if (wallet.trustScore > 700) {
            analysisText += `- **Đánh giá:** Đây là một ví hoạt động tích cực với điểm tin cậy cao. Các giao dịch có xu hướng an toàn, với số lượng nhỏ và thường xuyên. Không phát hiện hành vi đáng ngờ nào.\n`;
        } else if (wallet.trustScore < 300) {
            analysisText += `- **Cảnh báo:** Ví này có điểm tin cậy thấp. Lịch sử cho thấy có các giao dịch dẫn đến việc bị trừ điểm mạnh, có thể do tương tác với các ví rủi ro hoặc thực hiện giao dịch với khối lượng lớn bất thường. Cần giám sát cẩn thận.\n`;
        } else {
            analysisText += `- **Nhận xét:** Ví có mức độ hoạt động trung bình. Điểm tin cậy ở mức ổn định. Cần theo dõi thêm các giao dịch trong tương lai để có đánh giá chính xác hơn.\n`;
        }

        if(wallet.unblacklistCount > 0) {
            analysisText += `- **Lưu ý đặc biệt:** Ví này đã từng bị đưa vào danh sách đen và đã thực hiện kháng cáo **${wallet.unblacklistCount}** lần. Đây là một yếu tố cần được xem xét cẩn thận khi đánh giá rủi ro.\n`;
        }

        // Trả về kết quả mô phỏng
        res.status(200).json({ analysis: analysisText });

    } catch (error) {
        console.error("AI Analysis Error:", error);
        res.status(500).json({ message: "Lỗi server khi thực hiện phân tích." });
    }
});


// Khởi động Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
