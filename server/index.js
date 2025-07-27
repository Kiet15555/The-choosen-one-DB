// Import các thư viện cần thiết
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');

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
    owner_username: { type: String, required: true, lowercase: true },
    tags: { type: [String], default: [] }
});

// --- Tạo Models ---
const UserModel = mongoose.model("User", UserSchema);
const WalletModel = mongoose.model("Wallet", WalletSchema);

// --- API Endpoints ---
// Giữ nguyên các API cũ của bạn ở đây...
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
        let wallet = await WalletModel.findOne({ address: walletAddress.toLowerCase() });
        if (!wallet) {
            wallet = await WalletModel.create({
                address: walletAddress.toLowerCase(),
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
            { address: walletAddress.toLowerCase() },
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
            { address: walletAddress.toLowerCase() },
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
            { address: walletAddress.toLowerCase() },
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
app.post('/wallet/analyze', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: "Thiếu địa chỉ ví." });
        }

        const wallet = await WalletModel.findOne({ address: walletAddress.toLowerCase() });
        if (!wallet) {
             return res.status(200).json({ 
                status: {
                    riskLevel: "Chưa xác định",
                    trustScore: "N/A",
                    frozen: false,
                    unblacklistCount: 0
                },
                analysis: "### Báo cáo Phân tích AI\n\n- **Thông tin:** Ví này chưa từng tương tác với hệ thống của chúng tôi và không có dữ liệu trong database để phân tích." 
            });
        }
        
        const { history, trustScore, unblacklistCount, frozen, riskLevel } = wallet;

        const status = { trustScore, riskLevel, frozen, unblacklistCount };

        if (history.length === 0) {
            return res.status(200).json({ status, analysis: "### Báo cáo Phân tích AI\n\n- **Thông tin:** Ví này đã có trong hệ thống nhưng chưa có giao dịch nào được ghi nhận để phân tích." });
        }
        
        const validHistory = history.filter(tx => tx && tx.amount !== undefined && tx.amount !== null && !isNaN(Number(tx.amount)) && Number(tx.amount) < 1e18);

        if (validHistory.length === 0) {
             return res.status(200).json({ status, analysis: "### Báo cáo Phân tích AI\n\n- **Thông tin:** Ví này không có dữ liệu giao dịch hợp lệ để phân tích." });
        }

        const txCount = validHistory.length;
        const totalSent = validHistory.reduce((sum, tx) => sum + Number(tx.amount), 0);
        const uniqueRecipients = new Set(validHistory.map(tx => tx.recipient)).size;
        const avgTxAmount = totalSent / txCount;
        const largestTx = Math.max(...validHistory.map(tx => Number(tx.amount)));
        const negativeTxs = validHistory.filter(tx => tx.scoreImpact < 0);

        let analysisText = `### Báo cáo Phân tích AI\n\n`;
        
        analysisText += `#### Tổng quan & Thói quen Tài chính\n`;
        analysisText += `- **Tổng giao dịch:** ${txCount} giao dịch\n`;
        analysisText += `- **Tổng khối lượng:** ${totalSent.toFixed(6)} ETH\n`;
        analysisText += `- **Giao dịch lớn nhất:** ${largestTx.toFixed(6)} ETH\n`;
        analysisText += `- **Trung bình mỗi giao dịch:** ${avgTxAmount.toFixed(6)} ETH\n`;
        analysisText += `- **Số đối tác nhận tiền:** ${uniqueRecipients} ví\n\n`;

        analysisText += `#### Phân tích Rủi ro\n`;
        if (negativeTxs.length > 0) {
            const biggestDrop = Math.min(...negativeTxs.map(tx => tx.scoreImpact));
            analysisText += `- **Cảnh báo:** Phát hiện **${negativeTxs.length}** giao dịch có tác động tiêu cực đến điểm tin cậy. Giao dịch gây ảnh hưởng xấu nhất đã trừ **${biggestDrop}** điểm.\n`;
        } else {
            analysisText += `- **An toàn:** Không phát hiện giao dịch nào có tác động tiêu cực. Các hoạt động của ví đều tuân thủ quy tắc an toàn.\n`;
        }
        if(unblacklistCount > 0) {
            analysisText += `- **Lưu ý đặc biệt:** Ví này đã từng bị đưa vào danh sách đen và đã thực hiện kháng cáo **${unblacklistCount}** lần. Đây là một yếu tố rủi ro cần được xem xét cẩn thận.\n\n`;
        }

        analysisText += `#### Đánh giá & Đề xuất\n`;
        if (unblacklistCount > 1 || trustScore < 100) {
             analysisText += `> **Kết luận:** Mức độ rủi ro **Rất Cao**. Ví này có tiền sử kháng cáo nhiều lần hoặc đang bị chặn. Giao dịch với ví này tiềm ẩn nguy cơ lớn.\n> **Đề xuất:** **KHÔNG** nên thực hiện giao dịch với ví này.`;
        } else if (trustScore < 300 || unblacklistCount > 0) {
            analysisText += `> **Kết luận:** Mức độ rủi ro **Cao**. Ví này có điểm tin cậy thấp và có tiền sử hoạt động đáng ngờ. \n> **Đề xuất:** Hết sức thận trọng khi giao dịch. Chỉ thực hiện giao dịch với số tiền nhỏ nếu thực sự cần thiết.`;
        } else if (trustScore < 500) {
            analysisText += `> **Kết luận:** Mức độ rủi ro **Trung bình**. Ví có mức độ hoạt động ổn định nhưng có một vài giao dịch đáng ngờ. \n> **Đề xuất:** Để cải thiện điểm số, hãy ưu tiên giao dịch với các đối tác uy tín và tránh các giao dịch có giá trị quá lớn, bất thường.`;
        } else {
            analysisText += `> **Kết luận:** Mức độ rủi ro **Thấp**. Đây là một ví hoạt động tích cực với điểm tin cậy cao. Các giao dịch có xu hướng an toàn. \n> **Đề xuất:** Tiếp tục duy trì thói quen giao dịch tốt.`;
        }

        res.status(200).json({ status, analysis: analysisText });

    } catch (error) {
        console.error("AI Analysis Error:", error);
        res.status(500).json({ message: "Lỗi server khi thực hiện phân tích." });
    }
});
app.post('/admin/enrich-data-etherscan', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: "Thiếu địa chỉ ví." });
        }
        if (!process.env.ETHERSCAN_API_KEY) {
            return res.status(500).json({ message: "Thiếu Etherscan API Key trên server." });
        }
        const apiUrl = `https://api-sepolia.etherscan.io/api?module=account&action=txlist&address=${walletAddress}&startblock=0&endblock=99999999&sort=asc&apikey=${process.env.ETHERSCAN_API_KEY}`;
        
        const etherscanResponse = await fetch(apiUrl);
        const data = await etherscanResponse.json();

        if (data.status !== "1") {
            if (data.message === "No transactions found") {
                const newTags = ["Ví Chưa Có Giao Dịch (Etherscan)"];
                 const updatedWallet = await WalletModel.findOneAndUpdate(
                    { address: walletAddress.toLowerCase() },
                    { $addToSet: { tags: { $each: newTags } } },
                    { new: true, upsert: true, setDefaultsOnInsert: true }
                );
                return res.status(200).json({ 
                    message: `Làm giàu dữ liệu thành công! Đã thêm nhãn: ${newTags.join(', ')}`,
                    wallet: updatedWallet
                });
            }
            throw new Error(data.message || "Lỗi khi gọi Etherscan API.");
        }

        const transactions = data.result;
        const newTags = new Set();
        if (transactions.length > 50) {
            newTags.add("Hoạt Động Thường Xuyên (Etherscan)");
        }
        const firstTxTimestamp = parseInt(transactions[0].timeStamp);
        const ageInDays = (Date.now() / 1000 - firstTxTimestamp) / 86400;

        if (ageInDays < 7) {
            newTags.add("Ví Mới (Etherscan)");
        } else if (ageInDays > 365) {
            newTags.add("Ví Lâu Năm (Etherscan)");
        }
        
        const tagsArray = Array.from(newTags);
        if (tagsArray.length === 0) {
            return res.status(200).json({ message: "Không có nhãn mới nào để thêm từ Etherscan." });
        }

        const updatedWallet = await WalletModel.findOneAndUpdate(
            { address: walletAddress.toLowerCase() },
            { $addToSet: { tags: { $each: tagsArray } } },
            { new: true, upsert: true, setDefaultsOnInsert: true }
        );

        res.status(200).json({ 
            message: `Làm giàu dữ liệu thành công! Đã thêm các nhãn: ${tagsArray.join(', ')}`,
            wallet: updatedWallet
        });

    } catch (error) {
        console.error("Enrich Data Etherscan Error:", error);
        res.status(500).json({ message: "Lỗi server khi làm giàu dữ liệu từ Etherscan." });
    }
});

// --- MỚI: API KIỂM TRA RỦI RO ĐA LỚP ---
app.post('/wallet/analyze-risk-comprehensive', async (req, res) => {
    try {
        const { walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ message: "Thiếu địa chỉ ví." });
        }

        let isScam = false;
        let riskDetails = [];

        // Lớp 1: Kiểm tra Database nội bộ của Detectus
        const internalWalletData = await WalletModel.findOne({ address: walletAddress.toLowerCase() });
        if (internalWalletData) {
            if (internalWalletData.frozen) {
                isScam = true;
                riskDetails.push("Bị đóng băng bởi Admin");
            }
            if (internalWalletData.trustScore < 200) { // Ngưỡng rủi ro cao
                isScam = true;
                riskDetails.push(`Điểm tin cậy Detectus rất thấp (${internalWalletData.trustScore})`);
            }
        }
        
        // Lớp 2: Kiểm tra GoPlus Security API
        try {
            const goPlusUrl = `https://api.gopluslabs.io/api/v1/address_security/${walletAddress}?chain_id=1`;
            const goPlusResponse = await fetch(goPlusUrl);
            if (goPlusResponse.ok) {
                const goPlusData = await goPlusResponse.json();
                if (goPlusData.code === 1 && goPlusData.result && goPlusData.result[walletAddress.toLowerCase()]) {
                    const result = goPlusData.result[walletAddress.toLowerCase()];
                    if (result.cybercrime === "1" || result.financial_crime === "1" || result.blacklist_doubt === "1" || result.stealing_attack === "1" || result.honeypot_related_address === "1") {
                        isScam = true;
                        riskDetails.push("Gắn cờ bởi GoPlus Security");
                    }
                }
            }
        } catch (e) { console.error("GoPlus API check failed:", e.message); }


        // Lớp 3: Kiểm tra nhãn trên Etherscan (yêu cầu API Key)
        if (process.env.ETHERSCAN_API_KEY) {
            try {
                const etherscanUrl = `https://api.etherscan.io/api?module=account&action=txlist&address=${walletAddress}&startblock=0&endblock=1&page=1&offset=1&sort=asc&apikey=${process.env.ETHERSCAN_API_KEY}`;
                const etherscanResponse = await fetch(etherscanUrl);
                 if (etherscanResponse.ok) {
                    // Etherscan không có API trực tiếp lấy tag, nhưng ta có thể kiểm tra các tên miền .eth hoặc các thông tin khác nếu có
                    // Đây là một ví dụ đơn giản, thực tế cần các kỹ thuật phức tạp hơn hoặc dịch vụ chuyên dụng
                 }
            } catch (e) { console.error("Etherscan check failed:", e.message); }
        }


        res.status(200).json({
            is_scam: isScam,
            details: isScam ? riskDetails.join('; ') : "An toàn"
        });

    } catch (error) {
        console.error("Comprehensive Risk Check Error:", error);
        res.status(500).json({ is_scam: false, details: "Lỗi server khi kiểm tra." });
    }
});


// Khởi động Server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
