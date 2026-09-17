# ⚡ DC Portal Template — Enterprise Operations & Commerce Portal

> **Mẫu Portal Doanh Nghiệp Tinh Gọn (Zero-Build, High-Performance, AI-Ready)**  
> Tích hợp toàn diện: Thương mại đa kênh, Tài chính & Sao kê tự động SePay, Lark Suite SSO & Chatbot, BigQuery Data Warehouse, Meta Ads & CRM Conversions API.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![Google Cloud Run](https://img.shields.io/badge/Deploy-Cloud%20Run-blue.svg)](https://cloud.google.com/run)
[![AI Ready](https://img.shields.io/badge/AI%20Assisted-Claude%20%7C%20Cursor%20%7C%20Antigravity-orange.svg)](#hướng-dẫn-phát-triển-bằng-ai)

---

## 🌟 Điểm Nổi Bật Của Template

1. **Kiến Trúc Zero-Build Siêu Tốc**:
   - Backend thuần Node.js (`node:http`), khởi động tức thì trong < 100ms, tiêu thụ dưới 50MB RAM.
   - Frontend component hóa thông minh với engine reactive độc quyền trong [support.js](support.js). Không cần build step, không cần Webpack hay Vite cồng kềnh.
2. **Bảo Mật Tiêu Chuẩn Doanh Nghiệp**:
   - Mã nguồn đã được lọc sạch 100% token, API key, số tài khoản công ty và dữ liệu nội bộ.
   - Cơ chế bảo vệ Super Admin qua biến môi trường `SUPERADMIN_EMAILS`.
   - Xác thực đa dạng: Lark SSO (Feishu) hoặc Email OTP một lần có khóa tên miền `ALLOWED_EMAIL_DOMAINS`.
3. **Thương Mại & Vận Hành Đa Kênh**:
   - Đồng bộ đơn hàng từ Shopify, Pancake POS, Lead Form tự thiết kế, Shopee, TikTok Shop.
   - Phân tích phễu chuyển đổi và tracking UTM chi tiết từng chiến dịch quảng cáo.
4. **Tài Chính Tự Động Hóa (SePay)**:
   - Kết nối SePay Webhook nhận biến động số dư ngân hàng theo thời gian thực.
   - Tự động đối soát đơn hàng với tiền thực tế vào tài khoản ngân hàng.
   - Quy trình duyệt chi và hoàn ứng 2 cấp (Lớp 1 & Lớp 2) chặt chẽ.
5. **AI-Friendly Codebase**:
   - Đi kèm [AI_DEVELOPMENT_GUIDE.md](AI_DEVELOPMENT_GUIDE.md) giải thích toàn bộ data model và cú pháp reactive, giúp các AI assistant (Claude, Cursor, Antigravity, ChatGPT) dễ dàng mở rộng tính năng mới theo yêu cầu.

---

## 📁 Cấu Trúc Dự Án (Project Structure)

```text
├── server.mjs                  # Backend HTTP server, API endpoints, auth, webhooks
├── support.js                  # Engine reactive, virtual DOM diffing, component core
├── DC Portal.dc.html           # Ứng dụng quản trị chính (Dashboard, Sales, Finance, HR)
├── Login.dc.html               # Trang đăng nhập bảo mật (Lark SSO + Email OTP)
├── sales-form.html             # Giao diện landing page form thu thập Lead
├── sales-form-builder.html     # Công cụ thiết kế form kéo thả không cần code
├── organization.html           # Sơ đồ tổ chức & nhân sự công ty
├── assets/                     # Logo, icon tích hợp các nền tảng (Shopify, Meta, v.v.)
├── warehouse_bootstrap.sql     # Script SQL khởi tạo schema Data Warehouse BigQuery
├── warehouse_onboard.ps1       # Script PowerShell tự động setup BigQuery & IAM
├── Dockerfile                  # Container tối ưu cho Google Cloud Run
├── deploy.ps1 & deploy.sh      # Script 1-click build & deploy lên Google Cloud Run
├── .env.example                # File mẫu cấu hình tất cả biến môi trường
├── SECURITY_CHECKLIST.md       # Bảng kiểm tra an toàn trước khi chạy Production
└── AI_DEVELOPMENT_GUIDE.md     # Hướng dẫn chi tiết dành cho AI Coding Tools
```

---

## 🚀 Hướng Dẫn Bắt Đầu Nhanh (Quick Start)

### 1. Chạy Tại Máy Cục Bộ (Local Development)

Yêu cầu: Đã cài đặt **Node.js 18+**.

```bash
# 1. Clone repository
git clone https://github.com/lenle698/DC-Portal-Template.git
cd DC-Portal-Template

# 2. Tạo file cấu hình môi trường từ mẫu
cp .env.example .env

# 3. Chỉnh sửa thông tin cần thiết trong file .env

# 4. Chạy server với chế độ tự động reload (watch mode)
npm run dev
```

Mở trình duyệt tại: `http://localhost:8080`.

---

## ☁️ Triển Khai Lên Google Cloud Run (Production Deployment)

### Cách 1: Sử Dụng Script 1-Click (Khuyến nghị)

**Trên Windows (PowerShell):**
```powershell
.\deploy.ps1 -ProjectId "your-gcp-project-id" -Region "asia-southeast1"
```

**Trên Linux / macOS (Bash):**
```bash
chmod +x deploy.sh
./deploy.sh "your-gcp-project-id" "asia-southeast1"
```

### Cách 2: Lệnh `gcloud` Trực Tiếp

```bash
gcloud run deploy dc-portal-template \
  --source . \
  --platform managed \
  --region asia-southeast1 \
  --allow-unauthenticated \
  --set-env-vars PORT=8080,COMPANY_NAME="My Company",SUPERADMIN_EMAILS="admin@example.com"
```

---

## 🔑 Cấu Hình Biến Môi Trường (.env)

Xem chi tiết đầy đủ trong [.env.example](.env.example) và hướng dẫn an ninh trong [SECURITY_CHECKLIST.md](SECURITY_CHECKLIST.md).

Các biến môi trường cơ bản:
- `PORTAL_BASE_URL`: URL chính thức của Portal (ví dụ: `https://portal.mycompany.vn`).
- `SUPERADMIN_EMAILS`: Email quản trị viên có quyền tối cao (phân cách bằng dấu phẩy).
- `ALLOWED_EMAIL_DOMAINS`: Tên miền email nhân sự được phép đăng nhập (ví dụ: `mycompany.vn`).
- `LARK_APP_ID` & `LARK_APP_SECRET`: Khóa API ứng dụng Lark Suite / Feishu.
- `SEPAY_API_KEY`: API Token đồng bộ biến động số dư SePay.
- `ORDER_INGEST_SECRET`: Khóa bí mật nhận webhook đơn hàng từ bên ngoài.

---

## 🤖 Hướng Dẫn Phát Triển Bằng AI

Bạn có thể mở repository này bằng các công cụ AI IDE hiện đại như **Cursor**, **Antigravity**, hoặc **Claude Code**. Khi muốn thêm tính năng mới, hãy nhắc AI:

> *"Đọc file [AI_DEVELOPMENT_GUIDE.md](AI_DEVELOPMENT_GUIDE.md) để hiểu quy ước kiến trúc reactive trong support.js và cấu trúc router trong server.mjs trước khi code."*

AI sẽ tự động tuân thủ cách khai báo component, binding state hai chiều và viết endpoint API chuẩn xác theo phong cách của dự án.

---

## 📄 Bản Quyền & Giấy Phép

Phát hành dưới giấy phép [MIT License](LICENSE). Tự do sử dụng cho mục đích cá nhân và thương mại.
