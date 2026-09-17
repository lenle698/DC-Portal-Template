# 🛡️ Pre-Flight Security Checklist & Hardening Guide

Trước khi deploy ứng dụng lên production (ví dụ: Google Cloud Run `https://portal-xxxx-uc.a.run.app` hoặc domain tùy chỉnh), hãy kiểm tra toàn diện danh sách sau để đảm bảo bảo mật dữ liệu và an toàn hệ thống.

---

## 1. Kiểm tra Source Code & Git Repository (Code Sanitization)

- [ ] **Không lưu file `.env` vào Git**: Đảm bảo file `.gitignore` đã có `.env`, `.env.local`, `.env.*.local`.
- [ ] **Không hardcode API Token / Secret**:
  - `SEPAY_API_KEY` chỉ lấy từ biến môi trường `process.env.SEPAY_API_KEY`.
  - `LARK_APP_SECRET` chỉ lấy từ `process.env.LARK_APP_SECRET`.
  - `ORDER_INGEST_SECRET` chỉ lấy từ `process.env.ORDER_INGEST_SECRET`.
  - `META_APP_SECRET` và token truy cập Meta lấy từ `process.env`.
- [ ] **Không hardcode số tài khoản ngân hàng / PII cá nhân**:
  - Sử dụng biến `DEFAULT_BANK_ACCOUNT` và `COMPANY_NAME`.
  - Không hardcode danh sách tên nhân viên hoặc email cá nhân trong bộ lọc đơn hàng / doanh số.
- [ ] **Không hardcode ID nhóm chat Lark / Chatbot**:
  - Sử dụng `LARK_NOTIFICATION_CHAT_ID` hoặc `LARK_ORDER_NOTIFICATION_WEBHOOK_URL`.

---

## 2. Quản lý Quyền Truy cập & Xác thực (Authentication & RBAC)

- [ ] **Super Admin Protection**:
  - Cấu hình biến `SUPERADMIN_EMAILS` trong Cloud Run (ví dụ: `admin@yourdomain.com`).
  - Hệ thống kiểm tra quyền quản trị tối cao qua `role === 'admin' || user.isSuperAdmin || superadminEmails.has(email)`.
- [ ] **Xác thực Email OTP**:
  - Cấu hình `ALLOWED_EMAIL_DOMAINS=yourdomain.com` để chặn việc đăng nhập từ các email lạ bên ngoài doanh nghiệp.
  - OTP có thời hạn 5 phút, được hash bằng HMAC-SHA256 với secret server, có giới hạn thời gian yêu cầu lại (rate limit 45s).
- [ ] **Lark OAuth**:
  - Thêm URL Redirect chính xác vào Lark Developer Console: `https://<YOUR_APP_DOMAIN>/auth/lark/callback`.
  - Cấu hình `LARK_LOGIN_ALLOWLIST` nếu muốn chỉ cho phép một nhóm nhân sự cụ thể được truy cập.

---

## 3. Bảo vệ Webhook & API Endpoints (Webhook Security)

- [ ] **Webhook Đơn Hàng (`/api/webhooks/orders/:source`)**:
  - Luôn yêu cầu header `x-dc-order-secret` khớp với `ORDER_INGEST_SECRET` trên Cloud Run.
  - Chặn brute-force và kiểm tra chữ ký secret.
- [ ] **Webhook SePay Realtime (`/api/sepay/webhook`)**:
  - Khuyến nghị bật `strictAuth` trong cài đặt SePay của Portal để kiểm tra Token bí mật gửi từ SePay.
- [ ] **Meta Sync Cron Secret (`/api/marketing/cron-sync`)**:
  - Cấu hình `META_SYNC_CRON_SECRET` để Cloud Scheduler gửi header `Authorization: Bearer <SECRET>` khi kích hoạt đồng bộ tự động.

---

## 4. Google Cloud Platform (GCP) IAM & Least Privilege

- [ ] **Service Account chạy Cloud Run**:
  - Không dùng Service Account mặc định của Compute Engine (có quyền Editor quá rộng).
  - Tạo Service Account riêng, ví dụ: `portal-runner@<PROJECT_ID>.iam.gserviceaccount.com`.
  - Chỉ gán các role tối thiểu cần thiết:
    - `Cloud Datastore User` (để đọc/ghi Firestore)
    - `BigQuery Data Editor` & `BigQuery Job User` (để query/ghi kho dữ liệu)
    - `Storage Object Admin` (trên bucket uploads file)
- [ ] **Google Cloud Storage Bucket**:
  - Cấu hình CORS chặt chẽ, chỉ cho phép Origin từ domain Portal.
  - Kích hoạt Uniform bucket-level access.
- [ ] **Google Cloud Armor / Cloudflare** (Tùy chọn nâng cao):
  - Bật WAF hoặc Cloudflare WARP để ngăn chặn DDoS và chặn truy cập từ các dải IP bất thường.

---

## 5. Danh sách Biến Môi trường Tối thiểu Bắt buộc Khi Chạy Production

| Biến Môi Trường | Mô Tả | Ví Dụ |
| :--- | :--- | :--- |
| `PORT` | Cổng HTTP lắng nghe (Cloud Run tự set `8080`) | `8080` |
| `PORTAL_BASE_URL` | Domain chính thức của Portal | `https://portal.mycompany.vn` |
| `COMPANY_NAME` | Tên công ty / tổ chức | `Công Ty TNHH Mẫu` |
| `SUPERADMIN_EMAILS` | Email super admin hệ thống | `ceo@mycompany.vn,tech@mycompany.vn` |
| `ALLOWED_EMAIL_DOMAINS`| Tên miền email nhân viên được phép nhận OTP | `mycompany.vn` |
| `LARK_APP_ID` | App ID ứng dụng Lark | `cli_a1b2c3d4e5` |
| `LARK_APP_SECRET` | App Secret ứng dụng Lark | `s3cr3t...` |
| `LARK_REDIRECT_URI` | Callback URL OAuth Lark | `https://portal.mycompany.vn/auth/lark/callback` |
| `ORDER_INGEST_SECRET` | Secret xác thực webhook đơn hàng | `my_super_secret_order_key` |
| `SEPAY_API_KEY` | Token API đồng bộ SePay | `DX5...` |
| `SMTP_USER` & `SMTP_PASS` | Tài khoản gửi email OTP | `no-reply@mycompany.vn` |
