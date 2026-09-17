# ==============================================================================
# 🚀 1-Click Deployment Script for Google Cloud Run (Windows PowerShell)
# ==============================================================================
param (
    [string]$ProjectId = $env:GOOGLE_CLOUD_PROJECT,
    [string]$Region = "asia-southeast1",
    [string]$ServiceName = "dc-portal-template"
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  🚀 DC PORTAL TEMPLATE - CLOUD RUN DEPLOYMENT       " -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

if (-not $ProjectId) {
    $ProjectId = Read-Host "Nhập Google Cloud Project ID của bạn"
}

if (-not $ProjectId) {
    Write-Host "❌ Lỗi: Google Cloud Project ID không được để trống." -ForegroundColor Red
    exit 1
}

Write-Host "📌 Project ID: $ProjectId" -ForegroundColor Yellow
Write-Host "📌 Region:     $Region" -ForegroundColor Yellow
Write-Host "📌 Service:    $ServiceName" -ForegroundColor Yellow

# Verify gcloud is installed
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Lỗi: Không tìm thấy gcloud CLI. Vui lòng cài đặt Google Cloud SDK." -ForegroundColor Red
    exit 1
}

# Set current project
Write-Host "`n🔧 Đang cấu hình project..." -ForegroundColor Green
gcloud config set project $ProjectId

# Pre-flight check: ensure .env is not uploaded
if (Test-Path ".env") {
    Write-Host "⚠️ Cảnh báo: Tìm thấy file .env tại thư mục gốc. File này sẽ tự động được bỏ qua nhờ .gcloudignore." -ForegroundColor Yellow
}

# Deploy to Cloud Run using source deploy
Write-Host "`n🚀 Đang build và deploy lên Cloud Run (asia-southeast1)..." -ForegroundColor Green
gcloud run deploy $ServiceName `
    --source . `
    --platform managed `
    --region $Region `
    --allow-unauthenticated `
    --set-env-vars "PORT=8080"

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n🎉 DEPLOY THÀNH CÔNG!" -ForegroundColor Green
    $serviceUrl = (gcloud run services describe $ServiceName --platform managed --region $Region --format "value(status.url)")
    Write-Host "🌐 URL Dịch vụ của bạn: $serviceUrl" -ForegroundColor Cyan
    Write-Host "💡 Hãy nhớ cấu hình các biến môi trường (LARK_APP_ID, SEPAY_API_KEY, v.v.) trong Cloud Run Console!" -ForegroundColor Yellow
} else {
    Write-Host "`n❌ Deploy thất bại. Vui lòng kiểm tra lại log bên trên." -ForegroundColor Red
}
