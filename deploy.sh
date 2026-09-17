#!/usr/bin/env bash
# ==============================================================================
# 🚀 1-Click Deployment Script for Google Cloud Run (Linux/macOS Bash)
# ==============================================================================
set -e

PROJECT_ID=${1:-$GOOGLE_CLOUD_PROJECT}
REGION=${2:-"asia-southeast1"}
SERVICE_NAME=${3:-"dc-portal-template"}

echo "====================================================="
echo "  🚀 DC PORTAL TEMPLATE - CLOUD RUN DEPLOYMENT       "
echo "====================================================="

if [ -z "$PROJECT_ID" ]; then
    read -p "Nhập Google Cloud Project ID của bạn: " PROJECT_ID
fi

if [ -z "$PROJECT_ID" ]; then
    echo "❌ Lỗi: Google Cloud Project ID không được để trống."
    exit 1
fi

echo "📌 Project ID: $PROJECT_ID"
echo "📌 Region:     $REGION"
echo "📌 Service:    $SERVICE_NAME"

# Check gcloud CLI
if ! command -v gcloud &> /dev/null; then
    echo "❌ Lỗi: Không tìm thấy gcloud CLI. Vui lòng cài đặt Google Cloud SDK."
    exit 1
fi

echo -e "\n🔧 Đang cấu hình project..."
gcloud config set project "$PROJECT_ID"

echo -e "\n🚀 Đang build và deploy lên Cloud Run ($REGION)..."
gcloud run deploy "$SERVICE_NAME" \
    --source . \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --set-env-vars "PORT=8080"

SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --platform managed --region "$REGION" --format "value(status.url)")
echo -e "\n🎉 DEPLOY THÀNH CÔNG!"
echo -e "🌐 URL Dịch vụ của bạn: $SERVICE_URL"
echo -e "💡 Hãy nhớ cấu hình các biến môi trường trong Cloud Run Console!"
