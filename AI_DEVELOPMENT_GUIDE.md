# 🤖 AI Development & Extension Guide (Hướng Dẫn Phát Triển Cho AI)

> **Dành cho AI Coding Assistants (Cursor, Claude, Antigravity IDE, ChatGPT)**: Tài liệu này giải thích cấu trúc kiến trúc, cơ chế reactive nội tại, mô hình dữ liệu và cách thêm tính năng mới vào **DC Portal Template** một cách chính xác nhất mà không làm gãy hệ thống.

---

## 1. Tổng quan Kiến trúc (Architecture Overview)

DC Portal Template được thiết kế theo triết lý **Zero-Build & Ultra-Fast Native Performance**:
- **Backend**: Node.js thuần (`node:http`), không dùng Express, tự xây dựng bộ xử lý routing, multipart file upload, cookie session, HMAC crypto, Firestore và BigQuery connectors. Toàn bộ logic server tập trung trong `server.mjs`.
- **Frontend Reactive Core**: `support.js` chứa engine component hóa độc quyền (`DCComponent`), hỗ trợ data binding hai chiều, virtual DOM/diffing cơ bản, vòng đời component và syntax template tùy biến (`{{ variable }}`, `<sc-if>`, `<sc-for>`).
- **Giao diện chính**: `DC Portal.dc.html` chứa toàn bộ ứng dụng quản trị (Dashboard, Bán hàng, Tài chính, Marketing, Nhân sự, Cài đặt).
- **Hệ thống form tương tác ngoài**: `sales-form.html` (trang đích khách hàng điền lead) và `sales-form-builder.html` (công cụ thiết kế kéo thả form).

---

## 2. Cách Cơ chế Reactive trong `support.js` Hoạt động

Frontend không dùng React hay Vue nhưng có tư duy tương tự:

### 2.1. Khởi tạo Component & State
```javascript
class MyModuleComponent extends DCComponent {
  constructor() {
    super();
    this.state = {
      items: [],
      filter: 'all',
      isLoading: false
    };
  }

  // Khai báo data được truyền vào template HTML
  data() {
    return {
      itemsList: this.state.items,
      p_isLoading: this.state.isLoading,
      currentFilter: this.state.filter,
      setFilter: (e) => this.setState({ filter: e.target.value }),
      refreshData: () => this.fetchData()
    };
  }
}
```

### 2.2. Template Syntax trong file `.html`
Engine `support.js` phân tích các thẻ và cú pháp sau:
- **Biến hiển thị**: `{{ variableName }}`
- **Điều kiện hiển thị (`<sc-if>`)**:
  ```html
  <sc-if value="{{ p_isLoading }}" hint-placeholder-val="">
    <div class="loading-spinner">Đang tải dữ liệu...</div>
  </sc-if>
  ```
  *(Quy ước: Các cờ boolean trong state thường đặt tiền tố `p_` trong hàm `data()` để template dễ nhận diện)*.
- **Vòng lặp danh sách (`<sc-for>`)**:
  ```html
  <sc-for list="{{ itemsList }}" as="item" hint-placeholder-count="5">
    <div class="table-row">
      <span>{{ item.title }}</span>
      <span>{{ item.amountFormatted }}</span>
    </div>
  </sc-for>
  ```
- **Sự kiện (Event Binding)**:
  `onClick="{{ handleClick }}"`, `onInput="{{ handleInput }}"`, `onChange="{{ handleChange }}"`.

### 2.3. Cập nhật giao diện với `this.setState()`
Bất cứ khi nào gọi `this.setState({ key: value })`, `support.js` sẽ tự động tính toán lại hàm `data()` và re-render DOM tại các vị trí thay đổi mà không làm reload trang.

---

## 3. Hướng Dẫn Thêm Một Module / Trang Mới (Step-by-Step)

Giả sử bạn muốn tạo thêm một module quản lý mới: **Quản lý Kho (Inventory Management)**.

### Bước 1: Khai báo Phân quyền (RBAC)
Mở [server.mjs](file:///c:/Users/lenle/Dropbox/Mo%20Mang/DIGIFITY/App/DC%20portal%20template/server.mjs):
1. Tìm hằng số `roleModules` và thêm module `'inventory'` vào các vai trò được phép truy cập (Admin, Quản lý):
   ```javascript
   const roleModules = {
     Admin: [..., 'inventory'],
     'Quản lý': [..., 'inventory'],
   };
   ```
2. Trong hàm `data()` của [DC Portal.dc.html](file:///c:/Users/lenle/Dropbox/Mo%20Mang/DIGIFITY/App/DC%20portal%20template/DC%20Portal.dc.html), thêm cờ kiểm tra quyền:
   ```javascript
   canAccessInventory: this.hasModule('inventory'),
   ```

### Bước 2: Thêm Menu Điều hướng (Sidebar Navigation)
Trong phần Sidebar của [DC Portal.dc.html](file:///c:/Users/lenle/Dropbox/Mo%20Mang/DIGIFITY/App/DC%20portal%20template/DC%20Portal.dc.html):
```html
<sc-if value="{{ canAccessInventory }}">
  <div class="nav-item {{ isInventoryActive }}" onClick="{{ goToInventory }}">
    <span class="ms">inventory_2</span>
    <span class="label">Kho hàng</span>
  </div>
</sc-if>
```

### Bước 3: Thêm Giao diện Nội dung (Section Content)
Thêm khối container giao diện trong vùng `<main>` của [DC Portal.dc.html](file:///c:/Users/lenle/Dropbox/Mo%20Mang/DIGIFITY/App/DC%20portal%20template/DC%20Portal.dc.html):
```html
<sc-if value="{{ isSectionInventory }}">
  <div class="content-section">
    <div class="section-header">
      <h2>Quản lý Kho & Tồn kho</h2>
      <button class="primary-btn" onClick="{{ openCreateInventoryModal }}">
        <span class="ms">add</span> Thêm sản phẩm
      </button>
    </div>
    <!-- Bảng dữ liệu hoặc danh sách kho hàng -->
  </div>
</sc-if>
```

### Bước 4: Viết API Endpoints trong `server.mjs`
Mở [server.mjs](file:///c:/Users/lenle/Dropbox/Mo%20Mang/DIGIFITY/App/DC%20portal%20template/server.mjs) và định nghĩa router:
```javascript
// GET danh sách sản phẩm tồn kho
if (request.method === 'GET' && requestUrl.pathname === '/api/inventory') {
  const loginId = requireLogin(request, response);
  if (!loginId) return;
  const access = await userAccess(loginId);
  if (!access.modules.includes('inventory') && access.level !== 'admin') {
    return json(response, 403, { error: 'Không có quyền truy cập kho hàng' });
  }
  
  const snapshot = await firestore.collection('inventoryItems').orderBy('updatedAt', 'desc').limit(200).get();
  const items = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
  return json(response, 200, { items });
}

// POST tạo hoặc cập nhật sản phẩm kho
if (request.method === 'POST' && requestUrl.pathname === '/api/inventory') {
  const loginId = requireLogin(request, response);
  if (!loginId) return;
  const body = await readJson(request);
  if (!body.sku || !body.title) return json(response, 400, { error: 'Vui lòng nhập SKU và tên sản phẩm' });

  const docRef = firestore.collection('inventoryItems').doc(String(body.sku).trim());
  await docRef.set({
    title: String(body.title).trim(),
    stockQuantity: Number(body.stockQuantity || 0),
    updatedAt: new Date(),
    updatedBy: loginId
  }, { merge: true });

  return json(response, 200, { success: true, sku: body.sku });
}
```

---

## 4. Các Hàm Tiện Ích Chuẩn Bị Sẵn (Pre-built Utilities)

Khi viết code cho Backend (`server.mjs`):
- `json(response, statusCode, data)`: Trả về phản hồi JSON kèm HTTP status và CORS headers.
- `readJson(request)`: Đọc body JSON dạng stream an toàn, giới hạn dung lượng chống DoS.
- `requireLogin(request, response)`: Kiểm tra session cookie, trả về `loginId` hoặc tự redirect nếu chưa đăng nhập.
- `userAccess(loginId)`: Trả về đối tượng `{ level, role, modules, special, user }`.
- `fixMojibake(text)`: Tự động sửa lỗi encoding UTF-8 / Windows-1258 khi import dữ liệu tiếng Việt.
- `normalizedSearch(text)`: Chuẩn hóa xâu ký tự (bỏ dấu tiếng Việt, ký tự hoa, khoảng trắng) để tìm kiếm nhanh.

Khi viết code cho Frontend (`DC Portal.dc.html`):
- `this.setState(partialState)`: Cập nhật reactive state.
- `formatVnd(amount)`: Định dạng số tiền VNĐ (ví dụ: `1.500.000 ₫`).
- `fetch(url, { credentials: 'same-origin', ... })`: Luôn truyền `credentials` để gửi session cookie.

---

## 5. Nguyên Tắc An Toàn Dành Cho AI Code Generator

1. **Tuyệt đối không hardcode bí mật**: Mọi token hoặc URL nhạy cảm phải đọc từ `process.env`.
2. **Bảo tồn encoding UTF-8**: Khi thao tác với file tiếng Việt, luôn dùng encoding UTF-8 không BOM.
3. **Không import thêm thư viện npm nặng**: Hãy ưu tiên sử dụng `node:crypto`, `node:fs`, `node:http` để giữ server chạy siêu nhẹ (< 50MB RAM trên Cloud Run).
