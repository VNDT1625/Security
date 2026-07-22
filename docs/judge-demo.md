# Kịch bản trình diễn Prewise cho ban giám khảo

## Mục tiêu

Chứng minh Prewise là lớp kiểm soát rủi ro trước khi người dùng hoặc AI agent hành động. Trình diễn dùng luồng sản phẩm thật; không có route `/demo` riêng.

## Chuẩn bị trước khi trình diễn

1. Khởi động backend tại `http://127.0.0.1:8000` và web tại `http://127.0.0.1:3000`.
2. Mở `http://127.0.0.1:3000/analyze`.
3. Kiểm tra backend đã nạp model trước khi bắt đầu. Chuẩn bị sẵn một video/screenshot dự phòng của cùng luồng.

## Phần 1 — URL nguy hiểm (khoảng 75 giây)

1. Chọn **Website / URL** và dán mẫu phishing được phép trong bộ demo cục bộ.
2. Bấm **Phân tích nội dung**.
3. Trình bày quyết định `WARN` hoặc `BLOCK`, risk score và các evidence như domain giả mạo, typo-squatting, homoglyph, HTTP hoặc credential lure.
4. Mở chi tiết các lớp kiểm tra để giải thích rằng Prewise không chỉ trả một nhãn: hệ thống phân biệt lớp đã chạy, bị bỏ qua và không khả dụng.

## Phần 2 — URL an toàn (khoảng 45 giây)

1. Quay lại `/analyze` và dán URL an toàn đã xác minh trong bộ demo.
2. Chạy cùng mức phân tích.
3. Đối chiếu kết quả để chứng minh Prewise không chặn mọi URL có từ khóa nhạy cảm.

## Phần 3 — Local Shield → Windows Cloud Lab (khoảng 90 giây)

1. Trong ứng dụng Desktop, chọn một EXE thử nghiệm do đội sở hữu. Chỉ ra SHA-256,
   chữ ký Authenticode và việc file chưa được chạy.
2. Chọn **Auto Analyze**. Trình bày cây tiến trình, file trong vùng giám sát,
   registry persistence và network theo PID; kết thúc bằng trạng thái VM đã được
   hủy, không chỉ “đã gửi yêu cầu hủy”.
3. Với một lượt khác, chọn **Interactive Investigate · 5 phút**. Nhấn mạnh mẫu
   chỉ được stage, không tự chạy; đồng hồ bắt đầu sau `ready` và desktop chỉ mở
   sau one-time handshake với private broker.
4. Dừng phiên và chỉ ra chuỗi `termination_requested → terminating → terminated`.

Nếu Interactive AMI/broker chưa được cấu hình, không dùng màn hình giả. Hiển thị
trạng thái fail-visible và chuyển sang video dự phòng của chính build đã kiểm thử.

## Phần 4 — Bảo vệ AI agent (khoảng 60 giây)

1. Chạy MCP server trên máy cục bộ và gọi `scan_prompt_injection` với payload prompt injection nằm trong bộ mẫu được phép.
2. Trình bày evidence và policy quyết định trước khi agent được phép ghi memory, dùng tool hoặc thực hiện hành động nhạy cảm.
3. Chạy một prompt an toàn để đối chiếu. Không sử dụng secret, dữ liệu cá nhân hoặc kết nối tới hệ thống bên thứ ba.

## Thông điệp kết thúc

Prewise không thay thế mô hình nghiệp vụ hoặc người dùng. Nó tập hợp bằng chứng, công khai mức độ chắc chắn và áp policy `ALLOW/WARN/BLOCK` trước khi một hành động rủi ro diễn ra.

## Giới hạn phải nêu rõ

- Kết quả URL là đánh giá rủi ro, không phải kết luận pháp y.
- Các nguồn ngoài hoặc sandbox không khả dụng sẽ được hiển thị là chưa kiểm tra, không bị coi là an toàn.
- Auto và Interactive chỉ chạy mẫu do đội sở hữu/được phép; không tải hoặc phát tán malware thật trong phần thi.
- “Interactive desktop” chỉ được tuyên bố đã vận hành khi AMI và private broker đã qua một ca end-to-end; code/UI một mình chưa phải bằng chứng hạ tầng.
- Sàng lọc ảnh AI-generated chỉ hỗ trợ ảnh và frame video; không phân tích audio hoặc tính nhất quán chuyển động.
