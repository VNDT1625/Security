import { PrewiseShell } from "@/components/PrewiseUI";
import styles from "./methodology.module.css";
export default function Methodology() {
  return (
    <PrewiseShell>
      <main className={`inner-page method-page ${styles.page}`}>
        <header className="inner-head">
          <p className="eyebrow">
            <i /> TRUST BY DESIGN
          </p>
          <h1>Minh bạch, không phải hộp đen.</h1>
          <p>
            Prewise giải thích cách từng tín hiệu đóng góp vào kết quả — và luôn
            nói rõ những điều hệ thống chưa chắc chắn.
          </p>
        </header>
        <div className="method-grid">
          <aside>
            <a href="#meaning">01 · Cách đọc kết quả</a>
            <a href="#pipeline">02 · Quy trình đánh giá</a>
            <a href="#limits">03 · Giới hạn</a>
            <a href="#privacy">04 · Quyền riêng tư</a>
          </aside>
          <article>
            <section id="meaning">
              <span>01 / CÁCH ĐỌC KẾT QUẢ</span>
              <h2>Kết luận rõ ràng, bằng chứng cụ thể.</h2>
              <p>
                Hệ thống giữ phép tính kỹ thuật ở bên trong và hiển thị kết luận
                An toàn, Đáng ngờ hoặc Rủi ro cao. Quyết định cuối dựa trên bằng
                chứng và chính sách bảo vệ.
              </p>
              <div className="risk-scale" aria-label="Các mức kết luận rủi ro">
                <i />
                <div>
                  <b><small>An toàn</small></b>
                  <b><small>Đáng ngờ</small></b>
                  <b><small>Rủi ro cao</small></b>
                </div>
              </div>
            </section>
            <section id="pipeline">
              <span>02 / QUY TRÌNH</span>
              <h2>Từ nội dung thô đến bằng chứng.</h2>
              <div className="method-cards">
                <div>
                  <b>01</b>
                  <h3>Chuẩn hóa</h3>
                  <p>Bảo toàn ngữ cảnh của URL, email và tin nhắn.</p>
                </div>
                <div>
                  <b>02</b>
                  <h3>Phát hiện</h3>
                  <p>Nhận diện giả mạo, thúc ép và thu thập dữ liệu.</p>
                </div>
                <div>
                  <b>03</b>
                  <h3>Đối chiếu</h3>
                  <p>Liên kết từng kết luận với bằng chứng cụ thể.</p>
                </div>
              </div>
            </section>
            <section id="limits">
              <span>03 / GIỚI HẠN</span>
              <h2>AI có thể sai.</h2>
              <p>
                Website mới, ngữ cảnh thiếu hoặc kỹ thuật tấn công chưa từng
                thấy có thể tạo ra kết quả không chính xác. Hãy coi Prewise là
                lớp hỗ trợ quyết định và luôn xác minh qua kênh chính thức.
              </p>
            </section>
            <section id="privacy">
              <span>04 / QUYỀN RIÊNG TƯ</span>
              <h2>Bạn kiểm soát dữ liệu của mình.</h2>
              <p>
                Nội dung chỉ được gửi khi bạn chủ động nhấn Phân tích. Webcam và
                microphone không được sử dụng. Lịch sử bản demo được lưu cục bộ
                và có thể xóa bất kỳ lúc nào.
              </p>
            </section>
          </article>
        </div>
      </main>
    </PrewiseShell>
  );
}
