import type {Metadata} from "next";
import {ShieldCheck} from "lucide-react";
import {PrewiseShell} from "@/components/PrewiseUI";
import {WaitlistProducts} from "./WaitlistProducts";
import styles from "./downloads.module.css";

export const metadata:Metadata={
 title:"Tải xuống · Prewise",
 description:"Đăng ký nhận thông báo về ứng dụng Prewise và tiện ích trình duyệt.",
};

export default function DownloadsPage(){
 return <PrewiseShell><main id="main-content" className={`inner-page downloads-page ${styles.page}`}>
  <header className="inner-head">
   <span>PREWISE / DOWNLOADS</span>
   <h1>Tải lớp bảo vệ<br/>đến thiết bị của bạn.</h1>
   <p>Ứng dụng và extension hiện chưa có bản phát hành công khai. Đăng ký để nhận thông báo ngay khi bộ cài đã ký hoặc liên kết cửa hàng chính thức sẵn sàng.</p>
  </header>
  <WaitlistProducts/>
  <aside className="download-safety">
   <ShieldCheck aria-hidden/>
   <div><b>Chỉ tải từ nguồn chính thức</b><p>Prewise sẽ công bố checksum và chữ ký số cho từng bản phát hành. Không cài các tệp mang tên Prewise từ nguồn bên ngoài.</p></div>
  </aside>
 </main></PrewiseShell>;
}
