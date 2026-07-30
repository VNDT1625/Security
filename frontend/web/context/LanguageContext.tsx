"use client";

import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type Language = "vi" | "en";

const STORAGE_KEY = "prewise-language";
const SETTINGS_KEY = "prewise-settings";
const LANGUAGE_EVENT = "prewise-language-change";

export const ENGLISH_TRANSLATIONS: Record<string, string> = {
  "Bỏ qua đến nội dung chính": "Skip to main content",
  "Điều hướng chức năng": "Feature navigation",
  "Phân tích": "Analyze",
  "Phân tích mới": "New analysis",
  "Mở chức năng phân tích": "Open analysis",
  "Lịch sử": "History",
  "Mở lịch sử phân tích": "Open analysis history",
  "Minh bạch": "Transparency",
  "Mở thông tin minh bạch": "Open transparency information",
  "Quản lý API key": "Manage API key",
  "Tải ứng dụng & tiện ích": "Download apps & extensions",
  "Tải ứng dụng và tiện ích mở rộng": "Download apps and browser extensions",
  "Môi trường giả lập Windows": "Windows sandbox",
  "Mở môi trường giả lập Windows": "Open Windows sandbox",
  "Mở menu tài khoản": "Open account menu",
  "Khách Prewise": "Prewise guest",
  "Chưa đăng nhập": "Not signed in",
  "Đăng nhập / Đăng ký": "Sign in / Sign up",
  "Đăng nhập hoặc tạo tài khoản": "Sign in or create an account",
  "Đăng xuất": "Sign out",
  "Người dùng Prewise": "Prewise user",
  "Tài khoản cá nhân": "Personal account",
  "Tài khoản": "Account",
  "Gói dịch vụ": "Plans",
  "Cài đặt": "Settings",
  "Về trang chủ": "Back to home",
  "Nghiêm trọng": "Critical",
  "Cao": "High",
  "Trung bình": "Medium",
  "Thấp": "Low",
  "An toàn": "Safe",
  "Ngôn ngữ hiện tại": "Current language",
  "Tiếng Việt": "Vietnamese",
  "tiếng Việt": "Vietnamese",
  "tiếng Anh": "English",
  "Chuyển sang": "Switch to",
  "Đã lưu thay đổi": "Changes saved",
  "Đã xóa toàn bộ lịch sử cục bộ": "All local history has been deleted",
  "Điều chỉnh Prewise theo cách bạn đọc, làm việc và bảo vệ dữ liệu.": "Adjust Prewise to how you read, work, and protect data.",
  "Danh mục cài đặt": "Settings categories",
  "Giao diện": "Appearance",
  "Quyền riêng tư": "Privacy",
  "Dữ liệu": "Data",
  "Ngôn ngữ": "Language",
  "Chuyển động": "Motion",
  "Điều chỉnh animation và hiệu ứng không gian.": "Adjust animations and spatial effects.",
  "Đầy đủ": "Full",
  "Cinematic và phản hồi vật lý": "Cinematic with physical feedback",
  "Cân bằng": "Balanced",
  "Mượt mà, tối ưu hiệu năng": "Smooth and performance-optimized",
  "Tối giản": "Reduced",
  "Chỉ chuyển trạng thái thiết yếu": "Essential transitions only",
  "Mật độ giao diện": "Interface density",
  "Khoảng cách giữa các thành phần trong workspace.": "Spacing between workspace elements.",
  "Thoải mái": "Comfortable",
  "Gọn": "Compact",
  "Lưu lịch sử trên thiết bị": "Save history on this device",
  "Giữ tối đa 20 lần phân tích gần nhất trong trình duyệt.": "Keep up to 20 recent analyses in this browser.",
  "Che dữ liệu nhạy cảm": "Mask sensitive data",
  "Ẩn mật khẩu, OTP và thông tin thanh toán trong bản xem trước.": "Hide passwords, OTPs, and payment details in previews.",
  "Dữ liệu thuộc quyền kiểm soát của bạn": "Your data stays under your control",
  "Prewise không dùng webcam hoặc microphone. Nội dung chỉ được xử lý khi bạn chủ động nhấn Phân tích.": "Prewise does not use your webcam or microphone. Content is processed only when you choose Analyze.",
  "Dữ liệu được lưu cục bộ": "Locally stored data",
  "Lịch sử phân tích và tùy chọn giao diện được lưu trong trình duyệt này. Chúng không tự đồng bộ sang thiết bị khác.": "Analysis history and interface preferences are stored in this browser. They are not automatically synced to other devices.",
  "Xóa lịch sử phân tích": "Delete analysis history",
  "Thao tác này không thể hoàn tác.": "This action cannot be undone.",
  "Hủy": "Cancel",
  "Xác nhận xóa": "Confirm deletion",
  "Xóa dữ liệu": "Delete data",
  "Ngôn ngữ giao diện": "Interface language",
  "Lựa chọn được lưu cho các phiên truy cập tiếp theo.": "Your choice is saved for future visits.",
  "Interface preference": "Interface preference",
  "English đã sẵn sàng. Phạm vi bản dịch được kiểm tra tự động trong mỗi bản build.": "English is ready. Translation coverage is checked automatically in every build.",
  "Model AI": "AI model",
  "Che mật khẩu, OTP và số thẻ trong bản xem trước, lịch sử và kết quả được lưu.": "Mask passwords, OTPs, and card numbers in previews, history, and saved results.",
  "Trang Lịch sử trong workspace chỉ đọc dữ liệu trên trình duyệt này. Lịch sử tài khoản được tải riêng sau khi đăng nhập.": "Workspace History reads only data from this browser. Account history is loaded separately after sign-in.",
  "Model AI của bạn": "Your AI model",
  "Đăng nhập để chọn model/chế độ AI và đồng bộ lựa chọn riêng trên mọi thiết bị.": "Sign in to choose an AI model or mode and sync your selection across devices.",
  "Đăng nhập để cấu hình": "Sign in to configure",
  "Model và chế độ AI": "AI model and mode",
  "Web hỗ trợ AI bảo mật Prewise hoặc API endpoint HTTPS. Admin chỉ quyết định chế độ và model nào được phép xuất hiện.": "The web app supports Prewise security AI or an HTTPS API endpoint. Admins only control which modes and models are available.",
  "Đã cấu hình": "Configured",
  "Chưa chọn riêng": "No personal selection",
  "Chế độ AI": "AI mode",
  "AI bảo mật Prewise": "Prewise security AI",
  "Model local trên backend": "Local model on the backend",
  "API endpoint · model riêng": "API endpoint · custom model",
  "Hiện chưa có chế độ AI nào phù hợp với web được admin cho phép.": "No web-compatible AI mode is currently enabled by an admin.",
  "Chọn model được phép": "Choose an allowed model",
  "Lưu cho tài khoản của tôi": "Save for my account",
  "Kiểm tra model": "Test model",
  "Local LLM trên máy cá nhân không thể được web hosted truy cập an toàn. Tùy chọn này chỉ có trên Desktop khi Core API cũng chạy local. Endpoint từ xa bắt buộc HTTPS.": "A hosted web app cannot safely access a personal local LLM. This option is available only on Desktop when the Core API also runs locally. Remote endpoints require HTTPS.",
  "Đang tải cài đặt tài khoản…": "Loading account settings…",
  "Đang xử lý…": "Processing…",
  "Lịch sử phân tích": "Analysis history",
  "Các lần kiểm tra được lưu cục bộ trên thiết bị này để bạn có thể xem lại.": "Checks are stored locally on this device so you can review them.",
  "Tìm theo nội dung hoặc loại…": "Search by content or type…",
  "Tất cả": "All",
  "Website": "Website",
  "Không tìm thấy kết quả": "No results found",
  "Chưa có tín hiệu nào": "No signals yet",
  "Hãy thử từ khóa hoặc bộ lọc khác.": "Try another keyword or filter.",
  "Những lần phân tích của bạn sẽ xuất hiện ở đây. Dữ liệu demo chỉ lưu trên trình duyệt.": "Your analyses will appear here. Demo data is stored only in this browser.",
  "Bắt đầu phân tích →": "Start analyzing →",
  "Minh bạch, không phải hộp đen.": "Transparent, not a black box.",
  "Prewise giải thích cách từng tín hiệu đóng góp vào kết quả — và luôn nói rõ những điều hệ thống chưa chắc chắn.": "Prewise explains how every signal contributes to the result—and clearly states what remains uncertain.",
  "Cách đọc kết quả": "How to read results",
  "Quy trình đánh giá": "Assessment process",
  "Giới hạn": "Limitations",
  "Một điểm số không phải là một phán quyết.": "A score is not a verdict.",
  "Điểm rủi ro từ 0 đến 100 biểu thị cường độ của các tín hiệu nguy hiểm được phát hiện. Điểm càng cao, người dùng càng nên thận trọng.": "A risk score from 0 to 100 reflects the strength of detected danger signals. The higher the score, the more cautious you should be.",
  "Từ nội dung thô đến bằng chứng.": "From raw content to evidence.",
  "Chuẩn hóa": "Normalize",
  "Bảo toàn ngữ cảnh của URL, email và tin nhắn.": "Preserve the context of URLs, emails, and messages.",
  "Phát hiện": "Detect",
  "Nhận diện giả mạo, thúc ép và thu thập dữ liệu.": "Identify impersonation, pressure tactics, and data harvesting.",
  "Đối chiếu": "Correlate",
  "Liên kết từng kết luận với bằng chứng cụ thể.": "Link every conclusion to specific evidence.",
  "AI có thể sai.": "AI can be wrong.",
  "Website mới, ngữ cảnh thiếu hoặc kỹ thuật tấn công chưa từng thấy có thể tạo ra kết quả không chính xác. Hãy coi Prewise là lớp hỗ trợ quyết định và luôn xác minh qua kênh chính thức.": "New websites, missing context, or unseen attack techniques can produce inaccurate results. Treat Prewise as decision support and always verify through official channels.",
  "Bạn kiểm soát dữ liệu của mình.": "You control your data.",
  "Nội dung chỉ được gửi khi bạn chủ động nhấn Phân tích. Webcam và microphone không được sử dụng. Lịch sử bản demo được lưu cục bộ và có thể xóa bất kỳ lúc nào.": "Content is sent only when you choose Analyze. Webcam and microphone are never used. Demo history is stored locally and can be deleted at any time.",
  "Phân tích tín hiệu": "Analyze a signal",
  "Phân tích thật": "Live analysis",
  "Loại nội dung": "Content type",
  "Tin nhắn": "Message",
  "Nội dung cần kiểm tra": "Content to inspect",
  "Không dán mật khẩu, mã OTP, mã khôi phục hoặc dữ liệu tài chính bí mật.": "Do not paste passwords, OTPs, recovery codes, or confidential financial data.",
  "Cách Prewise xử lý dữ liệu": "How Prewise processes data",
  "Website / URL được gửi đến Security Gateway để phân tích thật. Khi chọn Chuyên sâu, URL được kiểm tra trong browser sandbox cô lập bằng dữ liệu canary tổng hợp.": "The website or URL is sent to the Security Gateway for live analysis. In Deep mode, it is inspected in an isolated browser sandbox using synthetic canary data.",
  "ký tự": "characters",
  "Đang kiểm tra:": "Checking:",
  "Phạm vi phân tích": "Analysis scope",
  "Dấu hiệu lừa đảo": "Scam indicators",
  "Độ tin cậy & giả mạo": "Trust & impersonation",
  "Dữ liệu nhạy cảm": "Sensitive data",
  "Thao túng & thúc ép": "Manipulation & pressure",
  "Bật hoặc tắt": "Toggle",
  "Mức độ phân tích": "Analysis depth",
  "Nhanh": "Quick",
  "Chuyên sâu": "Deep",
  "Chuyên sâu sẽ chạy browser sandbox cô lập; không gửi dữ liệu thật vào biểu mẫu.": "Deep mode runs an isolated browser sandbox and never submits real data to forms.",
  "URL được xử lý khi bạn chọn phân tích. Kết quả hiển thị là phản hồi trực tiếp từ backend, không phải điểm cố định của giao diện.": "The URL is processed when you choose Analyze. Results come directly from the backend and are not hard-coded UI scores.",
  "Ngữ cảnh bổ sung cho LLM": "Additional context for the LLM",
  "Ví dụ: Đây là email từ đối tác mới; người gửi nói đã gọi xác nhận…": "Example: This email is from a new partner; the sender says they called to verify…",
  "Thông tin này sẽ được lưu cùng phiên phân tích và gửi cho LLM khi tính năng giải thích được bật.": "This information is saved with the analysis session and sent to the LLM when explanations are enabled.",
  "Hỏi trợ lý về kết quả này": "Ask the assistant about this result",
  "Risk Core được chạy lại tại backend; LLM chỉ nhận bản tóm tắt và bằng chứng đã làm sạch.": "Risk Core runs again on the backend; the LLM receives only a sanitized summary and evidence.",
  "ĐANG SUY LUẬN": "THINKING",
  "SẴN SÀNG": "READY",
  "Ngữ cảnh bạn cung cấp": "Context you provided",
  "Chưa có ngữ cảnh bổ sung cho lần phân tích này.": "No additional context was provided for this analysis.",
  "Không gửi thêm dữ liệu": "No additional data sent",
  "Vì sao có mức rủi ro này?": "Why this risk level?",
  "Tôi nên làm gì tiếp theo?": "What should I do next?",
  "Bằng chứng nào quan trọng nhất?": "Which evidence matters most?",
  "Câu hỏi cho trợ lý AI": "Question for the AI assistant",
  "Hỏi về điểm rủi ro, bằng chứng hoặc bước xử lý tiếp theo…": "Ask about the risk score, evidence, or next steps…",
  "Không tìm thấy dữ liệu phân tích để tạo context…": "No analysis data was found to build context…",
  "Đang trả lời…": "Answering…",
  "Gửi câu hỏi →": "Send question →",
  "Đang kết nối tới mô hình…": "Connecting to the model…",
  "Phân tích nội dung": "Analyze content",
  "Đang mở không gian phân tích…": "Opening analysis workspace…",
  "Chuẩn hóa URL": "Normalizing URL",
  "Phân tích tên miền và giả mạo": "Analyzing domain and impersonation",
  "Chấm điểm rủi ro": "Scoring risk",
  "Tổng hợp bằng chứng": "Compiling evidence",
  "Hãy dán URL, email hoặc tin nhắn cần kiểm tra rồi thử lại.": "Paste a URL, email, or message to inspect, then try again.",
  "Luồng kiểm tra thật hiện đã được bật cho Website / URL. Email và SMS sẽ được kết nối ở bước tiếp theo.": "Live inspection is currently available for websites and URLs. Email and SMS support is coming next.",
  "Máy chủ không thể phân tích URL này.": "The server could not analyze this URL.",
  "Không thể kết nối dịch vụ phân tích.": "Could not connect to the analysis service.",
  "Về chúng tôi": "About us",
  "Vì sao chúng tôi xây sản phẩm này": "Why we built this product",
  "Prompt injection = phishing dành cho AI.": "Prompt injection is phishing for AI.",
  "Mô hình mối đe dọa": "Threat model",
  "Kẻ tấn công": "Attacker",
  "Nội dung độc hại": "Malicious content",
  "Người": "Human",
  "Đội ngũ": "Team",
  "Công nghệ": "Technology",
  "Nền tảng được xây trên các công nghệ ML và hạ tầng hiện đại.": "The platform is built with modern ML and infrastructure technologies.",
  "Mở demo kỹ thuật": "Open technical demo",

  "Điều hướng câu chuyện": "Story navigation",
  "Vấn đề": "Problem",
  "Giải Pháp": "Solution",
  "Lý Do": "Why",
  "Hành Động": "Action",
  "PHÂN TÍCH TÍN HIỆU ↗": "ANALYZE SIGNAL ↗",
  "Dán tín hiệu cần kiểm tra…": "Paste a signal to inspect…",
  "Tín hiệu cần kiểm tra": "Signal to inspect",
  "Mở scanner": "Open scanner",
  "Quan sát tín hiệu đáng ngờ; tập trung hoặc chạm để kích hoạt cảnh báo trực quan": "Inspect the suspicious signal; focus or tap to activate the visual warning",
  "Bạn có chắc mình đang thấy": "Are you sure you are seeing",
  "toàn bộ": "the whole",
  "sự thật?": "truth?",
  "CHƯA BAO GIỜ.": "NEVER.",
  "Tài khoản của bạn đã bị hạn chế.": "Your account has been restricted.",
  "Chúng tôi phát hiện hoạt động bất thường. Hãy xác minh trong vòng": "We detected unusual activity. Verify within",
  "30 phút": "30 minutes",
  "để tránh khóa tài khoản.": "to avoid an account lock.",
  "Nút Xác minh ngay trong mẫu email lừa đảo; không tương tác": "Verify now button in a phishing email sample; non-interactive",
  "XÁC MINH NGAY ↗": "VERIFY NOW ↗",
  "MỌI THỨ ĐỀU CÓ VẺ ĐÚNG.": "EVERYTHING LOOKS RIGHT.",
  "Lừa đảo hiện đại không cần trông đáng ngờ.": "Modern scams do not need to look suspicious.",
  "Nó mượn thiết kế quen thuộc, cái tên bạn tin tưởng và khoảnh khắc bạn thiếu thời gian để suy nghĩ.": "It borrows familiar design, a name you trust, and the moment when you have no time to think.",
  "Danh tính hiển thị không khớp nguồn gửi.": "The displayed identity does not match the sender.",
  "Thúc ép hành động trước khi kiểm chứng.": "Pressures you to act before verifying.",
  "Yêu cầu mật khẩu, OTP hoặc thanh toán.": "Requests passwords, OTPs, or payment.",
  "Các ví dụ URL giả mạo": "Examples of impersonating URLs",
  "Khi vẻ ngoài có thể bị sao chép,": "When appearances can be copied,",
  "niềm tin cần bằng chứng.": "trust needs evidence.",
  "Prewise là lớp phân tích an toàn giúp phát hiện, giải thích và đánh giá tín hiệu đáng ngờ trước khi bạn quyết định tin tưởng.": "Prewise is a security analysis layer that detects, explains, and assesses suspicious signals before you decide to trust them.",
  "MỘT HỆ THỐNG · NHIỀU CÁCH SỬ DỤNG": "ONE SYSTEM · MANY WAYS TO USE IT",
  "Scanner, trợ lý, bảo vệ trong trình duyệt, sandbox và tích hợp cho AI — cùng dùng chung một lớp đánh giá.": "Scanner, assistant, browser protection, sandbox, and AI integrations—all powered by one assessment layer.",
  "Phân tích và hiểu rõ.": "Analyze and understand.",
  "Kiểm tra tín hiệu, giải thích bằng chứng và lưu lại kết quả để đối chiếu về sau.": "Inspect signals, explain the evidence, and save results for later comparison.",
  "Khả năng phân tích": "Analysis capabilities",
  "URL & website": "URLs & websites",
  "Email · Gmail · EML": "Email · Gmail · EML",
  "SMS & văn bản": "SMS & text",
  "Tệp & báo cáo": "Files & reports",
  "LỊCH SỬ ↗": "HISTORY ↗",
  "Hỗ trợ đúng ngữ cảnh.": "Help in the right context.",
  "Hỏi đáp pháp luật và an ninh mạng, gọi lại kết quả bằng @ID hoặc nhận cảnh báo ngay tại nơi rủi ro xuất hiện.": "Ask about law and cybersecurity, recall results with @ID, or receive warnings exactly where risk appears.",
  "Khả năng trợ lý và bảo vệ": "Assistant and protection capabilities",
  "Trợ lý pháp luật & ANM": "Legal & cybersecurity assistant",
  "Ngữ cảnh @ID lịch sử": "History context with @ID",
  "Cảnh báo Web & Gmail": "Web & Gmail warnings",
  "MỞ TRỢ LÝ ↗": "OPEN ASSISTANT ↗",
  "TẢI TIỆN ÍCH ↗": "GET EXTENSION ↗",
  "Kiểm chứng và kết nối.": "Verify and connect.",
  "Mở nội dung đáng ngờ trong môi trường cô lập, sau đó đưa lớp đánh giá Prewise vào AI agent và workflow.": "Open suspicious content in an isolated environment, then bring the Prewise assessment layer into AI agents and workflows.",
  "Khả năng sandbox và tích hợp": "Sandbox and integration capabilities",
  "MỞ SANDBOX ↗": "OPEN SANDBOX ↗",
  "KẾT NỐI MCP ↗": "CONNECT MCP ↗",
  "Phân tích sâu.": "Analyze deeply.",
  "Kiểm tra URL, email, SMS và file; xem mức độ rủi ro cùng các tín hiệu đứng sau kết quả.": "Inspect URLs, emails, SMS, and files; see the risk level and the signals behind the result.",
  "MỞ SCANNER ↗": "OPEN SCANNER ↗",
  "Bảo vệ đúng lúc.": "Protection at the right moment.",
  "Nhận cảnh báo ngay khi duyệt web và đọc Gmail, không cần rời khỏi nội dung đang xem.": "Get warnings while browsing and reading Gmail without leaving the content you are viewing.",
  "Mở rộng cho AI.": "Extend protection to AI.",
  "Bảo vệ AI agent bằng cách kiểm tra độ tin cậy trước khi agent thực hiện hành động.": "Protect AI agents by checking trustworthiness before they act.",
  "KẾT NỐI WORKFLOW ↗": "CONNECT WORKFLOW ↗",
  "Đây là những gì Prewise trả về.": "This is what Prewise returns.",
  "Domain giả mạo": "Impersonating domain",
  "Ngôn ngữ thúc ép": "Pressuring language",
  "Yêu cầu mật khẩu + OTP": "Password + OTP request",
  "tín hiệu được đối chiếu": "signals correlated",
  "Xem giải thích và hành động đề xuất": "View explanations and recommended actions",
  "Kiểm tra chủ động · Bảo vệ trong trình duyệt · Tích hợp vào AI": "Proactive inspection · Browser protection · AI integration",
  "Đây không phải": "This is not",
  "mối đe dọa giả định.": "a hypothetical threat.",
  "Những tín hiệu nhỏ bị bỏ qua đã trở thành tổn thất thật — được ghi nhận trong báo cáo công khai.": "Small overlooked signals have become real losses—documented in public reports.",
  "EMAIL TRÔNG HOÀN TOÀN BÌNH THƯỜNG. TỔN THẤT THÌ KHÔNG.": "THE EMAIL LOOKS COMPLETELY NORMAL. THE LOSS DOES NOT.",
  "Chỉ một email giả mạo đúng người, đúng thời điểm cũng có thể khiến khoản thanh toán bị chuyển vào tài khoản của kẻ lừa đảo.": "A single impersonating email sent to the right person at the right time can divert a payment to a scammer.",
  "Thiệt hại do email doanh nghiệp giả mạo": "Losses from business email compromise",
  "Thiệt hại do lừa đảo đầu tư": "Losses from investment fraud",
  "Đơn trình báo về lừa đảo hỗ trợ kỹ thuật": "Tech support fraud complaints",
  "DẤU HIỆU CHUNG": "COMMON SIGNALS",
  "Mạo danh người gửi": "Sender impersonation",
  "Tạo áp lực thời gian": "Time pressure",
  "Thay đổi tài khoản nhận tiền": "Changed receiving account",
  "Đánh cắp thông tin xác thực": "Credential theft",
  "Những thông điệp nguy hiểm nhất thường trông giống những gì chúng ta đã quen tin tưởng.": "The most dangerous messages often look like what we have learned to trust.",
  "Nguồn dữ liệu: FBI Internet Crime Complaint Center (IC3), Internet Crime Report 2023.": "Data source: FBI Internet Crime Complaint Center (IC3), Internet Crime Report 2023.",
  "XEM BÁO CÁO GỐC ↗": "VIEW ORIGINAL REPORT ↗",
  "Đừng để sự khẩn cấp": "Do not let urgency",
  "quyết định thay bạn.": "decide for you.",
  "DỪNG TRƯỚC KHI CLICK": "PAUSE BEFORE CLICKING",
  "KIỂM TRA NGUỒN GỬI": "CHECK THE SENDER",
  "TỰ NHẬP TÊN MIỀN": "TYPE THE DOMAIN YOURSELF",
  "KHÔNG CHIA SẺ OTP": "NEVER SHARE OTPs",
  "Nhìn kỹ trước khi tin.": "Look closely before you trust.",
  "Dán tín hiệu đáng ngờ. Prewise sẽ bóc tách điều đang ẩn phía sau.": "Paste a suspicious signal. Prewise will uncover what is hiding behind it.",
  "Dán nội dung cần kiểm tra…": "Paste content to inspect…",
  "BẮT ĐẦU PHÂN TÍCH →": "START ANALYSIS →",
  "Nhìn ra điều lừa đảo": "See what scams",
  "cố che giấu.": "try to hide.",
  "Kiểm chứng trước khi tin. Quyết định vẫn luôn thuộc về bạn.": "Verify before trusting. The decision always remains yours.",
  "SẢN PHẨM": "PRODUCT",
  "Báo cáo tín hiệu": "Report a signal",
  "TIN CẬY": "TRUST",
  "Phương pháp": "Methodology",
  "Giới hạn AI": "AI limitations",
  "THÔNG TIN": "INFORMATION",
  "Liên hệ": "Contact",
  "Điều khoản": "Terms",
  "Mở product walkthrough tương tác": "Open the interactive product walkthrough",
  "Product walkthrough Prewise": "Prewise product walkthrough",
  "Ảnh dự phòng product walkthrough Prewise": "Fallback image for the Prewise product walkthrough",
  "XEM DEMO TƯƠNG TÁC ↗": "VIEW INTERACTIVE DEMO ↗",
  "Dùng thử Scanner": "Try the Scanner",
  "Phương pháp phân tích": "Analysis methodology",
  "Liên hệ đội ngũ": "Contact the team",

  "Lab phân tích tự động": "Automated analysis lab",
  "Máy ảo theo gói tài khoản": "Virtual machine for your plan",
  "lượt": "credits",
  "Phiên cô lập": "Isolated session",
  "Làm mới": "Refresh",
  "Tự động kiểm tra": "Automated inspection",
  "Desktop tương tác": "Interactive desktop",
  "Mở website thật": "Open a live website",
  "Kiểm thử": "Inspect",
  "PHÁT HIỆN RÒ RỈ": "LEAK DETECTED",
  "HOÀN TẤT": "COMPLETED",
  "Phân tích EXE": "Analyze an EXE",
  "Chọn EXE": "Choose EXE",
  "Web cơ bản": "Basic web",
  "EXE chuyên dụng": "Dedicated EXE",
  "phút": "minutes",
  "Mở website": "Open websites",
  "Chạy EXE": "Run EXE",
  "GPU/ứng dụng nặng": "GPU/heavy applications",
  "Cần nâng gói": "Upgrade required",
  "Chọn môi trường phù hợp rồi bắt đầu": "Choose a suitable environment to begin",
  "Toàn màn hình": "Full screen",
  "Máy ảo tương tác": "Interactive virtual machine",
  "Đang tự động cấp máy…": "Provisioning machine…",
  "Sẵn sàng tạo phiên": "Ready to create a session",
  "Môi trường local chỉ mở web, tối đa 10 lượt trải nghiệm mỗi ngày.": "The local environment supports web only, with up to 10 trial sessions per day.",
  "Windows cloud dành cho EXE; dùng một credit.": "Windows cloud for EXE files; uses one credit.",
  "Windows GPU cloud cho game và file nặng; dùng một credit.": "Windows GPU cloud for games and heavy files; uses one credit.",
  "Bắt đầu Sandbox": "Start Sandbox",
  "Kết thúc phiên": "End session",

  "Tải lớp bảo vệ": "Bring protection",
  "đến thiết bị của bạn.": "to your device.",
  "Ứng dụng và extension hiện chưa có bản phát hành công khai. Trang này sẽ là nơi cung cấp bộ cài đã ký và liên kết cửa hàng chính thức.": "The app and extension are not publicly available yet. This page will provide signed installers and links to official stores.",
  "Sản phẩm có thể tải": "Downloadable products",
  "Prewise cho Windows": "Prewise for Windows",
  "Sắp ra mắt": "Coming soon",
  "Ứng dụng bảo vệ trên máy tính, kiểm tra liên kết và tệp trước khi mở.": "Desktop protection that inspects links and files before you open them.",
  "Thông báo khi phát hành": "Notify me at launch",
  "Tiện ích trình duyệt": "Browser extension",
  "Cảnh báo website đáng ngờ trực tiếp trên Chrome, Edge và các trình duyệt Chromium.": "Warn about suspicious websites directly in Chrome, Edge, and Chromium browsers.",
  "Tham gia danh sách chờ": "Join the waitlist",
  "Chỉ tải từ nguồn chính thức": "Download only from official sources",
  "Prewise sẽ công bố checksum và chữ ký số cho từng bản phát hành. Không cài các tệp mang tên Prewise từ nguồn bên ngoài.": "Prewise will publish checksums and digital signatures for every release. Do not install files named Prewise from external sources.",

  "Kết nối Prewise với AI agent, automation và ứng dụng nội bộ.": "Connect Prewise to AI agents, automation, and internal applications.",
  "Key bên dưới phục vụ trải nghiệm demo. Nâng cấp Team để sử dụng endpoint production.": "The key below is for the demo experience. Upgrade to Team to use production endpoints.",
  "Xem gói Team →": "View Team plan →",
  "Đang thiết lập kênh bảo mật…": "Setting up a secure channel…",
  "Không thể tải API key. Hãy tải lại trang hoặc thử lại sau.": "Could not load the API key. Reload the page or try again later.",
  "Ẩn key": "Hide key",
  "Hiện key": "Show key",
  "Sao chép": "Copy",
  "Đang tạo…": "Creating…",
  "Xác nhận tạo lại": "Confirm rotation",
  "Tạo lại key →": "Rotate key →",
  "Key hiện tại sẽ mất hiệu lực ngay lập tức.": "The current key will become invalid immediately.",
  "Không đưa key vào mã nguồn hoặc chia sẻ qua tin nhắn. Sử dụng biến môi trường cho mọi tích hợp.": "Do not put keys in source code or share them through messages. Use environment variables for every integration.",
  "Đã sao chép an toàn vào clipboard": "Securely copied to clipboard",
  "Không thể sao chép tự động": "Could not copy automatically",
  "Key mới đã được tạo; key cũ không còn hiệu lực": "A new key was created; the old key is no longer valid",
  "Không thể tạo lại key": "Could not rotate the key",

  "Dữ liệu minh họa, thay đổi không gửi lên máy chủ": "Sample data; changes are not sent to the server",
  "Hồ sơ": "Profile",
  "Quản lý danh tính hiển thị và thông tin đăng nhập.": "Manage your display identity and sign-in information.",
  "Chưa đặt tên": "No name set",
  "Tên hiển thị": "Display name",
  "Tên của bạn": "Your name",
  "KHÔNG THỂ THAY ĐỔI": "CANNOT BE CHANGED",
  "Đổi mật khẩu": "Change password",
  "Đang lưu…": "Saving…",
  "Lưu thay đổi →": "Save changes →",
  "Mật khẩu hiện tại": "Current password",
  "Mật khẩu mới · tối thiểu 12 ký tự": "New password · at least 12 characters",
  "Xác nhận →": "Confirm →",
  "Đã lưu bản xem trước cục bộ": "Local preview saved",
  "Đã cập nhật hồ sơ": "Profile updated",
  "Không thể lưu hồ sơ": "Could not save profile",
  "Đã mô phỏng đổi mật khẩu": "Password change simulated",
  "Đã đổi mật khẩu": "Password changed",
  "Không thể đổi mật khẩu": "Could not change password",

  "Bắt đầu miễn phí": "Start free",
  "1000 lượt phân tích/ngày": "1000 analyses/day",
  "URL, email và SMS": "URLs, emails, and SMS",
  "Lịch sử cục bộ": "Local history",
  "Lịch sử tài khoản": "Account history",
  "Các lần quét URL và email được tải từ tài khoản trên máy chủ, không phải lịch sử cục bộ của trình duyệt.": "URL and email scans are loaded from your server account, not this browser's local history.",
  "Các lần kiểm tra được lưu riêng trên trình duyệt này. Đây không phải lịch sử tài khoản đồng bộ từ máy chủ.": "Checks are stored only in this browser. This is separate from server-synced account history.",
  "Các lần phân tích mới chỉ xuất hiện tại đây khi tùy chọn Lưu lịch sử trên thiết bị được bật.": "New analyses appear here only when Save history on this device is enabled.",
  "Khi tắt, lần phân tích mới chỉ được giữ trong tab hiện tại và không xuất hiện trong lịch sử cục bộ.": "When disabled, new analyses remain only in the current tab and are not added to local history.",
  "Che mật khẩu, OTP và số thẻ trong bản xem trước, lịch sử và kết quả được lưu. Nội dung gốc vẫn được gửi để phân tích khi bạn chủ động bấm nút.": "Mask passwords, OTPs, and card numbers in previews, history, and stored results. Original content is sent for analysis only when you explicitly submit it.",
  "Trang Lịch sử trong workspace chỉ đọc dữ liệu trên trình duyệt này. Lịch sử tài khoản là dữ liệu riêng được tải từ máy chủ sau khi đăng nhập.": "Workspace history reads only this browser's data. Account history is separately loaded from the server after sign-in.",
  "Xóa lịch sử phân tích cục bộ": "Delete local analysis history",
  "Xóa danh sách lịch sử và mọi bản ghi kết quả ở cả bộ nhớ phiên lẫn bộ nhớ lâu dài. Thao tác này không thể hoàn tác.": "Delete the history list and all result records from session and persistent storage. This action cannot be undone.",
  "Dùng thử 7 ngày": "Try free for 7 days",
  "Phân tích không giới hạn": "Unlimited analyses",
  "Báo cáo và giải thích sâu": "Advanced reports and explanations",
  "Extension + ứng dụng": "Extension + app",
  "Ưu tiên mô hình mới": "Priority access to new models",
  "Toàn bộ quyền lợi Pro": "All Pro benefits",
  "API key và MCP endpoint": "API key and MCP endpoint",
  "Dashboard đội nhóm": "Team dashboard",
  "SLA và hỗ trợ kỹ thuật": "SLA and technical support",
  "Điều cần biết trước khi chọn.": "What to know before choosing.",
  "Có thể bắt đầu mà không cần thẻ không?": "Can I start without a card?",
  "Có. Gói Free không yêu cầu thẻ thanh toán và đủ để trải nghiệm các luồng phân tích chính.": "Yes. The Free plan requires no payment card and covers the core analysis flows.",
  "Dữ liệu có được dùng để huấn luyện không?": "Is my data used for training?",
  "Không mặc định. Nội dung chỉ được xử lý để trả kết quả theo chính sách quyền riêng tư của Prewise.": "Not by default. Content is processed only to return results under Prewise's privacy policy.",
  "Team/API phù hợp với ai?": "Who is Team/API for?",
  "Dành cho đội ngũ cần bảo vệ AI agent, automation hoặc tích hợp Prewise vào sản phẩm nội bộ.": "For teams that need to protect AI agents and automation or integrate Prewise into internal products.",

  "KẾT QUẢ MINH HỌA": "DEMO RESULT",
  "KẾT QUẢ BACKEND": "BACKEND RESULT",
  "Đánh giá rủi ro hoàn tất": "Risk assessment complete",
  "Prewise đã phát hiện nhiều tín hiệu cần được xem xét trước khi bạn tiếp tục.": "Prewise detected several signals that should be reviewed before you continue.",
  "Kết quả dưới đây được trả trực tiếp từ Security Gateway.": "The result below came directly from the Security Gateway.",
  "Tác vụ báo cáo": "Report actions",
  "Chưa khả dụng": "Not available yet",
  "Xuất báo cáo": "Export report",
  "Chia sẻ": "Share",
  "Tổng quan kết quả": "Result overview",
  "KHUYẾN NGHỊ": "RECOMMENDATION",
  "Không truy cập hoặc cung cấp thông tin.": "Do not visit or provide information.",
  "Hãy xác minh thêm trước khi tiếp tục.": "Verify further before continuing.",
  "Chưa thấy tín hiệu rủi ro nổi bật.": "No prominent risk signals detected.",
  "Trang đích có tín hiệu rủi ro cao. Không nhập mật khẩu, OTP, dữ liệu thẻ hoặc thông tin định danh.": "The destination shows high-risk signals. Do not enter passwords, OTPs, card data, or identity information.",
  "Có một số tín hiệu cần xác minh qua kênh chính thức trước khi thao tác.": "Some signals require verification through official channels before you act.",
  "Kết quả hiện tại không thay thế việc xác minh tên miền và kênh liên hệ chính thức.": "This result does not replace verification of the domain and official contact channels.",
  "Độ tin cậy": "Confidence",
  "Giải thích độ tin cậy": "Confidence explanation",
  "Độ tin cậy được backend cung cấp khi có đủ tín hiệu; đây không phải là kết luận tuyệt đối.": "Confidence is supplied by the backend when enough signals are available; it is not an absolute conclusion.",
  "Risk score là mức tổng hợp tín hiệu rủi ro trên thang 100. Confidence thể hiện mức nhất quán của bằng chứng. Luôn xác minh bằng kênh chính thức.": "Risk score aggregates risk signals on a 100-point scale. Confidence reflects evidence consistency. Always verify through official channels.",
  "Đây là luồng demo dùng điểm số và bằng chứng cố định để minh họa giao diện.": "This demo flow uses fixed scores and evidence to illustrate the interface.",
  "Kết quả này là phản hồi backend thật.": "This is a live backend response.",
  "BẰNG CHỨNG": "EVIDENCE",
  "tín hiệu": "signals",
  "Tín hiệu": "Signal",
  "HÀNH ĐỘNG ĐỀ XUẤT": "RECOMMENDED ACTIONS",
  "Không mở liên kết hoặc biểu mẫu": "Do not open links or forms",
  "Đóng trang nếu bạn đã truy cập.": "Close the page if you already visited it.",
  "Không chia sẻ thông tin": "Do not share information",
  "Không nhập mật khẩu, OTP hay dữ liệu thẻ.": "Do not enter passwords, OTPs, or card data.",
  "Xác minh qua kênh chính thức": "Verify through official channels",
  "Tự nhập tên miền hoặc gọi số đã xác thực.": "Type the domain yourself or call a verified number.",
  "Báo cáo tín hiệu đáng ngờ": "Report suspicious signals",
  "Giúp cộng đồng nhận diện sớm hơn.": "Help the community detect them sooner.",
  "Báo cáo website ↗": "Report website ↗",
  "← Phân tích nội dung khác": "← Analyze other content",
  "Kết quả hỗ trợ quyết định, không thay thế xác minh hoặc đánh giá chuyên môn.": "Results support decisions and do not replace verification or professional assessment.",
  "Đang chuẩn bị báo cáo…": "Preparing report…",
  "Tín hiệu rủi ro": "Risk signal",
  "Backend phát hiện tín hiệu cần xem xét.": "The backend detected a signal that needs review.",
  "Đang xác định": "Determining",
  "VỪA": "MEDIUM",
  "CAO": "HIGH",
  "Lỗi": "Error",
  "Theo tháng": "Monthly",
  "Theo năm": "Yearly",
  "/ tháng": "/ month",
  "Thanh toán theo năm · tiết kiệm 20%": "Billed yearly · save 20%",
  "Tên miền có dấu hiệu giả mạo": "Domain shows signs of impersonation",
  "Tên miền sử dụng ký tự và cấu trúc gần giống một dịch vụ tài chính đáng tin cậy.": "The domain uses characters and a structure resembling a trusted financial service.",
  "Tạo cảm giác khẩn cấp": "Creates a sense of urgency",
  "Nội dung thúc ép người nhận hành động ngay để tránh khóa tài khoản.": "The content pressures the recipient to act immediately to avoid an account lock.",
  "xác minh trong vòng 30 phút": "verify within 30 minutes",
  "Yêu cầu dữ liệu nhạy cảm": "Requests sensitive data",
  "Biểu mẫu đích yêu cầu thông tin đăng nhập và mã xác thực.": "The destination form requests sign-in details and verification codes.",
  "Tải xuống · Prewise": "Downloads · Prewise",
  "Tải ứng dụng Prewise và tiện ích mở rộng trình duyệt.": "Download the Prewise app and browser extension."
};

const normalizedTranslations = new Map(
  Object.entries(ENGLISH_TRANSLATIONS).map(([source, target]) => [normalize(source), target]),
);

declare global {
  interface Text {
    __prewiseOriginalText?: string;
  }
}

function normalize(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

export function translateText(value: string): string | null {
  const normalized = normalize(value);
  if (!normalized) return null;
  const exact = normalizedTranslations.get(normalized);
  if (exact) return value.replace(normalized, exact);

  let translated = value;
  let changed = false;
  const entries = [...Object.entries(ENGLISH_TRANSLATIONS)].sort((a, b) => b[0].length - a[0].length);
  for (const [source, target] of entries) {
    if (translated.includes(source)) {
      translated = translated.split(source).join(target);
      changed = true;
    }
  }
  return changed ? translated : null;
}

function translateDocument(language: Language): void {
  const root = document.body;
  if (!root) return;
  const textWalker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent || parent.closest("script, style, textarea, [data-i18n-ignore]")) return NodeFilter.FILTER_REJECT;
      return normalize(node.nodeValue || "") ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    },
  });
  const textNodes: Text[] = [];
  while (textWalker.nextNode()) textNodes.push(textWalker.currentNode as Text);
  for (const node of textNodes) {
    const element = node.parentElement;
    if (!element) continue;
    const original = node.__prewiseOriginalText ?? node.nodeValue ?? "";
    if (node.__prewiseOriginalText === undefined) node.__prewiseOriginalText = original;
    const next = language === "en" ? (translateText(original) ?? original) : original;
    if (node.nodeValue !== next) node.nodeValue = next;
  }

  for (const element of root.querySelectorAll<HTMLElement>("[placeholder], [title], [aria-label]")) {
    if (element.closest("[data-i18n-ignore]")) continue;
    for (const attribute of ["placeholder", "title", "aria-label"] as const) {
      const value = element.getAttribute(attribute);
      if (!value) continue;
      const backup = `i18nOriginal${attribute.replace("-", "")}`;
      if (language === "en") {
        if (!element.dataset[backup]) element.dataset[backup] = value;
        const original = element.dataset[backup] || value;
        const next = translateText(original) ?? original;
        if (element.getAttribute(attribute) !== next) element.setAttribute(attribute, next);
      } else if (element.dataset[backup]) {
        element.setAttribute(attribute, element.dataset[backup]);
        delete element.dataset[backup];
      }
    }
  }
}

function readLanguage(): Language {
  if (typeof window === "undefined") return "vi";
  const direct = localStorage.getItem(STORAGE_KEY);
  if (direct === "en" || direct === "vi") return direct;
  try {
    const settings = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "null");
    return settings?.language === "en" ? "en" : "vi";
  } catch {
    return "vi";
  }
}

type LanguageContextValue = { language: Language; setLanguage: (language: Language) => void; toggleLanguage: () => void };
const fallbackLanguageContext: LanguageContextValue = {
  language: "vi",
  setLanguage: () => undefined,
  toggleLanguage: () => undefined,
};
const LanguageContext = createContext<LanguageContextValue>(fallbackLanguageContext);

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguageState] = useState<Language>("vi");

  const setLanguage = useCallback((next: Language) => {
    setLanguageState(next);
    localStorage.setItem(STORAGE_KEY, next);
    try {
      const settings = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
      localStorage.setItem(SETTINGS_KEY, JSON.stringify({ ...settings, language: next }));
    } catch { /* Ignore unavailable or invalid storage. */ }
    document.documentElement.lang = next;
    document.documentElement.dataset.language = next;
    window.dispatchEvent(new CustomEvent(LANGUAGE_EVENT, { detail: next }));
  }, []);

  useEffect(() => {
    const initial = readLanguage();
    setLanguageState(initial);
    document.documentElement.lang = initial;
    document.documentElement.dataset.language = initial;
    try {
      const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
      const motion = ["full", "balanced", "reduced"].includes(saved?.motion) ? saved.motion : "balanced";
      const density = ["comfortable", "compact"].includes(saved?.density) ? saved.density : "comfortable";
      document.documentElement.dataset.motion = motion;
      document.documentElement.dataset.density = density;
    } catch {
      document.documentElement.dataset.motion = "balanced";
      document.documentElement.dataset.density = "comfortable";
    }
  }, []);

  useEffect(() => {
    let scheduled = false;
    let applyingTranslation = false;
    const apply = () => {
      scheduled = false;
      applyingTranslation = true;
      translateDocument(language);
      queueMicrotask(() => { applyingTranslation = false; });
    };
    const schedule = () => {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(apply);
    };
    schedule();
    const observer = new MutationObserver((mutations) => {
      if (applyingTranslation) return;
      for (const mutation of mutations) {
        if (mutation.type === "characterData") {
          const node = mutation.target as Text;
          const current = node.nodeValue || "";
          const previous = mutation.oldValue || "";
          const translatedPrevious = translateText(previous);
          if (current !== translatedPrevious) node.__prewiseOriginalText = current;
        }
        for (const added of mutation.addedNodes) {
          if (added.nodeType === Node.TEXT_NODE) (added as Text).__prewiseOriginalText = added.nodeValue || "";
        }
      }
      schedule();
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true, characterDataOldValue: true });
    return () => observer.disconnect();
  }, [language]);

  const value = useMemo<LanguageContextValue>(() => ({
    language,
    setLanguage,
    toggleLanguage: () => setLanguage(language === "vi" ? "en" : "vi"),
  }), [language, setLanguage]);

  return <LanguageContext.Provider value={value}>{children}</LanguageContext.Provider>;
}

export function useLanguage(): LanguageContextValue {
  return useContext(LanguageContext);
}
