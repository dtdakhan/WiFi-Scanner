# Wi-Fi Scanner (PySide6)

Quét **thụ động** các Access Point lân cận (không bắt gói tin, không bẻ khóa), hiển thị mỗi BSSID một dòng, lọc/sắp xếp, xuất JSON/CSV, chẩn đoán lỗi. Danh sách profiles đã lưu **không bao giờ** được dùng làm nguồn AP.

## Cài đặt (Python 3.10+)
```
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt                       # macOS tự cài thêm pyobjc-framework-CoreWLAN
pip install -r requirements-dev.txt                   # chỉ khi chạy test
```
- **Windows 10/11**: không cần gì thêm. Bật Location (Windows 11) nếu scan rỗng/bị từ chối. Không cần Administrator.
- **Linux**: cần NetworkManager (`nmcli`). Không cần sudo; polkit có thể từ chối ở một số môi trường (không có session).
- **macOS**: xem phần hạn chế (bắt buộc app bundle + Location Services).

## Chạy
```
python main.py                      # GUI
python main.py --diagnose           # quét + báo cáo chẩn đoán (không GUI)
python main.py --export out.csv     # hoặc out.json; dùng cùng backend với GUI
python main.py --debug              # log DEBUG
```
GUI: bấm `▶ Quét` để bắt đầu quét liên tục, bấm `■ Dừng` để dừng (đo lặp mỗi N giây, bảng cập nhật tại chỗ, giữ dòng đang chọn; panel chi tiết hiện lịch sử/min/max/TB của tín hiệu theo BSSID; tự dừng sau 3 lỗi liên tiếp) → tìm kiếm SSID/BSSID, lọc băng tần/security/mạng ẩn → bấm tiêu đề cột để sắp xếp → chọn dòng xem chi tiết → `Xuất JSON/CSV` (chọn *đang lọc* hoặc *toàn bộ*; có cảnh báo BSSID là dữ liệu nhạy cảm vị trí). `Chẩn đoán` hiện bước nào lỗi (quét / lấy dữ liệu / parsing / lọc).

Khi không thấy AP: xem `Chẩn đoán` — phân biệt "scan thành công nhưng 0 bản ghi", "scan lỗi", "adapter tắt", "parser lỗi".

## Các cột của bảng
Cột mặc định: SSID, BSSID, Signal, **Δ Signal** (đổi so với lần đo trước), Channel, Frequency, Band, Security, **Cipher**, Radio Type, Connection, **AP cùng kênh** (độ đông của kênh). Cột ẩn mặc định: **Vendor**, Thấy lần đầu, Thấy lần cuối. **Chuột phải lên tiêu đề cột** để bật/tắt cột; kéo cạnh tiêu đề để đổi độ rộng, kéo thả tiêu đề để đổi thứ tự. Các cột Δ, AP cùng kênh, Thấy lần đầu/cuối được suy ra từ dữ liệu quét thật trong phiên và có trong file xuất.

**Vendor (tùy chọn):** tải file OUI của IEEE `https://standards-oui.ieee.org/oui/oui.txt` và lưu thành `app/data/oui.txt` (hoặc đặt biến môi trường `WIFI_SCANNER_OUI` trỏ tới file). Không có file thì cột Vendor hiển thị N/A; BSSID cục bộ (bit locally-administered) hiển thị "MAC cục bộ (LAA)".

## Nguồn dữ liệu & hạn chế theo hệ điều hành
| OS | Phương thức | Signal | Security | Lưu ý |
|---|---|---|---|---|
| Windows | `WlanScan` + notification + `WlanGetNetworkBssList` (ctypes) | dBm **và** % | theo BSSID (parse RSN/WPA IE) | `ulChCenterFrequency` là kHz; danh sách BSS có thể chứa AP cũ (cache OS); Win11 cần Location |
| Windows (fallback, có cảnh báo) | `netsh wlan show networks mode=bssid` | chỉ % | theo SSID | parse theo cấu trúc nên chạy được cả khi nhãn bị dịch |
| Linux | `nmcli -t --escape yes ... device wifi list --rescan yes` | chỉ % | theo BSSID (chuỗi của nmcli) | NM giới hạn tần suất rescan → tự dùng `--rescan no` + cảnh báo cache; không có radio type/dBm (`iw scan` có dBm nhưng thường cần root, chưa tích hợp) |
| macOS | CoreWLAN qua PyObjC | dBm | theo BSSID | macOS 14+: SSID/BSSID bị che nếu thiếu Location Services; script Python trần thường không xin được quyền → cần app bundle |

Trường nguồn không cung cấp = `None`/`N/A`. Không quy đổi % ↔ dBm, không đoán WPA/radio, không gộp BSSID theo SSID. Sắp xếp theo tín hiệu: nhóm dBm trước, nhóm % sau, không bao giờ so khác đơn vị. Hủy scan: chưa hỗ trợ (`WlanScan` không hủy được; scan có timeout).

## Kiểm thử
```
QT_QPA_PLATFORM=offscreen python -m pytest -q      # hoặc: python -m unittest discover tests
```
Kết quả thực tế (sandbox Linux, Python 3.12, PySide6 6.12.0): **38 passed**. Bao gồm: parser nmcli/netsh (EN + VI), nhiều BSSID cùng SSID, SSID Unicode/có `:`/ẩn, thiếu trường, bản ghi lỗi không làm mất bản ghi khác, band/channel (6 GHz), sắp xếp/lọc, export, timeout/thiếu executable/permission (mock), chẩn đoán 0 bản ghi, GUI offscreen (spinner dừng khi thành công/thất bại, worker không chạy trên main thread, chặn scan đồng thời).

**Chưa được xác minh:** `scanner_windows` phần native (`wlanapi.dll`) và `scanner_macos` (CoreWLAN) chưa chạy trên phần cứng thật; `nmcli` chưa chạy với adapter thật; fixture `netsh_vi.txt` là tổng hợp, không chụp từ máy thật; cách tính `age_ms` từ `ullHostTimestamp` chưa triển khai (trường để `None`). Test mock chỉ chứng minh logic, không chứng minh adapter phát hiện đủ AP.

## Đóng gói
```
pip install pyinstaller
pyinstaller --noconsole --name WiFiScanner main.py          # Windows / Linux
```
macOS: dùng `--windowed --osx-bundle-identifier com.example.wifiscanner`, rồi thêm vào `Info.plist` của `.app` khóa `NSLocationUsageDescription` (và `NSLocationWhenInUseUsageDescription`) và ký lại ứng dụng; nếu không, SSID/BSSID sẽ bị che.
