ACTION_LANG="en"
_detect_lang() {
    local raw
    raw=$(getprop persist.sys.locale 2>/dev/null)
    [ -z "$raw" ] && raw=$(getprop ro.product.locale 2>/dev/null)
    [ -z "$raw" ] && raw=$(getprop ro.system.locale 2>/dev/null)
    local code=$(printf '%s' "$raw" | sed 's/_/-/g')
    case "$code" in
        zh-Hans*|zh-CN*) code="zh-CN" ;;
        zh-Hant*|zh-TW*|zh-HK*) code="zh-TW" ;;
        pt-BR*) code="pt-BR" ;;
        pt*) code="pt-BR" ;;
        es-ES*|es*) code="es-ES" ;;
        *-*) code="${code%%-*}" ;;
    esac
    case "$code" in
        ar|az|bn|de|el|es-ES|fa|fr|id|it|ja|ko|pl|pt-BR|ru|th|tl|tr|uk|vi|zh-CN|zh-TW) ACTION_LANG="$code" ;;
    esac
}
_detect_lang

_msg() {
    case "$ACTION_LANG" in
    zh-CN) case "$1" in
        confirm_header)     echo "清除持久化密钥存储" ;;
        confirm_warning_1)  echo "这将删除所有缓存的证明密钥。" ;;
        confirm_warning_2)  echo "使用证明的应用将在下次使用时重新注册。" ;;
        confirm_vol_up)     echo "音量+ = 确认清除" ;;
        confirm_vol_down)   echo "音量- = 取消（10秒后默认）" ;;
        confirm_cancelled)  echo "已取消 - 密钥已保留" ;;
        confirm_cleared)    echo "持久化密钥存储已清除" ;;
        confirm_not_found)  echo "未找到持久化密钥存储" ;;
    esac ;;
    zh-TW) case "$1" in
        confirm_header)     echo "清除持久化金鑰儲存" ;;
        confirm_warning_1)  echo "這將刪除所有快取的證明金鑰。" ;;
        confirm_warning_2)  echo "使用證明的應用程式將在下次使用時重新註冊。" ;;
        confirm_vol_up)     echo "音量+ = 確認清除" ;;
        confirm_vol_down)   echo "音量- = 取消（10秒後預設）" ;;
        confirm_cancelled)  echo "已取消 - 金鑰已保留" ;;
        confirm_cleared)    echo "持久化金鑰儲存已清除" ;;
        confirm_not_found)  echo "未找到持久化金鑰儲存" ;;
    esac ;;
    ja) case "$1" in
        confirm_header)     echo "永続キーストレージを消去" ;;
        confirm_warning_1)  echo "キャッシュされた証明キーをすべて削除します。" ;;
        confirm_warning_2)  echo "証明を使用するアプリは次回使用時に再登録されます。" ;;
        confirm_vol_up)     echo "音量+ = 消去を確認" ;;
        confirm_vol_down)   echo "音量- = キャンセル（10秒後デフォルト）" ;;
        confirm_cancelled)  echo "キャンセルされました - キーは保持されます" ;;
        confirm_cleared)    echo "永続キーストレージを消去しました" ;;
        confirm_not_found)  echo "永続キーストレージが見つかりません" ;;
    esac ;;
    ko) case "$1" in
        confirm_header)     echo "영구 키 저장소 지우기" ;;
        confirm_warning_1)  echo "캐시된 모든 증명 키를 삭제합니다." ;;
        confirm_warning_2)  echo "증명을 사용하는 앱은 다음 사용 시 재등록됩니다." ;;
        confirm_vol_up)     echo "볼륨+ = 지우기 확인" ;;
        confirm_vol_down)   echo "볼륨- = 취소 (10초 후 기본값)" ;;
        confirm_cancelled)  echo "취소됨 - 키 유지됨" ;;
        confirm_cleared)    echo "영구 키 저장소가 지워졌습니다" ;;
        confirm_not_found)  echo "영구 키 저장소를 찾을 수 없습니다" ;;
    esac ;;
    ru) case "$1" in
        confirm_header)     echo "Очистить постоянное хранилище ключей" ;;
        confirm_warning_1)  echo "Это удалит все кэшированные ключи аттестации." ;;
        confirm_warning_2)  echo "Приложения, использующие аттестацию, перерегистрируются при следующем использовании." ;;
        confirm_vol_up)     echo "Громкость+ = Подтвердить очистку" ;;
        confirm_vol_down)   echo "Громкость- = Отмена (по умолчанию через 10с)" ;;
        confirm_cancelled)  echo "Отменено - ключи сохранены" ;;
        confirm_cleared)    echo "Постоянное хранилище ключей очищено" ;;
        confirm_not_found)  echo "Постоянное хранилище ключей не найдено" ;;
    esac ;;
    de) case "$1" in
        confirm_header)     echo "Persistenten Schlüsselspeicher löschen" ;;
        confirm_warning_1)  echo "Dies löscht alle zwischengespeicherten Attestierungsschlüssel." ;;
        confirm_warning_2)  echo "Apps mit Attestierung registrieren sich bei der nächsten Nutzung neu." ;;
        confirm_vol_up)     echo "Laut+ = Löschen bestätigen" ;;
        confirm_vol_down)   echo "Leise- = Abbrechen (Standard nach 10s)" ;;
        confirm_cancelled)  echo "Abgebrochen - Schlüssel beibehalten" ;;
        confirm_cleared)    echo "Persistenter Schlüsselspeicher gelöscht" ;;
        confirm_not_found)  echo "Kein persistenter Schlüsselspeicher gefunden" ;;
    esac ;;
    fr) case "$1" in
        confirm_header)     echo "Effacer le stockage de clés persistant" ;;
        confirm_warning_1)  echo "Ceci supprime toutes les clés d'attestation en cache." ;;
        confirm_warning_2)  echo "Les apps utilisant l'attestation se réinscriront à la prochaine utilisation." ;;
        confirm_vol_up)     echo "Vol+ = Confirmer l'effacement" ;;
        confirm_vol_down)   echo "Vol- = Annuler (par défaut après 10s)" ;;
        confirm_cancelled)  echo "Annulé - clés conservées" ;;
        confirm_cleared)    echo "Stockage de clés persistant effacé" ;;
        confirm_not_found)  echo "Aucun stockage de clés persistant trouvé" ;;
    esac ;;
    es-ES) case "$1" in
        confirm_header)     echo "Borrar almacenamiento persistente de claves" ;;
        confirm_warning_1)  echo "Esto elimina todas las claves de atestación en caché." ;;
        confirm_warning_2)  echo "Las apps que usan atestación se volverán a registrar en el próximo uso." ;;
        confirm_vol_up)     echo "Vol+ = Confirmar borrado" ;;
        confirm_vol_down)   echo "Vol- = Cancelar (predeterminado tras 10s)" ;;
        confirm_cancelled)  echo "Cancelado - claves conservadas" ;;
        confirm_cleared)    echo "Almacenamiento persistente de claves borrado" ;;
        confirm_not_found)  echo "No se encontró almacenamiento persistente de claves" ;;
    esac ;;
    pt-BR) case "$1" in
        confirm_header)     echo "Limpar armazenamento persistente de chaves" ;;
        confirm_warning_1)  echo "Isso exclui todas as chaves de atestação em cache." ;;
        confirm_warning_2)  echo "Apps que usam atestação serão re-registrados no próximo uso." ;;
        confirm_vol_up)     echo "Vol+ = Confirmar limpeza" ;;
        confirm_vol_down)   echo "Vol- = Cancelar (padrão após 10s)" ;;
        confirm_cancelled)  echo "Cancelado - chaves preservadas" ;;
        confirm_cleared)    echo "Armazenamento persistente de chaves limpo" ;;
        confirm_not_found)  echo "Nenhum armazenamento persistente de chaves encontrado" ;;
    esac ;;
    it) case "$1" in
        confirm_header)     echo "Cancella archivio chiavi persistente" ;;
        confirm_warning_1)  echo "Questo elimina tutte le chiavi di attestazione in cache." ;;
        confirm_warning_2)  echo "Le app che usano l'attestazione si re-registreranno al prossimo utilizzo." ;;
        confirm_vol_up)     echo "Vol+ = Conferma cancellazione" ;;
        confirm_vol_down)   echo "Vol- = Annulla (predefinito dopo 10s)" ;;
        confirm_cancelled)  echo "Annullato - chiavi conservate" ;;
        confirm_cleared)    echo "Archivio chiavi persistente cancellato" ;;
        confirm_not_found)  echo "Nessun archivio chiavi persistente trovato" ;;
    esac ;;
    tr) case "$1" in
        confirm_header)     echo "Kalıcı Anahtar Deposunu Temizle" ;;
        confirm_warning_1)  echo "Bu, önbelleğe alınmış tüm doğrulama anahtarlarını siler." ;;
        confirm_warning_2)  echo "Doğrulama kullanan uygulamalar bir sonraki kullanımda yeniden kaydolacak." ;;
        confirm_vol_up)     echo "Ses+ = Temizlemeyi onayla" ;;
        confirm_vol_down)   echo "Ses- = İptal (10sn sonra varsayılan)" ;;
        confirm_cancelled)  echo "İptal edildi - anahtarlar korundu" ;;
        confirm_cleared)    echo "Kalıcı anahtar deposu temizlendi" ;;
        confirm_not_found)  echo "Kalıcı anahtar deposu bulunamadı" ;;
    esac ;;
    id) case "$1" in
        confirm_header)     echo "Hapus Penyimpanan Kunci Persisten" ;;
        confirm_warning_1)  echo "Ini menghapus semua kunci atestasi yang di-cache." ;;
        confirm_warning_2)  echo "Aplikasi yang menggunakan atestasi akan mendaftar ulang saat digunakan." ;;
        confirm_vol_up)     echo "Vol+ = Konfirmasi hapus" ;;
        confirm_vol_down)   echo "Vol- = Batal (default setelah 10 detik)" ;;
        confirm_cancelled)  echo "Dibatalkan - kunci dipertahankan" ;;
        confirm_cleared)    echo "Penyimpanan kunci persisten dihapus" ;;
        confirm_not_found)  echo "Penyimpanan kunci persisten tidak ditemukan" ;;
    esac ;;
    vi) case "$1" in
        confirm_header)     echo "Xóa lưu trữ khóa cố định" ;;
        confirm_warning_1)  echo "Thao tác này xóa tất cả khóa chứng thực được lưu cache." ;;
        confirm_warning_2)  echo "Các ứng dụng dùng chứng thực sẽ đăng ký lại khi sử dụng tiếp theo." ;;
        confirm_vol_up)     echo "Vol+ = Xác nhận xóa" ;;
        confirm_vol_down)   echo "Vol- = Hủy (mặc định sau 10s)" ;;
        confirm_cancelled)  echo "Đã hủy - giữ nguyên khóa" ;;
        confirm_cleared)    echo "Đã xóa lưu trữ khóa cố định" ;;
        confirm_not_found)  echo "Không tìm thấy lưu trữ khóa cố định" ;;
    esac ;;
    ar) case "$1" in
        confirm_header)     echo "مسح تخزين المفاتيح الدائم" ;;
        confirm_warning_1)  echo "يؤدي هذا إلى حذف جميع مفاتيح التصديق المخزنة مؤقتاً." ;;
        confirm_warning_2)  echo "التطبيقات التي تستخدم التصديق ستعيد التسجيل في الاستخدام التالي." ;;
        confirm_vol_up)     echo "رفع الصوت = تأكيد المسح" ;;
        confirm_vol_down)   echo "خفض الصوت = إلغاء (افتراضي بعد 10 ثوانٍ)" ;;
        confirm_cancelled)  echo "تم الإلغاء - تم الاحتفاظ بالمفاتيح" ;;
        confirm_cleared)    echo "تم مسح تخزين المفاتيح الدائم" ;;
        confirm_not_found)  echo "لم يتم العثور على تخزين مفاتيح دائم" ;;
    esac ;;
    th) case "$1" in
        confirm_header)     echo "ล้างที่จัดเก็บคีย์ถาวร" ;;
        confirm_warning_1)  echo "การดำเนินการนี้จะลบคีย์การรับรองที่แคชไว้ทั้งหมด" ;;
        confirm_warning_2)  echo "แอปที่ใช้การรับรองจะลงทะเบียนใหม่ในการใช้งานครั้งถัดไป" ;;
        confirm_vol_up)     echo "เพิ่มเสียง = ยืนยันการล้าง" ;;
        confirm_vol_down)   echo "ลดเสียง = ยกเลิก (ค่าเริ่มต้นหลัง 10 วินาที)" ;;
        confirm_cancelled)  echo "ยกเลิกแล้ว - คีย์ยังคงอยู่" ;;
        confirm_cleared)    echo "ล้างที่จัดเก็บคีย์ถาวรแล้ว" ;;
        confirm_not_found)  echo "ไม่พบที่จัดเก็บคีย์ถาวร" ;;
    esac ;;
    uk) case "$1" in
        confirm_header)     echo "Очистити постійне сховище ключів" ;;
        confirm_warning_1)  echo "Це видаляє всі кешовані ключі атестації." ;;
        confirm_warning_2)  echo "Програми, що використовують атестацію, повторно зареєструються при наступному використанні." ;;
        confirm_vol_up)     echo "Гучність+ = Підтвердити очищення" ;;
        confirm_vol_down)   echo "Гучність- = Скасувати (за замовчуванням через 10с)" ;;
        confirm_cancelled)  echo "Скасовано - ключі збережено" ;;
        confirm_cleared)    echo "Постійне сховище ключів очищено" ;;
        confirm_not_found)  echo "Постійне сховище ключів не знайдено" ;;
    esac ;;
    pl) case "$1" in
        confirm_header)     echo "Wyczyść trwały magazyn kluczy" ;;
        confirm_warning_1)  echo "To usuwa wszystkie buforowane klucze atestacji." ;;
        confirm_warning_2)  echo "Aplikacje używające atestacji zarejestrują się ponownie przy następnym użyciu." ;;
        confirm_vol_up)     echo "Głośność+ = Potwierdź czyszczenie" ;;
        confirm_vol_down)   echo "Głośność- = Anuluj (domyślnie po 10s)" ;;
        confirm_cancelled)  echo "Anulowano - klucze zachowane" ;;
        confirm_cleared)    echo "Trwały magazyn kluczy wyczyszczony" ;;
        confirm_not_found)  echo "Nie znaleziono trwałego magazynu kluczy" ;;
    esac ;;
    az) case "$1" in
        confirm_header)     echo "Davamlı Açar Yaddaşını Təmizlə" ;;
        confirm_warning_1)  echo "Bu, keşlənmiş bütün təsdiqləmə açarlarını silir." ;;
        confirm_warning_2)  echo "Təsdiqləmədən istifadə edən tətbiqlər növbəti istifadədə yenidən qeydiyyatdan keçəcək." ;;
        confirm_vol_up)     echo "Səs+ = Təmizləməni təsdiqlə" ;;
        confirm_vol_down)   echo "Səs- = Ləğv et (10 saniyə sonra defolt)" ;;
        confirm_cancelled)  echo "Ləğv edildi - açarlar saxlanıldı" ;;
        confirm_cleared)    echo "Davamlı açar yaddaşı təmizləndi" ;;
        confirm_not_found)  echo "Davamlı açar yaddaşı tapılmadı" ;;
    esac ;;
    bn) case "$1" in
        confirm_header)     echo "স্থায়ী কী সংরক্ষণ পরিষ্কার করুন" ;;
        confirm_warning_1)  echo "এটি সমস্ত ক্যাশড অ্যাটেস্টেশন কী মুছে ফেলে।" ;;
        confirm_warning_2)  echo "অ্যাটেস্টেশন ব্যবহারকারী অ্যাপগুলি পরবর্তী ব্যবহারে পুনরায় নিবন্ধন করবে।" ;;
        confirm_vol_up)     echo "ভলিউম+ = পরিষ্কার নিশ্চিত করুন" ;;
        confirm_vol_down)   echo "ভলিউম- = বাতিল (১০ সেকেন্ডে ডিফল্ট)" ;;
        confirm_cancelled)  echo "বাতিল করা হয়েছে - কী সংরক্ষিত" ;;
        confirm_cleared)    echo "স্থায়ী কী সংরক্ষণ পরিষ্কার করা হয়েছে" ;;
        confirm_not_found)  echo "কোনো স্থায়ী কী সংরক্ষণ পাওয়া যায়নি" ;;
    esac ;;
    el) case "$1" in
        confirm_header)     echo "Εκκαθάριση Μόνιμου Αποθηκευτικού Χώρου Κλειδιών" ;;
        confirm_warning_1)  echo "Διαγράφει όλα τα προσωρινά αποθηκευμένα κλειδιά πιστοποίησης." ;;
        confirm_warning_2)  echo "Οι εφαρμογές που χρησιμοποιούν πιστοποίηση θα επανεγγραφούν στην επόμενη χρήση." ;;
        confirm_vol_up)     echo "Ένταση+ = Επιβεβαίωση εκκαθάρισης" ;;
        confirm_vol_down)   echo "Ένταση- = Ακύρωση (προεπιλογή μετά από 10 δευτ)" ;;
        confirm_cancelled)  echo "Ακυρώθηκε - τα κλειδιά διατηρήθηκαν" ;;
        confirm_cleared)    echo "Ο μόνιμος αποθηκευτικός χώρος κλειδιών εκκαθαρίστηκε" ;;
        confirm_not_found)  echo "Δεν βρέθηκε μόνιμος αποθηκευτικός χώρος κλειδιών" ;;
    esac ;;
    fa) case "$1" in
        confirm_header)     echo "پاک کردن ذخیره‌سازی دائمی کلید" ;;
        confirm_warning_1)  echo "این کار همه کلیدهای تأیید کش‌شده را حذف می‌کند." ;;
        confirm_warning_2)  echo "برنامه‌های استفاده‌کننده از تأیید در استفاده بعدی دوباره ثبت‌نام می‌کنند." ;;
        confirm_vol_up)     echo "صدا+ = تأیید پاک کردن" ;;
        confirm_vol_down)   echo "صدا- = لغو (پیش‌فرض پس از ۱۰ ثانیه)" ;;
        confirm_cancelled)  echo "لغو شد - کلیدها حفظ شدند" ;;
        confirm_cleared)    echo "ذخیره‌سازی دائمی کلید پاک شد" ;;
        confirm_not_found)  echo "ذخیره‌سازی دائمی کلید یافت نشد" ;;
    esac ;;
    tl) case "$1" in
        confirm_header)     echo "Burahin ang Persistent Key Storage" ;;
        confirm_warning_1)  echo "Buburahin nito ang lahat ng naka-cache na attestation keys." ;;
        confirm_warning_2)  echo "Magre-rehistro muli ang mga app na gumagamit ng attestation sa susunod na paggamit." ;;
        confirm_vol_up)     echo "Vol+ = Kumpirmahin ang pagbura" ;;
        confirm_vol_down)   echo "Vol- = Kanselahin (default pagkatapos ng 10s)" ;;
        confirm_cancelled)  echo "Nakansela - napanatili ang mga key" ;;
        confirm_cleared)    echo "Nabura ang persistent key storage" ;;
        confirm_not_found)  echo "Walang nahanap na persistent key storage" ;;
    esac ;;
    *) case "$1" in
        confirm_header)     echo "Clear Persistent Key Storage" ;;
        confirm_warning_1)  echo "This deletes all cached attestation keys." ;;
        confirm_warning_2)  echo "Apps using attestation will re-enroll on next use." ;;
        confirm_vol_up)     echo "Vol+  = Confirm clear" ;;
        confirm_vol_down)   echo "Vol-  = Cancel (default after 10s)" ;;
        confirm_cancelled)  echo "Cancelled - keys preserved" ;;
        confirm_cleared)    echo "Persistent key storage cleared" ;;
        confirm_not_found)  echo "No persistent key storage found" ;;
    esac ;;
    esac
}
