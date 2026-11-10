#!/system/bin/sh
# Debug-only diagnostic plane. Shipped solely in debug ZIPs; its presence is the gate that
# service.sh (setup) and action.sh (export) test before touching external storage.
DIAG_DIR=/data/media/0/TEESimulator

diag_setup() {
    mkdir -p "$DIAG_DIR"
    chmod 0777 "$DIAG_DIR"
    chcon u:object_r:media_rw_data_file:s0 "$DIAG_DIR" 2>/dev/null
}

diag_export() {
    _ts=$(date +%Y%m%d-%H%M%S)
    _dest=/sdcard/Download/teesim-logs-$_ts
    mkdir -p "$_dest"
    cp -f "$DIAG_DIR"/teesim-uid-* "$_dest"/ 2>/dev/null
    cp -f /data/adb/tricky_store/logs/certgen.log* "$_dest"/ 2>/dev/null
    logcat -d -s TEESimulator > "$_dest/logcat.txt" 2>/dev/null
    echo "  ✅ Saved to $_dest"
}
