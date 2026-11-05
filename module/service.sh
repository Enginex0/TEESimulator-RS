MODDIR=${0%/*}
cd $MODDIR

# Fork-based supervisor for instant restart
./supervisor ./daemon "$MODDIR" &

# Debug builds ship diag.sh; its presence enables the external-storage diagnostic plane.
if [ -f "$MODDIR/diag.sh" ]; then
  . "$MODDIR/diag.sh"
  diag_setup
fi
