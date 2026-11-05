MODDIR=${0%/*}
cd $MODDIR

# Delay the first launch without delaying subsequent supervised restarts.
( sleep 30; exec ./supervisor ./daemon "$MODDIR" ) &

# Debug builds ship diag.sh; its presence enables the external-storage diagnostic plane.
if [ -f "$MODDIR/diag.sh" ]; then
  . "$MODDIR/diag.sh"
  diag_setup
fi
