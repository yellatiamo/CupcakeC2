# Remote Desktop — Retired

**Status: removed from product (v4.2.0)**

The entire remote-desktop stack has been deleted:

- Panel UI (`RemoteDesktop.vue`) and client menu entry
- Server APIs `/api/desktop/*` (mstsc forward + guacd web)
- L2 module `desktop`, Yamux stream type `0x0D`
- Agent `desktop_bridge`, `rdp_enable`, `desktop_worker`

Product L2 modules remaining: **`iso_host`**, **`inject`**.

Do not reintroduce GDI/JPEG canvas or guacd without a new design review.
