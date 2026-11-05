# Isolated browser for one user: official Telegram Web in Chromium, streamed with KasmVNC.
#
# KasmVNC serves ~/Downloads over its web server, which would let files reach the PC without
# being scanned. The browser manager mounts an empty read-only folder over ~/Downloads, Chromium
# is forced (policy) to save into ~/tgv-downloads, which the gateway scans, and the gateway
# refuses /desk/Downloads.
FROM kasmweb/chromium:1.18.0
