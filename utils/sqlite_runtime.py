from __future__ import annotations

import threading


# SQLite keeps a process-wide Unix file-descriptor cache. Serializing complete
# connection lifecycles avoids an open/close mutex deadlock under thread load.
sqlite_connection_guard = threading.RLock()
