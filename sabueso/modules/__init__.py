"""Built-in analysis modules. Importing this package registers all of them."""

from sabueso.modules.base import (  # noqa: F401
    SEVERITIES,
    AnalysisContext,
    Module,
    Option,
    ResultSink,
    available_modules,
    get_module,
    register,
)
from sabueso.modules.generic import carving, hashset, image, inventory, ioc, yara  # noqa: F401
from sabueso.modules.windows import (  # noqa: F401
    browsers,
    defender,
    evtx,
    jumplists,
    lnk,
    logfile,
    memory,
    mft,
    notifications,
    prefetch,
    psreadline,
    rdp_cache,
    recyclebin,
    registry,
    setupapi,
    shellbags,
    srum,
    tasks,
    usnjrnl,
    wintimeline,
    wmi,
)
