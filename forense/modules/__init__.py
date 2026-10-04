"""Built-in analysis modules. Importing this package registers all of them."""

from forense.modules.base import (  # noqa: F401
    SEVERITIES,
    AnalysisContext,
    Module,
    Option,
    ResultSink,
    available_modules,
    get_module,
    register,
)
from forense.modules.generic import carving, hashset, inventory, ioc  # noqa: F401
from forense.modules.windows import (  # noqa: F401
    browsers,
    evtx,
    jumplists,
    lnk,
    mft,
    prefetch,
    recyclebin,
    registry,
    shellbags,
    srum,
)
