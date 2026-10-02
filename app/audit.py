import time,structlog
log=structlog.get_logger("audit")
def emit(event,**fields):
    log.info(event,ts=time.time(),**fields)
