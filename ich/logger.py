#coding: utf-8

'''
    logger.py
    ~~~~~~~~~

    God said, we need a logger, so the logger came.
'''

import logging

log_level = logging.DEBUG

logger = logging.getLogger(__name__)
logger.setLevel(log_level)

formatter = logging.Formatter('%(levelname)s - %(message)s')

console_handler = logging.StreamHandler()
console_handler.setLevel(log_level)
console_handler.setFormatter(formatter)

logger.addHandler(console_handler)
