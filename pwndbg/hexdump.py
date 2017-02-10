#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Hexdump implementation, ~= stolen from pwntools.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import copy
import string

import pwndbg.color.hexdump as H
import pwndbg.color.theme as theme
import pwndbg.config

color_scheme = None
printable = None

def groupby(array, count, fill=None):
    array = copy.copy(array)
    while fill and len(array) % count:
        array.append(fill)
    for i in range(0, len(array), count):
        yield array[i:i+count]

config_colorize_ascii = theme.Parameter('hexdump-colorize-ascii', True, 'whether to colorize the hexdump command ascii section')
config_separator      = theme.Parameter('hexdump-ascii-block-separator', '│', 'block separator char of the hexdump command')

@pwndbg.config.Trigger([H.config_normal, H.config_zero, H.config_special, H.config_printable, config_colorize_ascii])
def load_color_scheme():
    global color_scheme, printable
    #
    # We want to colorize the hex characters and only print out
    # printable values on the righ hand side.
    #
    color_scheme = {i:H.normal("%02x" % i) for i in range(256)}
    printable = {i:H.normal('.') for i in range(256)}

    for c in bytearray((string.ascii_letters + string.digits + string.punctuation).encode('utf-8', 'ignore')):
        color_scheme[c] = H.printable("%02x" % c)
        printable[c] = H.printable("%s" % chr(c)) if pwndbg.config.hexdump_colorize_ascii else "%s" % chr(c)

    for c in bytearray(b'\x00'):
        color_scheme[c] = H.zero("%02x" % c)
        printable[c] = H.zero('.') if pwndbg.config.hexdump_colorize_ascii else '.'

    for c in bytearray(b'\xff\x7f\x80'):
        color_scheme[c] = H.special("%02x" % c)
        printable[c] = H.special('.') if pwndbg.config.hexdump_colorize_ascii else '.'

    color_scheme[-1] = '  '
    printable[-1] = ' '

def hexdump(data, address = 0, width = 16, skip = True,
            addr_callback=lambda addr, text: text,
            hex_callback=lambda addr, text: text,
            ascii_callback=lambda addr, text: text):
    """Returns an iterator over the colorized, hex-dumped data.

    Arguments:
        data(bytes): Raw data to dump
        address(int): Address of the first byte, used for the left column
        width(int): Width of the display, in bytes.  Must be a multiple of 4.
        skip(bool): Whether to skip repeating chunks of data
        addr_callback(func): Callable to augment the colorized address.
        hex_callback(func): Callable to augment the colorized hex data.
            Signature is callback(address, text) where address is the address
            of the bute, and text is the colorized text which is emitted at that
            address.  This callback is on the hex representation.
        ascii_callback(func): Callable to augment the colorized ASCII data.

    """
    if not color_scheme or not printable:
        load_color_scheme()
    data = list(bytearray(data))
    base = address
    last_line = None
    skipping  = False
    for i, line in enumerate(groupby(data, width, -1)):
        if skip and line == last_line:
            if not skipping:
                skipping = True
                yield '...'
            continue
        else:
            skipping  = False
            last_line = line

        hexline = []

        hexline.append(H.offset("+%04x " % (i*width)))
        hexline.append(H.address("%#08x  " % (base + (i*width))))

        hexaddr = address
        for group in groupby(line, 4):
            for char in group:
                char = hex_callback(hexaddr, color_scheme[char])
                hexline.append(char)
                hexline.append(' ')
                hexaddr += 1
            hexline.append(' ')

        hexline.append(H.separator('%s' % config_separator))

        ascaddr = address
        for group in groupby(line, 4):
            for char in group:
                char = ascii_callback(ascaddr, printable[char])
                hexline.append(char)
                ascaddr += 1
            hexline.append(H.separator('%s' % config_separator))

        address += width
        yield(''.join(hexline))

    hexline = []

    if address:
        hexline.append(H.offset("+%04x " % len(data)))

    hexline.append(H.address("%#08x  " % (base + len(data))))

    yield ''.join(hexline)
