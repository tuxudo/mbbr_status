#!/usr/local/munkireport/munkireport-python3

# This is the clientside module for mbbr_status

import os
import subprocess
import io
import plistlib
import sys

def get_mbbr_info():
    '''Uses mbbr to get Malwarebytes activation status for this machine'''
    cmd = ['/usr/local/bin/mbbr register']
    rundata = subprocess.check_output(cmd, shell=True)
    try:
        buf = io.StringIO(rundata.decode())
        keylist = buf.read().replace('\t', '').splitlines()
        return keylist
    except Exception:
        return {}

def flatten_mbbr_info(dict):
    '''Flatten the output into a dictionary'''
    mbbrdata = {}
    for i in dict:
        if i:
            pair = i.split(':', 1)
            if len(pair) < 2:
                continue
            key, value = pair
            mbbrdata[key] = value
    return mbbrdata

def main():
    '''Main'''

    # Check for existance of /usr/local/bin/mbbr before going further
    mbbr_dir = '/usr/local/bin/mbbr'
    if not os.path.exists(mbbr_dir):
        print('Client is missing the mbbr tool at /usr/local/bin/mbbr. Exiting')
        exit(0)

    # Get results
    result = dict()
    info = get_mbbr_info()
    result = flatten_mbbr_info(info)

    # Write mbbr results to cache
    cachedir = '%s/cache' % os.path.dirname(os.path.realpath(__file__))
    output_plist = os.path.join(cachedir, 'malwarebytes.plist')
    try:
        plistlib.writePlist(result, output_plist)
    except:
        with open(output_plist, 'wb') as fp:
            plistlib.dump(result, fp, fmt=plistlib.FMT_XML)

if __name__ == "__main__":
    main()
