import os
import re
import sys
import logging
import json
from argparse import ArgumentParser
from urllib.parse import urlparse

import requests

URL_ENV_VAR = 'M3U_URL'
CONFIG_FILE = 'config.json'
LOG_FORMAT = '%(asctime)-15s [%(funcName)s] %(message)s'

M3U_HEADER = b'#EXTM3U'
M3U_INFO = b'#EXTINF:'
M3U_GROUP = b'#EXTGRP:'
M3U_INFO_GROUP_RE = re.compile(b'.*group-title=\"(.*?)\"')
M3U_INFO_RE = re.compile(b'.*tvg-id=\"(.*?)\".*tvg-name=\"(.*?)\"')


def load_config():
    """
    Load the configuration file
    """
    try:
        with open(CONFIG_FILE, 'rb') as file:
            return json.load(file)
    except FileNotFoundError as err:
        logging.error(f'Unable to open config file {CONFIG_FILE}: {err}')
        sys.exit(1)
    except json.JSONDecodeError as err:
        logging.error(f'Invalid JSON in config file {CONFIG_FILE}')
        sys.exit(1)


def get_playlist(config):
    """
    Get (or download) the playlist
    """
    playlist=None
    if URL_ENV_VAR in os.environ:
        playlist = os.environ[URL_ENV_VAR]
    elif 'playlist' in config:
        playlist = config['playlist']

    if not playlist:
        logging.error(f'No playlist in {URL_ENV_VAR} or config {CONFIG_FILE}')
        sys.exit(1)
    
    try:
        pl_url = urlparse(playlist)
    except ValueError as err:
        logging.error(f'Unable to parse playlist URL "{playlist}"')
        sys.exit(1)

    pl_path = pl_url.path
    if not (pl_url.scheme and pl_url.hostname):
        logging.info(f'Using local file "{pl_url.path}"')
        return pl_path

    logging.info(f'Downloading playlist from "{playlist}"')
    resp = requests.get(playlist)
    logging.info('Download complete')
    if resp.status_code != 200:
        logging.error(f'Invalid response while downloading URL ({resp.status_code}: {resp.content}')
        sys.exit(1)

    output = '/tmp/playlist.m3u'
    with open(output, 'wb') as file:
        file.write(resp.content)

    return output


def byte_cast(item):
    if type(item) == dict:
        result = {k : bytes(v, 'ascii') for k,v in item.items()}
    else:
        result = bytes(item.lower(), 'ascii')
    return result


def match_item(criteria, item, exact = False):
    """
    Determine if an item matches and if it should be remapped
    @return boolean tuple representing match and remap
    """
    if len(item) == 0:
        return False, None

    for criterion in criteria:
        if type(criterion) == dict and criterion['name'] == item:
            return True, criterion['group_remap'] if 'group_remap' in criterion else None
        if type(criterion) == dict and criterion['name'] in item and not exact:
            return True, criterion['group_remap'] if 'group_remap' in criterion else None
        elif item in criterion:
            return True, None

    return False, None

def filter_playlist(config, input, output):
    """
    Filter the entries in the playlist.
    """
    groups = [ bytes(group.lower(), 'ascii') for group in config['groups'] ]
    names = [ byte_cast(name) for name in config['names'] ]
    ids = [ byte_cast(id) for id in config['ids'] ]

    url = None
    group = None
    info = None
    group_name = None
    keep = False
    remap = None
    all_groups = []
    for line in input:

        # let the header through
        if line.startswith(M3U_HEADER):
            output.write(line)
            continue
        elif line.startswith(M3U_INFO):
            info = line

            # see if the group matches
            match = M3U_INFO_GROUP_RE.match(line)
            if match is not None:
                group_name = match.group(1).lower()
                if group_name in groups:
                    keep = True

            # see if the name tag matches
            match = M3U_INFO_RE.match(line)
            if match is not None:
                tvg = match.group(1).lower()
                info_name = match.group(2).lower()

                # check for keep/remap on name
                keep_flag, remap_flag = match_item(names, info_name)
                keep = True if keep_flag else keep
                if keep:
                    pass
                remap = remap_flag if remap_flag is not None else remap

                # check for exact match/remap on tvg-id
                keep_flag, remap_flag = match_item(ids, tvg, True)
                keep = True if keep_flag else keep
                if keep:
                    pass
                remap = remap_flag if remap_flag is not None else remap

            # see if the other name matches
            info_name = line.rsplit(b',')[1].lower()
            keep_flag, remap_flag = match_item(names, info_name)
            keep = True if keep_flag else keep
            remap = remap_flag if remap_flag is not None else remap
        elif line.startswith(M3U_GROUP):
            group = line
            group_name = line.split(b':')[1].strip().lower()
            if group_name in groups:
                keep = True
        else:
            url = line
            if keep:
                if remap:
                    base_re = rb'(.*group-title=\")(.*?)(\".*)'
                    rep_re = rb"\1" + remap + rb"\3"
                    info = re.sub(base_re, rep_re, info)
                    group = b':'.join([group.split(b':')[0],remap]) + b'\n'
                output.write(info)
                output.write(group)
                output.write(url)
                info = None
                group = None
                url = None
                group_name = None
                keep = False
                remap = False

        if keep and group_name and not group_name in all_groups:
            all_groups.append(group_name)

    logging.info(f'Groups matched (by group or id): {all_groups}')


def __main__():
    """
    Run the program
    """
    parser = ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                        help='debug logging')
    parser.add_argument('-l', '--logfile', action='store', dest='logfile',
                        help='log file location')
    parser.add_argument('-o', '--output', action='store', dest='output',
                        help='output file location')
    args = parser.parse_args()
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format=LOG_FORMAT, level=log_level, filename=args.logfile if args.logfile else None)
    cfg = load_config()

    output_filename = args.output if args.output else cfg['output'] if 'output' in cfg else None
    if not output_filename:
        logging.error(f'No output in {CONFIG_FILE}')
        sys.exit(1)

    pl_filename = get_playlist(cfg)

    with open(output_filename, 'wb') as out_file:
        with open(pl_filename, 'rb') as in_file:
            filter_playlist(cfg, in_file, out_file)


if __name__ == '__main__':
    __main__()