import os
import re
import sys
import time
import signal
import logging
import json
import asyncio
from argparse import ArgumentParser
from urllib.parse import urlparse
from pathlib import Path

import requests
from asyncinotify import Inotify, Mask

URL_ENV_VAR = 'M3U_URL'
CONFIG_ENV_VAR = 'M3U_CONFIG'
EVERY_ENV_VAR = 'M3U_EVERY'
CONFIG_FILE = 'config.json'
LOG_FORMAT = '%(asctime)-15s [%(funcName)s] %(message)s'

M3U_HEADER = b'#EXTM3U'
M3U_INFO = b'#EXTINF:'
M3U_GROUP = b'#EXTGRP:'
M3U_INFO_GROUP_RE = re.compile(b'.*group-title=\"(.*?)\"')
M3U_INFO_RE = re.compile(b'.*tvg-id=\"(.*?)\".*tvg-name=\"(.*?)\"')


def load_config(config_file):
    """
    Load the configuration file
    """
    try:
        with open(config_file, 'rb') as file:
            return json.load(file)
    except FileNotFoundError as err:
        logging.error('Unable to open config file %s: %s', config_file, err)
        return None
    except json.JSONDecodeError:
        logging.error('Invalid JSON in config file %s', config_file)
        return None
    except Exception as err:
        logging.error('Unexpected error while loading config file %s: %s', config_file, err)
        return None


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
        logging.error('No playlist in %s or config %s', URL_ENV_VAR, CONFIG_FILE)
        raise Exception('No playlist configured')

    try:
        pl_url = urlparse(playlist)
    except ValueError:
        logging.error('Unable to parse playlist URL "%s"', playlist)
        raise Exception('Invalid playlist URL')

    pl_path = pl_url.path
    if not (pl_url.scheme and pl_url.hostname):
        logging.info('Using local file "%s"', pl_url.path)
        return pl_path

    logging.info('Downloading playlist from "%s"', playlist)
    try:
        resp = requests.get(playlist, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        raise Exception(f'Download failed: {e}')

    logging.info('Download complete')
    if resp.status_code != 200:
        logging.error('Invalid response while downloading URL (%s: %s)',
                      resp.status_code, resp.content)
        raise Exception(f'Invalid response: {resp.status_code}')

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

def filter_playlist(config, input_lines, output):
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
    for line in input_lines:

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
                    # if we have an EXTINF line, remap the group
                    if info:
                        info = re.sub(base_re, rep_re, info)
                    # if we have an EXTGRP line, remap the group
                    if group:
                        group = b':'.join([group.split(b':')[0],remap]) + b'\n'

                # if we found an EXTINF line and it matches the criteria, write it
                if info:
                    output.write(info)
                # if we found an EXTGRP line and it matches the criteria, write it
                if group:
                    output.write(group)

                # write the URL
                output.write(url)

                # reset everything for the next stream
                info = None
                group = None
                url = None
                group_name = None
                keep = False
                remap = False

        if keep and group_name and not group_name in all_groups:
            all_groups.append(group_name)

    logging.info('Groups matched (by group or id): %s', all_groups)


async def process_playlist(cfg, output_filename):
    """
    Run the playlist processing logic
    """
    try:
        # Run blocking I/O in executor to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        pl_filename = await loop.run_in_executor(None, get_playlist, cfg)
        
        await loop.run_in_executor(None, lambda: filter_playlist_wrapper(cfg, pl_filename, output_filename))
        logging.info('Playlist processing complete')
    except Exception as e:
        logging.error('Error processing playlist: %s', e)

def filter_playlist_wrapper(cfg, pl_filename, output_filename):
    """Wrapper to handle file opening for filter_playlist in executor"""
    with open(output_filename, 'wb') as out_file:
        with open(pl_filename, 'rb') as in_file:
            filter_playlist(cfg, in_file, out_file)

async def watch_config(config_file, queue):
    """
    Watch for changes to the config file and put events in the queue
    """
    path = Path(config_file).resolve()
    # Watch the directory, as editors often replace files atomically (rename/move)
    # which changes the inode and breaks direct file watches.
    dir_path = path.parent
    filename = path.name

    with Inotify() as inotify:
        inotify.add_watch(dir_path, Mask.CLOSE_WRITE | Mask.MOVED_TO | Mask.CREATE)
        async for event in inotify:
            if event.name and str(event.name) == filename:
                logging.info('Config file %s changed', config_file)
                await queue.put('config_change')

async def run_scheduler(every, queue):
    """
    Put events in the queue based on the timer
    """
    if every is None:
        return
        
    while True:
        logging.info('Sleeping for %d hours', every)
        await asyncio.sleep(every * 3600)
        await queue.put('timer')

async def main():
    """
    Run the program
    """
    parser = ArgumentParser()
    parser.add_argument('-d', '--debug', action='store_true', dest='debug',
                        help='debug logging')
    parser.add_argument('-c', '--config', action='store', dest='config',
                        help='config file location')
    parser.add_argument('-l', '--logfile', action='store', dest='logfile',
                        help='log file location')
    parser.add_argument('-o', '--output', action='store', dest='output',
                        help='output file location')
    parser.add_argument('-e', '--every', action='store', dest='every', type=int,
                        help='run continuously every N hours')
    args = parser.parse_args()
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format=LOG_FORMAT, level=log_level, filename=args.logfile if args.logfile else None)

    config_source = args.config if args.config else os.environ.get(CONFIG_ENV_VAR, CONFIG_FILE)
    
    every = args.every
    if every is None and EVERY_ENV_VAR in os.environ:
        try:
            every = int(os.environ[EVERY_ENV_VAR])
        except ValueError:
            logging.error('Invalid value for %s: %s', EVERY_ENV_VAR, os.environ[EVERY_ENV_VAR])
            sys.exit(1)

    # Initial load and run
    cfg = load_config(config_source)
    output_filename = None
    if cfg is not None:
        output_filename = args.output if args.output else cfg['output'] if 'output' in cfg else None
        if not output_filename:
            logging.error('No output in %s', config_source)
            cfg = None

    if cfg is not None and output_filename is not None:
        await process_playlist(cfg, output_filename)

    if not every and not (os.environ.get('M3U_WATCH_CONFIG')): # Keep running if every is set OR we just want to watch
        # If no loop is requested and no explicit watch request (optional feature), exit
        if every is None:
            return

    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def request_shutdown(signame):
        logging.info('Received %s, shutting down', signame)
        try:
            queue.put_nowait('shutdown')
        except asyncio.QueueFull:
            pass
    
    # Start background tasks
    tasks = []
    tasks.append(asyncio.create_task(watch_config(config_source, queue)))
    if every:
        tasks.append(asyncio.create_task(run_scheduler(every, queue)))

    for signame in ('SIGTERM', 'SIGINT', 'SIGQUIT'):
        if hasattr(signal, signame):
            loop.add_signal_handler(getattr(signal, signame), request_shutdown, signame)

    logging.info('Entering event loop. Waiting for %s', 'timer or config change')

    try:
        while True:
            reason = await queue.get()
            logging.info('Triggered by: %s', reason)

            if reason == 'shutdown':
                break
            
            # Reload config if file changed
            if reason == 'config_change':
                # Small delay to ensure write is complete
                await asyncio.sleep(0.1)
                try:
                    cfg = load_config(config_source)
                    # Update output filename if it changed in config
                    if cfg is None:
                        logging.error('Config load failed; skipping processing until next trigger')
                        continue
                    if not args.output and 'output' in cfg:
                        output_filename = cfg['output']
                    if output_filename is None:
                        logging.error('No output in %s', config_source)
                        cfg = None
                        continue
                except Exception as e:
                    logging.error("Failed to reload config: %s", e)
                    continue

            if cfg is None or output_filename is None:
                logging.info('Skipping processing due to missing config/output')
                queue.task_done()
                continue

            await process_playlist(cfg, output_filename)
            queue.task_done()
            
    except asyncio.CancelledError:
        logging.info("Shutting down")
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
