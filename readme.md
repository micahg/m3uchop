# M3U Chop

Pre-process a playlist

## Setup

Ensure you have the requests python module installed.

Set your `M3U_URL` to either a remote source or local file.

Set your `config.json` to contain the following:

```
{
    "groups": [
        "group_one"
    ],
    ids: [
        "tvg_id_one"
    ],
    "channels": [
        "channel_one"
    ]
}
```

There you can specify where to write the filtered output, and add some groups or specific names that you care about.

Note that groups must match exactly (case insensitive), while channels are a substring. So the example above would match a channel named `channel_one_hundred`.

If you want this to run periodically on cron, hourly for example, you can run:

```
M3U_URL="https://example.com/playlist.m3u"
0 * * * * cd /home/user/m3uchop && python3 m3uchop.py -l /var/log/m3uchop.log -o /tmp/filtered.m3u
```

## Development

Just notes here...

### Getting Categories

```
grep -Po 'group-title="\K[^"]*' playlist.m3u  | sort | uniq
```