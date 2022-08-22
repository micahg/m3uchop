# M3U Chop

Pre-process a playlist

## Setup

Ensure you have the requests python module installed.

Set your `M3U_URL` to either a remote source or local file.

Set your `config.json` to contain the following:

```
{
    "output": "filtered.m3u",
    "groups": [
        "group_one"
    ],
    "channels": [
        "channel_one"
    ]
}
```

There you can specify where to write the filtered output, and add some groups or specific names that you care about.

Note that groups must match exactly (case insensitive), while channels are a substring. So the example above would match a channel named `channel_one_hundred`.

## Getting Categories

```
grep -Po 'group-title="\K[^"]*' playlist.m3u  | sort | uniq
```