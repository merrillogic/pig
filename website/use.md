---
title: Use?
layout: page
---

## Setup

We just had a network of a few computers and virtual machines to run attacks on. You can do this however you want. Log traffic to `pcap` files.

You don't even need a network. All you need is some `pcap` files to parse on the server.

## Running the server

1. <a href="code.html">Get the code</a>.

2. Install the requirements in `requirements.txt`. Perhaps `pip install -r requirements.txt` will work.

3. Once this is done, go to the `pig_web` directory. `manage.py` contains all of the usual Django commands (e.g. `syncdb`, `runserver`, etc.) as well as a few of our own.

      - `start_analyzer` will start all of our attack analyzers on the database specified in the settings file.
      - `parse_pcap` will parse a `pcap`-file into the database.
      - `traffic_report` generates the data for our graph.
      - `parse_arp` will parse the output of the `arp` command and load ARP records into the database. This is necessary for detecting Man in the Middle Attacks.

4. Want to run it in production? Deploy as you would any other Django application. Personally, I recommend [Gunicorn](http://gunicorn.org/) and [Supervisor](http://supervisord.org/). Our configuration is in `conf/supervisord.conf` if you're looking for inspiration.

## Building your own analyzers

<a href="https://bitbucket.org/rouge8/pig/wiki/AttackAnalyzer">Check out the wiki.</a>
