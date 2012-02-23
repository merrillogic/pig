#!/bin/sh

cd "`dirname "$0"`"
python manage.py run_gunicorn --settings=honeynet_web.settings_production
