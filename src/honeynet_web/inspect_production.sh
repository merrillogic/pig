#!/bin/sh

cd "`dirname "$0"`"

python manage.py shell --settings=honeynet_web.settings_production
