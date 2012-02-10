from settings import *

DEBUG = False
TEMPLATE_DEBUG = DEBUG

INSTALLED_APPS += ('gunicorn',)

DATABASES =  {
    'default': {
        'ENGINE': 'django.db.backends.psycopg2',
        'NAME': 'logger',
        'USER': 'logger',
        'PASSWORD': 'ohyeswearewatchingsoveryclosely',
        'HOST': '137.22.30.46',
        'PORT': '5432',
    }
}

