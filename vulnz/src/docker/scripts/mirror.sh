#!/bin/sh

echo "Updating..."

DELAY_ARG=""
if [ -z $NVD_API_KEY ]; then
  DELAY_ARG="--delay=10000"
fi

if [ -n "${DELAY}" ]; then
  DELAY_ARG="--delay=$DELAY"
fi

java $JAVA_OPT -jar /usr/local/bin/vulnz cve $DELAY_ARG --cache --directory /usr/local/apache2/htdocs
