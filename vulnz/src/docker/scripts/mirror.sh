#!/bin/sh

echo "Updating..."

java $JAVA_OPT -jar /usr/local/bin/vulnz cve --cache --directory /usr/local/apache2/htdocs
