#!/bin/sh

echo "Validating the cache..."
for file in /usr/local/apache2/htdocs/*.gz; do
    if ! gzip -t "$file"; then
        echo "Corrupt gz file detected: $file, clearing cache and re-running mirror"
        rm -rf /usr/local/apache2/htdocs/*
        supervisorctl start init_nvd_cache
        break
    fi
done

