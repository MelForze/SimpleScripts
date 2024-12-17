#!/bin/bash

# Убедимся, что файл с URL-адресами задан
if [ -z "$1" ]; then
  echo "Usage: $0 <file_with_urls>"
  exit 1
elif [ -z "$2" ]; then
  echo "What to collect?
-everything   Will collect everything 
-all    Will collect all 
-path   Will collect all paths
-file   Will collect all files"
  exit 1
fi

if [ "$2" == "-all" ] || [ "$2" == "-everything" ]; then
  mkdir -p all
  # Читаем файл построчно
  for URL1 in $(cat "$1"); do
    # Заменяем символы в URL для URL2
    echo "${URL1} Started!"
    URL2=$(echo "$URL1" | sed 's/https:\/\//https_/' | sed 's/http:\/\//http_/' | sed 's/[\.:\/]/_/g')

    # Запускаем первую команду
    katana -u "$URL1" -d 5 -crawl-scope "$URL1" -js-crawl -jsluice -crawl-duration 15m -known-files all -disable-redirects -headless -c 150 -p 1 -silent >> "all/${URL2}_active.txt"
    echo "Active DONE"
    
    # Сортируем и убираем дубликаты
    sort -u "all/${URL2}_active.txt" > "all/${URL2}_Katana.txt"
    
    # Удаляем временные файлы
    rm "all/${URL2}_active.txt"
  done
fi

if [ "$2" == "-file" ] || [ "$2" == "-everything" ]; then 
  mkdir -p files
  for URL1 in $(cat "$1"); do
    # Заменяем символы в URL для URL2
    echo "${URL1} Started!"
    URL2=$(echo "$URL1" | sed 's/https:\/\//https_/' | sed 's/http:\/\//http_/' | sed 's/[\.:\/]/_/g')

    # Запускаем
    katana -u "$URL1" -d 5 -crawl-scope "$URL1" -js-crawl -jsluice -crawl-duration 15m -known-files all -disable-redirects -headless -c 150 -p 1 -silent -f ufile >> "files/${URL2}_active.txt"
    echo "Active DONE"
    
    # Сортируем и убираем дубликаты
    sort -u "files/${URL2}_active.txt" > "files/${URL2}_Katana.txt"
    
    # Удаляем временные файлы
    rm "files/${URL2}_active.txt"
  done
fi

if [ "$2" == "-path" ] || [ "$2" == "-everything" ]; then
  mkdir -p paths
  for URL1 in $(cat "$1"); do
    # Заменяем символы в URL для URL2
    echo "${URL1} Started!"
    URL2=$(echo "$URL1" | sed 's/https:\/\//https_/' | sed 's/http:\/\//http_/' | sed 's/[\.:\/]/_/g')
    echo "$URL1" >> "paths/${URL2}_active.txt"
    
    # Запускаем
    katana -u "$URL1" -d 5 -crawl-scope "$URL1" -js-crawl -jsluice -crawl-duration 15m -known-files all -disable-redirects -headless -c 150 -p 1 -silent -f udir >> "paths/${URL2}_active.txt"
    echo "Active DONE"
    
    # Сортируем и убираем дубликаты
    sort -u "paths/${URL2}_active.txt" > "paths/${URL2}_Katana.txt"
    
    # Удаляем временные файлы
    rm "paths/${URL2}_active.txt"
  done
fi