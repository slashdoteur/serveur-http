#!/bin/bash
# Script d’installation pour bichttpd
set -e
 
# Base d’installation
BASE_DIR="$HOME/opt/bichttpd"
 
echo "Création de l’arborescence dans $BASE_DIR ..."
mkdir -p "$BASE_DIR/usr/sbin"
mkdir -p "$BASE_DIR/etc"
mkdir -p "$BASE_DIR/var/log"
mkdir -p "$BASE_DIR/srv/http"
 
# Compilation automatique si le binaire n’existe pas
if [ ! -f "./bichttpd" ]; then
    echo "Compilation de bichttpd.c ..."
    gcc -Wall -Werror bichttpd.c -o bichttpd
fi
 
# Installation du binaire
echo "Installation du binaire..."
cp ./bichttpd "$BASE_DIR/usr/sbin/"
chmod +x "$BASE_DIR/usr/sbin/bichttpd"

echo "Installation terminée."
echo "Binaire installé dans $BASE_DIR/usr/sbin/"