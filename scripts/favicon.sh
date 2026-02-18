#!/bin/bash
# Generate favicons from a source image using ImageMagick

SOURCE=$1
DEST=$2

if [ -z "$SOURCE" ]; then
    echo "Usage: $0 <source_image> [destination_dir]"
    exit 1
fi

if [ -z "$DEST" ]; then
    DEST="./favicons"
fi

mkdir -p "$DEST"

# Check for convert
if ! command -v convert &> /dev/null; then
    echo "ImageMagick 'convert' not found. Please install ImageMagick."
    exit 1
fi

echo "Generating favicons from $SOURCE to $DEST..."

# Apple Touch Icon
convert "$SOURCE" -resize 180x180 "$DEST/apple-touch-icon.png"

# Favicon 32x32
convert "$SOURCE" -resize 32x32 "$DEST/favicon-32x32.png"

# Favicon 16x16
convert "$SOURCE" -resize 16x16 "$DEST/favicon-16x16.png"

# Android Chrome 192x192
convert "$SOURCE" -resize 192x192 "$DEST/android-chrome-192x192.png"

# Android Chrome 512x512
convert "$SOURCE" -resize 512x512 "$DEST/android-chrome-512x512.png"

# Favicon.ico (multi-size)
convert "$SOURCE" -define icon:auto-resize=64,48,32,16 "$DEST/favicon.ico"

echo "Done."
