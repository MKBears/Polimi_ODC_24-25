#!/bin/sh

set -e  # Exit immediately if a command exits with a non-zero status

# Define the target directory
TARGET_DIR="initramfs"

# Check if the directory exists
if [ ! -d "$TARGET_DIR" ]; then
  echo "Error: Directory '$TARGET_DIR' does not exist. Cannot pack it."
  exit 1
fi

# Change into the directory
cd "$TARGET_DIR"

# Compress the directory contents into initramfs.cpio.gz
echo "Packing contents of '$TARGET_DIR' into initramfs.cpio.gz..."
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz

# Return to the parent directory
cd ..

echo "Packing complete. File saved as initramfs.cpio.gz."
