#!/bin/sh

set -e  # Exit immediately if a command exits with a non-zero status

# Define the target directory
TARGET_DIR="initramfs"

# Check if the directory exists and remove it
if [ -d "$TARGET_DIR" ]; then
  echo "Directory '$TARGET_DIR' exists. Deleting it..."
  rm -rf "$TARGET_DIR"
fi

# Recreate the directory
echo "Creating directory '$TARGET_DIR'..."
mkdir "$TARGET_DIR"

# Change into the directory
cd "$TARGET_DIR"

# Extract the initramfs.cpio.gz file
echo "Extracting initramfs.cpio.gz into '$TARGET_DIR'..."
gzip -dc ../initramfs.cpio.gz | cpio -idmv

# Returning to the parent directory
cd ..

echo "Extraction complete."
