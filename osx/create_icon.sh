#!/bin/bash

#
# https://stackoverflow.com/a/31883126
#

export PROJECT=LiliTun
export ICONDIR=$PROJECT.app/Contents/Resources/$PROJECT.iconset
export ORIGICON=../../android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png

mkdir -p $ICONDIR

# Normal screen icons
for SIZE in 16 32 64 128 256 512; do
sips -z $SIZE $SIZE $ORIGICON --out $ICONDIR/icon_${SIZE}x${SIZE}.png ;
done

# Retina display icons
for SIZE in 32 64 256 512; do
sips -z $SIZE $SIZE $ORIGICON --out $ICONDIR/icon_$(expr $SIZE / 2)x$(expr $SIZE / 2)x2.png ;
done

# Make a multi-resolution Icon
iconutil -c icns -o $PROJECT.app/Contents/Resources/$PROJECT.icns $ICONDIR
rm -rf $ICONDIR #it is useless now
