#!/bin/sh
FILES=`cat .files | sed "s/^/$2\//"`
cd ..
mv $1 $2
tar zcvf $2/$2.tar.gz $FILES
mv $2 $1
cd -
