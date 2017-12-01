#!/bin/bash

SOURCE="${BASH_SOURCE[0]}"
#print $SOURCE

while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
#print $DIR

make
cd bin; java -cp ".:../lib/*" cloudStorage.app.DeleteLocalFiles
gnome-terminal --working-directory=$DIR/bin -e 'java -cp ".:../lib/*" funct.pki.PKIServerApp'
sleep 1
gnome-terminal --working-directory=$DIR/bin -e 'java -cp ".:../lib/*" cloudStorage.app.ServerRegisterApp'
sleep 1
gnome-terminal --working-directory=$DIR/bin -e 'java -cp ".:../lib/*" cloudStorage.app.ServerApp'
sleep 1
gnome-terminal --working-directory=$DIR/bin -e 'java -cp ".:../lib/*" cloudStorage.app.UserRegisterApp 101'
sleep 1
gnome-terminal --working-directory=$DIR/bin -e 'java -cp ".:../lib/*" cloudStorage.app.UserGUI'



# if no other node processes are active, to close all these
# gnome-terminal is enough to do 'killall node'
