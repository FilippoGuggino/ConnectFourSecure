#!/bin/bash

konsole -e "./server.o" &
SER=$!
sleep .5
konsole -e "./client.o" &
CLI=$!

#wait $SER $CLI

function cleanup(){
  echo "Killing Processes"
  sudo kill $SER $CLI
}

trap cleanup EXIT
trap cleanup INT
