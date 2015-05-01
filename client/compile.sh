#!/bin/sh
clear

jar cvf jar/Library.jar Library

jar tvf jar/Library.jar

javac -classpath .:jar/sqlitejdbc-v056.jar.:jar/Library.jar Library/*.java Client/*.java 

jar cvf jar/carapaca.jar Client

jar tvf jar/carapaca.jar