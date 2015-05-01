#!/bin/sh
clear

jar cvf jar/Library.jar Library

jar tvf jar/Library.jar

javac -classpath .:jar/sqlitejdbc-v056.jar.:jar/Library.jar Library/*.java Server/*.java 

jar cvf jar/carapaca.jar Server

jar tvf jar/carapaca.jar