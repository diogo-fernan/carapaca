#!/bin/sh
java -Djava.net.preferIPv4Stack=true -classpath .:jar/carapacad.jar:jar/Library.jar:jar/sqlitejdbc-v056.jar Server.Carapacad rsa docs/serverRSA.key 12345 12345