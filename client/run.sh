#!/bin/sh
java -Djava.net.preferIPv4Stack=true -cp .:jar/carapaca.jar:jar/Library.jar:jar/sqlitejdbc-v056.jar Client.Carapaca root@localhost:12345 docs/clientRSA.key 12345