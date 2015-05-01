cls
jar cvf jar\Library.jar Library
jar tvf jar\Library.jar

javac -cp .:jar\sqlitejdbc-v056.jar.:jar\Library.jar Library\*.java Server\*.java 

jar cvf jar\carapacad.jar Server
jar tvf jar\carapacad.jar