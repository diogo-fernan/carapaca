# carapaca

*carapaça* (Portuguese word for *shell*) is a Java implementation of a simpler version of the Secure Shell (SSH) tool. It follows a client-server architecture and was designed while having in mind the Request for Comments (RFCs) [4251](https://www.ietf.org/rfc/rfc4251.txt), [4252](https://www.ietf.org/rfc/rfc4252.txt), [4253](https://www.ietf.org/rfc/rfc4253.txt) and [4254](https://www.ietf.org/rfc/rfc4254.txt), which respectively elaborate on the **architecture of SSH**, on the **SSH authentication protocol**, on the **SSH transport layer protocol**, and on the **SSH connection protocol**. The aforementioned protocols define the security and cryptographic primitives employed by SSH in order to ensure integrity, confidentiality and privacy in a given session. As in SSH, *carapaca* allows the specification and negotiation of a cipher suite when a remote session is initialized, supporting the Diffie-Hellman (DH) key exchange protocol, symmetric encryption (AES and DES) with a few cipher modes (OFB8 and CFB8), hash functions (MD5 and SHA1), message authentication codes (HMAC with SHA1 or MD5 and SHA1 or MD5 with AES or DES), and digital signatures (MD5 or SHA1 with RSA), amongst others. *carapaca* allows issuing commands on the remote host with few restrictions.

*carapaca* was developed a few years back by a group of researchers for academic purposes. The tool is available for anyone who wishes to explore the inner workings of the protocols behind SSH or even look at the extensive Java cryptographic details.

# Dependencies and Usage

*carapaca* was developed with the [Java Cryptography Architecture (JCA)](http://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html) and the Java Cryptography Extension (JCE), which implement many security functions in the Java Development Kit (JDK). At the time, *carapaca* was written with JDK version 1.7.0_03.

The server side of *carapaca* is called *carapacad*. It spawns a thread for each connecting user and stores user authentication information in a local [SQLite](http://www.sqlite.org/) database. At the time, it was used the [SQLite JDBC driver](https://bitbucket.org/xerial/sqlite-jdbc/) with version 0.56.

*carapacad* depicts a functionality to generate an RSA key pair needed for running the server, which accepts it as input argument along with the desired listening port (*e.g.*, 22 or some other binding port). The client application also uses a local SQLite database to store key information of the servers to which it connects to. The user password is only requested by the server after the protocol suite is negotiated and after the session keys are exchanged. Once the user is successfully authenticated, a shell is spawned where commands issued are passed onto the remote Linux `/bin/sh/` or Windows `cmd.exe` shells. The command output is captured at the remote host and is sent back to the client, pretty printing the data to the command line interface.

The program execution entry points for the client and server applications are respectively defined in `client/Client/Carapaca.java` and in `server/Server/Carapacad.java`. The `Library` folder included in both applications contains common code. The software package is also bundled with compilation and execution scripts for both the server and client applications.

# Author

[@dfernan__](https://twitter.com/dfernan__)