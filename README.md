# JOSEServer
Test server to handle elliptic curve JOSE compact serialized tokens using ECDH-ES algorithms to verify
invalid curve attacks.

Maven 
`mvn clean compile exec:java`

The server is assigned on port `8081`. It can be changed in the projects main mehtod in the
`PublicKeyIssuer.java` file.

Since Java version 1.8, the Java Cryptographic Archetecture detects invalid points by default. To
test attacks against the server and the two vulnerable libraries implemented, it has to run on a Java Runtime Environment below that version, e. g. version
1.7.

To get the servers public keys, a request on the root `/` results in a list of JWE headers for all
libraries, containing information for each NIST curve P-256, P-384, P-521.

Testing JWEs against the server, needs to specify the library, that shall be used.
This can be done by requesting either `/jose4j` or `/nimbus`. A typical use case for JWEs is to
transmit information in the URL using parameters. By default, the parameter is declares as `token`.
The following request can be used as example to communicate with the libraries.

´http://localhost:8081/nimbus/?token=eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJ0eXAiOiJKV0UiLCJlcGsiOiB7Imt0eSI6ICJFQyIsImNydiI6ICJQLTI1NiIsIngiOiAiQU9JWDBxejRYVlRTRjNBWWh3MEV1NHlhbjN0R25RMEVpMmRzWm1hQW1CQTkiLCJ5IjogIkFOQ1RMMXM1d1g2TU9URV96R2RJR2FpUmZ5TDcycE5FVUREbXFsUHdYekFXIn19.WhCut9yB3UHwKevGW5_r9bMyNtUpVqY-SsvJh4EZAgGpajmdYm63qA.AAAAAAAAAAAAAAAAAAAAAA.BeSR3eUORVEwn_HGu99icw.DoNgFMhPEAj8p4dvggC9pg
´

The response differs, if the used curve point is valid and the token is properly generated. In this
case the response is the decrypted payload. Otherwise the internal exception will be delegated as
response. 

Note, that the servers key pairs are dynamically generated and therefore static as long as the
server runs.
