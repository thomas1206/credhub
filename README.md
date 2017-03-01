# CredHub 

The CredHub server manages secrets like passwords, certificates, ssh keys, rsa keys, strings 
(arbitrary values) and CAs. CredHub provides a REST API to get, set, or generate and securely store
such secrets.
 
* [CredHub Tracker](https://www.pivotaltracker.com/n/projects/1977341)
 
See additional repos for more info:

* [credhub-cli](https://github.com/pivotal-cf/credhub-cli) :     command line interface for credhub
* [credhub-acceptance-tests](https://github.com/pivotal-cf/credhub-acceptance-tests) : integration tests written in Go.
* [credhub-release](https://github.com/pivotal-cf/credhub-release) : BOSH release of CredHub server **[Currently private - Coming Soon]**

## Development Notes

### Starting the server

Start the app: `./start_server.sh`

### Running against different databases

CredHub supports MySql, Postgres, and H2. You can change which database is used by
adjusting the spring datasource values in the `application-dev.yml` file. Migrations 
should run automatically during application startup.

Testing with different databases requires you to set a system property with the profile 
corresponding to your desired database. For example, to test with H2, you'll need to run
the tests with the `-Dspring.profiles.active=unit-test-h2` profile. 

During development, it is helpful to set up different IntelliJ testing profiles that use
the following VM Options:

- `-ea -Dspring.profiles.active=unit-test-h2` for testing with H2
- `-ea -Dspring.profiles.active=unit-test-mysql` for testing with MySQL
- `-ea -Dspring.profiles.active=unit-test-postgres` for testing with Postgres



# To SSL and x509 client certificates locally, do the following:

# * Run 'make' in src/test/resources/tools/ssl_gen

# * Run 'make' in src/test/resources/tools/ca_gen

# * Uncomment the following block:

#server:
#  ssl:
#    enabled: true
#    key-store: src/test/resources/tools/ssl_gen/keystore.jks
#    key-password: changeit
#    key-alias: cert
#    ciphers: ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-RSA-AES256-GCM-SHA384
#    client-auth: want
#    trust-store: src/test/resources/tools/ca_gen/truststore.jks
#    trust-store-password: changeit
#    trust-store-type: JKS

# * Use the client cert:
#   curl -H "Content-Type: application/json" -X POST -d '{"name":"cred","type":"password"}' https://localhost:9000/api/v1/data -k --cert src/test/resources/tools/ca_gen/tmp/client_cert.p12:changeit

# * Use oauth:
#   /Users/pivotal/go/src/github.com/pivotal-cf/credhub-cli/build/credhub generate -n foo -t password > /dev/null
#   curl -H "Authorization: bearer $(cat ~/.credhub/config.json | jq -r '.AccessToken')" -H "Content-Type: application/json" -X POST -d '{"name":"cred","type":"password"}' https://localhost:9000/api/v1/data -k
