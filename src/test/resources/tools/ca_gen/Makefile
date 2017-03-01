PASSWORD=changeit
TMP_KEYSTORE=keystore.jks
HOSTNAME=localhost
CLIENTNAME=client_cert

DNAME_CA='CN=some_ca,C=CC'
# For server certificates, the Common Name (CN) must be the hostname
DNAME_HOST='CN=${HOSTNAME},C=CC'
DNAME_CLIENT='CN=${CLIENTNAME},C=CC'
TRUSTSTORE=truststore.jks

all:	clean create-keystore-with-ca create-truststore-with-ca make-client display

create-keystore-with-ca:
	# Generate a certificate authority (CA)
	keytool -genkey -alias ca -ext BC=ca:true \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 3650 -dname ${DNAME_CA} \
	    -keystore ${TMP_KEYSTORE} -storepass ${PASSWORD}

export-authority:
	# Export certificate authority
	keytool -export -alias ca -file ca.crt -rfc \
	    -keystore ${TMP_KEYSTORE} -storepass ${PASSWORD}

create-truststore-with-ca: export-authority
	# Import certificate authority into a new truststore
	keytool -import -trustcacerts -noprompt -alias ca -file ca.crt \
	    -keystore ${TRUSTSTORE} -storepass ${PASSWORD}

make-client:
	# Generate client certificate
	keytool -genkey -alias ${CLIENTNAME} \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 3650 -dname ${DNAME_CLIENT} \
	    -keystore ${TMP_KEYSTORE} -storepass ${PASSWORD}
	# Generate a host certificate signing request
	keytool -certreq -alias ${CLIENTNAME} -ext BC=ca:true \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA \
	    -validity 3650 -file "${CLIENTNAME}.csr" \
	    -keystore ${TMP_KEYSTORE} -storepass ${PASSWORD}
	# Generate signed certificate with the certificate authority
	keytool -gencert -alias ca \
	    -validity 3650 -sigalg SHA512withRSA \
	    -infile "${CLIENTNAME}.csr" -outfile "${CLIENTNAME}.crt" -rfc \
		-keystore ${TMP_KEYSTORE} -storepass ${PASSWORD}
    # Import now-signed cer
	keytool -import -trustcacerts -alias $(CLIENTNAME) \
	    -file "$(CLIENTNAME).crt" \
	    -keystore $(TMP_KEYSTORE) -storepass $(PASSWORD)
	# Export private certificate for importing into a browser
	keytool -importkeystore -srcalias ${CLIENTNAME} \
	    -srckeystore ${TMP_KEYSTORE} -srcstorepass ${PASSWORD} \
	    -destkeystore "${CLIENTNAME}.p12" -deststorepass ${PASSWORD} \
	    -deststoretype PKCS12

display:
	echo "The ${TRUSTSTORE} trusts:"
	keytool -list -keystore ${TRUSTSTORE} -storepass ${PASSWORD}
	echo
	echo "Your client cert should be in ${CLIENTNAME}.p12"

clean:
	# Remove generated artifacts
	rm -f "${CLIENTNAME}.p12" "${CLIENTNAME}.csr" "${CLIENTNAME}.crt" ca.crt "${TRUSTSTORE}" "${TMP_KEYSTORE}"
