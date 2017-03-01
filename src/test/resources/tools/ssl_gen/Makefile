PASSWORD=changeit
KEYSTORE=keystore.jks
HOSTNAME=localhost
DNAME='CN=${HOSTNAME},C=CC'

all:	clean create-keystore-with-cert display

create-keystore-with-cert:
	# Generate a cert
	keytool -genkey -alias cert \
	    -keyalg RSA -keysize 4096 -sigalg SHA512withRSA -keypass ${PASSWORD} \
	    -validity 3650 -dname ${DNAME} \
	    -keystore ${KEYSTORE} -storepass ${PASSWORD}

display:
	echo "The ${KEYSTORE} contains:"
	keytool -list -keystore ${KEYSTORE} -storepass ${PASSWORD}

clean:
	# Remove generated artifacts
	rm -f "${KEYSTORE}"
