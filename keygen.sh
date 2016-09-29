#!/bin/sh -e

die() {
	echo $1
	exit 1
}

test -e secrets || mkdir secrets || die "secrets already exists"

(test -e secrets/achmed-pub.gpg && test -e secrets/achmed-sec.gpg) ||  echo "
%echo Generating a configuration OpenPGP key
Key-Type: default
Subkey-Type: default
Name-Real: achmed
Name-Comment: achmed certificate encryption keys
Name-Email: achmed@offblast.org
Expire-Date: 0
%pubring secrets/achmed-pub.gpg
%secring secrets/achmed-sec.gpg
%commit
%echo done
" | gpg2 --batch --armor --gen-key || die "unable to create gpg keys"

test -e secrets/acme.key || openssl ecparam -out secrets/acme.key -name prime256v1 -genkey || die "unable to create acme secret"

test -e secrets/secrets.yaml || cat > secrets/secrets.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: achmed
data:
  acme.key: $(base64 -w 0 < secrets/acme.key)
  achmed-pub.gpg: $(base64 -w 0 < secrets/achmed-pub.gpg)
  achmed-sec.gpg: $(base64 -w 0 < secrets/achmed-sec.gpg)
EOF

