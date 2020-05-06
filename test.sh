#!/usr/bin/env bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NOC='\033[0m'
ALREADY_ENC="Already encrypted"
SECRETS_REPO="https://github.com/futuresimple/helm-secrets"
HELM_CMD="helm"

trap_error() {
    local status=$?
    if [ "$status" -ne 0 ]; then
        echo -e "${RED}General error${NOC}"
        exit 1
    else
        exit 0
    fi
    echo -e "${RED}General error${NOC}"
}

trap "trap_error" EXIT

test_encryption() {
fingerprint1Count=$(cat < "${secret}" | grep -Ec "40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE")
fingerprint2Count=$(cat < "${secret}" | grep -Ec "4434EA5D05F10F59D0DF7399AF1D073646ED4927")

ok=0

if [[ $secret == *"./example/helm_vars/projectX/"* ]]; then
  [[ "${fingerprint1Count}" -eq 0 && "${fingerprint2Count}" -eq 1 ]] && ok=1
elif [[ $secret == *"./example/helm_vars/projectY/"* ]]; then
  [[ "${fingerprint1Count}" -eq 1 && "${fingerprint2Count}" -eq 0 ]] && ok=1
elif [[ $secret == *"./example/helm_vars/"* ]]; then
  [[ "${fingerprint1Count}" -eq 1 && "${fingerprint2Count}" -eq 1 ]] && ok=1
else
  echo "Secret in unkown folder"
fi

if [ "${ok}" -eq 1 ];
then
    echo -e "${GREEN}[OK]${NOC} File properly encrypted"
else
    echo -e "${RED}[FAIL]${NOC} ${secret} Not encrypted properly"
    exit 1
fi
}

test_view() {
result_view=$(${HELM_CMD} secrets view "${secret}" | grep -Ec "(40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE|4434EA5D05F10F59D0DF7399AF1D073646ED4927)")
if [ "${result_view}" -gt 0 ];
then
    echo -e "${RED}[FAIL]${NOC} Decryption failed"
else
    echo -e "${GREEN}[OK]${NOC} File decrypted and viewable"
fi
}

test_decrypt() {
ymldec=$(sed -e "s/\\.y\(a\|\)ml$/.yaml.dec/" <<<"$secret")

if [ -f "${ymldec}" ];
then

    result_dec=$(cat < "${ymldec}" | grep -Ec "(40B6FAEC80FD467E3FE9421019F6A67BB1B8DDBE|4434EA5D05F10F59D0DF7399AF1D073646ED4927)")
    if [ "${result_dec}" -gt 0 ];
    then
        echo -e "${RED}[FAIL]${NOC} Decryption failed"
    else
        echo -e "${GREEN}[OK]${NOC} File decrypted"
    fi
else
    echo -e "${RED}[FAIL]${NOC} ${ymldec} not exist"
    exit 1
fi
}

test_clean() {
if [ -f "${secret_dec}" ];
then
    echo -e "${RED}[FAIL]${NOC} ${secret_dec} exist after cleanup"
    exit 1
else
    echo "looking in $(dirname ${secret_dec})/no-secret.yaml.dec"
    if [ ! -f "$(dirname ${secret_dec})/no-secret.yaml.dec" ];
    then
        echo -e "${RED}[FAIL]${NOC} no-secret.yaml.dec has been deleted"
        exit 1
    else
        echo -e "${GREEN}[OK]${NOC} Cleanup ${mode}"
    fi
fi
}

test_already_encrypted() {
if [[ "${enc_res}" == *"${ALREADY_ENC}"* ]];
then
    echo -e "${GREEN}[OK]${NOC} Already Encrypted"
else
    echo -e "${RED}[FAIL]${NOC} Not Encrypted or re-encrypted. Should be already encrypted with no re-encryption."
    exit 1
fi
}


test_helm_secrets() {
echo -e "${YELLOW}+++${NOC} ${BLUE}Testing ${secret}${NOC}"
secret_dec=$(sed -e "s/\\.y\(a\|\)ml$/.yaml.dec/" <<<"$secret")

echo -e "${YELLOW}+++${NOC} Encrypt and Test"
"${HELM_CMD}" secrets enc "${secret}" > /dev/null || exit 1 && \
test_encryption "${secret}"

echo -e "${YELLOW}+++${NOC} Test if 'Already Encrypted' feature works"
enc_res=$("${HELM_CMD}" secrets enc "${secret}" | grep "${ALREADY_ENC}")
test_already_encrypted "${enc_res}"

echo -e "${YELLOW}+++${NOC} View encrypted Test"
test_view "${secret}"

echo -e "${YELLOW}+++${NOC} Decrypt"
"${HELM_CMD}" secrets dec "${secret}" > /dev/null || exit 1 && \
test_decrypt "${secret}" && \
cp "${secret_dec}" "${secret_dec}.bak"

echo -e "${YELLOW}+++${NOC} Cleanup Test"
"${HELM_CMD}" secrets clean "$(dirname ${secret})" > /dev/null || exit 1
mode="specified directory"
test_clean "${secret}" "${mode}" && \
cp "${secret_dec}.bak" "${secret_dec}" && \
"${HELM_CMD}" secrets clean "${secret_dec}" > /dev/null || exit 1
mode="specified .dec file"
test_clean "${secret}" "${secret_dec}" "${mode}" # && \
# cp "${secret_dec}.bak" "${secret_dec}" && \
# "${HELM_CMD}" secrets clean "${secret_dec}" > /dev/null || exit 1
# mode="specified encrypted secret file"
# test_clean "${secret}" "${mode}"
# The functionality above doesn't work, it only works with .dec in filename
rm "${secret_dec}.bak"

echo -e "${YELLOW}+++${NOC} Once again Encrypt and Test"
"${HELM_CMD}" secrets enc "${secret}" > /dev/null || exit 1 && \
test_encryption "${secret}"
}

echo -e "${YELLOW}+++${NOC} Installing helm-secrets plugin"
if [ "$(helm plugin list | tail -n +2 | cut -d ' ' -f 1 | grep -c "secrets")" -eq 1 ];
then
    echo -e "${GREEN}[OK]${NOC} helm-secrets plugin installed"
else
    "${HELM_CMD}" plugin install "${SECRETS_REPO}" 2>/dev/null
    echo -e "${RED}[FAIL]${NOC} No helm-secrets plugin aborting"
    exit 1
fi

echo ""
if [ -x "$(command -v gpg --version)" ];
then
    echo -e "${YELLOW}+++${NOC} Importing private pgp key for projectx"
    gpg --import example/pgp/projectx.asc
    echo ""
    echo -e "${YELLOW}+++${NOC} Importing private pgp key for projectx"
    gpg --import example/pgp/projecty.asc
    echo ""
else
    echo -e "${RED}[FAIL]${NOC} Install gpg"
    exit 1
fi

echo -e "${YELLOW}+++${NOC} Show helm_vars tree from example"
if [ -x "$(command -v tree --version)" ];
then
    tree -Ca example/helm_vars/
else
    echo -e "${RED}[FAIL]${NOC} Install tree command"
    exit 1
fi

echo ""
for secret in $(find . -type f -name *secret*.yaml -o -name *secret*.yml);
do test_helm_secrets "${secret}";
done
