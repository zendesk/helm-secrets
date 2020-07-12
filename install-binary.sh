#!/usr/bin/env bash

set -ueo pipefail

SOPS_VERSION="3.5.0"
SOPS_DEB_URL="https://github.com/mozilla/sops/releases/download/v${SOPS_VERSION}/sops_${SOPS_VERSION}_amd64.deb"
SOPS_DEB_SHA="27369eb0a50fd7c34f4a01fa8bbfee617a5883a83ad1118c377a21caf1a1a655"
SOPS_LINUX_URL="https://github.com/mozilla/sops/releases/download/v${SOPS_VERSION}/sops-v${SOPS_VERSION}.linux"
SOPS_LINUX_SHA="610fca9687d1326ef2e1a66699a740f5dbd5ac8130190275959da737ec52f096"

RED='\033[0;31m'
GREEN='\033[0;32m'
#BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NOC='\033[0m'

# Find some tools
case "${HELM_BIN}" in
    helm)
        HELM_DIR="$(dirname $(command -v helm))"
        ;;
    *)
        HELM_DIR="$(dirname ${HELM_BIN})"
        ;;
esac

get_sha_256 () {
    if command -v sha256sum > /dev/null; then res=$(sha256sum $1)
    elif command -v shasum > /dev/null; then res=$(shasum -a 256 $1)
    else res=$(/usr/bin/shasum -a 256 $1)
    fi
    echo $res | cut -d ' ' -f 1
}

# Install the helm wrapper in the same dir as helm itself. That's not
# guaranteed to work, but it's better than hard-coding it.
HELM_WRAPPER="${HELM_DIR}/helm-wrapper"

if hash sops 2>/dev/null; then
    echo "sops is already installed:"
    sops --version
else

    # Try to install sops.

    ### Mozilla SOPS binary install
    if [ "$(uname)" == "Darwin" ];
    then
            brew install sops
    elif [ "$(uname)" == "Linux" ];
    then
        if which dpkg;
        then
            curl -sL "${SOPS_DEB_URL}" > /tmp/sops
            if [ "$(get_sha_256 /tmp/sops)" == "${SOPS_DEB_SHA}" ];
            then
                sudo dpkg -i /tmp/sops;
            else
                echo -e "${RED}Wrong SHA256${NOC}"
            fi
        else
            curl -sL "${SOPS_LINUX_URL}" > /tmp/sops
            if [ "$(get_sha_256 /tmp/sops)" == "${SOPS_LINUX_SHA}" ];
            then
                chmod +x /tmp/sops
                mv /tmp/sops /usr/local/bin/
            else
                echo -e "${RED}Wrong SHA256${NOC}"
            fi
        fi
        rm /tmp/sops 2>/dev/null || true
    else
        echo -e "${RED}No SOPS package available${NOC}"
        exit 1
    fi
fi

### git diff config
if [ -x "$(command -v git --version)" ];
then
    git config --global diff.sopsdiffer.textconv "sops -d"
else
    echo -e "${RED}[FAIL]${NOC} Install git command"
    exit 1
fi
