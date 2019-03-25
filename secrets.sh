#!/usr/bin/env bash
# shellcheck disable=SC1003

# Parts of this project are MIT Licensed, they will be denoted below.

# MIT License

# Original work Copyright (c) 2017 Jonathan Peres
# Modified work Copyright (c) 2019 Just_Insane

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# The suffix to use for decrypted files. The default can be overridden using
# the HELM_SECRETS_DEC_SUFFIX environment variable.
DEC_SUFFIX="${HELM_SECRETS_DEC_SUFFIX:-.yaml.dec}"

# Make sure HELM_BIN is set (normally by the helm command)
HELM_BIN="${HELM_BIN:-helm}"

# The secret store to use to store values
# Defaults to "secret/helm"
if [[ -z "${VAULT_PATH}" ]]
then
    default=secret/helm
    read -p "Enter a Vault KV Store path [$default]: " VAULT_PATH
    VAULT_PATH=${VAULT_PATH:-$default}
    unset default
fi

# The plaintext deliminator used to specify which values need to be stored in Vault
# Defaults to "changme"
if [[ -z "${secret_deliminator}" ]]
then
    default=changeme
    read -p "Enter a secret deliminator [$default]: " secret_deliminator
    secret_deliminator=${secret_deliminator:-$default}
    echo "Secret Deliminator is $secret_deliminator"
    unset default
fi

getopt --test > /dev/null
if [[ $? -ne 4 ]]
then
    cat <<EOF
I’m sorry, "getopt --test" failed in this environment.

You may need to install enhanced getopt, e.g. on OSX using
"brew install gnu-getopt".
EOF
    exit 1
fi

set -ueo pipefail

usage() {
    cat <<EOF
GnuPG secrets encryption in Helm Charts

This plugin provides ability to encrypt/decrypt secrets files
to store in less secure places, before they are installed using
Helm.

To decrypt/encrypt/edit you need to initialize/first encrypt secrets with
sops - https://github.com/mozilla/sops

Available Commands:
  enc    	Encrypt secrets file
  dec    	Decrypt secrets file
  view   	Print secrets decrypted
  edit   	Edit secrets file and encrypt afterwards
  clean         Remove all decrypted files in specified directory (recursively)
  install	wrapper that decrypts secrets[.*].yaml files before running helm install
  upgrade	wrapper that decrypts secrets[.*].yaml files before running helm upgrade
  lint		wrapper that decrypts secrets[.*].yaml files before running helm lint
  diff		wrapper that decrypts secrets[.*].yaml files before running helm diff
                  (diff is a helm plugin)

EOF
}

enc_usage() {
    cat <<EOF
Encrypt secrets

It uses your gpg credentials to encrypt .yaml file. If the file is already
encrypted, look for a decrypted ${DEC_SUFFIX} file and encrypt that to .yaml.
This allows you to first decrypt the file, edit it, then encrypt it again.

You can use plain sops to encrypt - https://github.com/mozilla/sops

Vault secrets

If VAULT_TOKEN env variable is set, automatically store values in Vault.
Secret values must be entered into the helm chart as a specific vaule, in this case "changme", for example

  db:
    name: nextcloud
    user: nextcloud
    password: changeme

would prompt to enter a value for the db password.

Example:
  $ ${HELM_BIN} secrets enc <SECRET_FILE_PATH>
  $ git add <SECRET_FILE_PATH>
  $ git commit
  $ git push

EOF
}

dec_usage() {
    cat <<EOF
Decrypt secrets

It uses your gpg credentials to decrypt previously encrypted .yaml file.
Produces ${DEC_SUFFIX} file.

You can use plain sops to decrypt specific files - https://github.com/mozilla/sops

Vault secrets

If VAULT_TOKEN env variable is set, automatically pull values from Vault in a plaintext file.
Values must be pulled in order to update or install via Helm.

For example:

 db:
    name: nextcloud
    user: nextcloud
    password: <value entered during enc command>

Example:
  $ ${HELM_BIN} secrets dec <SECRET_FILE_PATH>

Typical usage:
  $ ${HELM_BIN} secrets dec secrets/myproject/secrets.yaml
  $ vim secrets/myproject/secrets.yaml.dec

EOF
}

view_usage() {
    cat <<EOF
View specified secrets[.*].yaml file

Example:
  $ ${HELM_BIN} secrets view <SECRET_FILE_PATH>

Typical usage:
  $ ${HELM_BIN} secrets view secrets/myproject/nginx/secrets.yaml | grep basic_auth

EOF
}

edit_usage() {
    cat <<EOF
Edit encrypted secrets

Decrypt encrypted file, edit and then encrypt

You can use plain sops to edit - https://github.com/mozilla/sops

Example:
  $ ${HELM_BIN} secrets edit <SECRET_FILE_PATH>
  or $ sops <SECRET_FILE_PATH>
  $ git add <SECRET_FILE_PATH>
  $ git commit
  $ git push

EOF
}

clean_usage() {
    cat <<EOF
Clean all decrypted files if any exist

It removes all decrypted ${DEC_SUFFIX} files in the specified directory
(recursively) if they exist.

Example:
  $ ${HELM_BIN} secrets clean <dir with secrets>

EOF
}

install_usage() {
    cat <<EOF
Install a chart

This is a wrapper for the "helm install" command. It will detect -f and
--values options, and decrypt any secrets.*.yaml files before running "helm
install".

Example:
  $ ${HELM_BIN} secrets install <HELM INSTALL OPTIONS>

Typical usage:
  $ ${HELM_BIN} secrets install -n i1 stable/nginx-ingress -f values.test.yaml -f secrets.test.yaml

EOF
}

upgrade_usage() {
    cat <<EOF
Upgrade a deployed release

This is a wrapper for the "helm upgrade" command. It will detect -f and
--values options, and decrypt any secrets.*.yaml files before running "helm
upgrade".

Example:
  $ ${HELM_BIN} secrets upgrade <HELM UPGRADE OPTIONS>

Typical usage:
  $ ${HELM_BIN} secrets upgrade i1 stable/nginx-ingress -f values.test.yaml -f secrets.test.yaml

EOF
}

lint_usage() {
    cat <<EOF
Run helm lint on a chart

This is a wrapper for the "helm lint" command. It will detect -f and
--values options, and decrypt any secrets.*.yaml files before running "helm
lint".

Example:
  $ ${HELM_BIN} secrets lint <HELM LINT OPTIONS>

Typical usage:
  $ ${HELM_BIN} secrets lint ./my-chart -f values.test.yaml -f secrets.test.yaml

EOF
}

diff_usage() {
    cat <<EOF
Run helm diff on a chart

"diff" is a helm plugin. This is a wrapper for the "helm diff" command. It
will detect -f and --values options, and decrypt any secrets.*.yaml files
before running "helm diff".

Example:
  $ ${HELM_BIN} secrets diff <HELM DIFF OPTIONS>

Typical usage:
  $ ${HELM_BIN} secrets diff upgrade i1 stable/nginx-ingress -f values.test.yaml -f secrets.test.yaml

EOF
}

is_help() {
    case "$1" in
	-h|--help|help)
	    return 0
	    ;;
	*)
	    return 1
	    ;;
    esac
}

# Parses yaml document
# Based on https://github.com/jasperes/bash-yaml
parse_yaml() {
    local yaml_file=$1
    local s
    local w
    local fs

    s='[[:space:]]*'
    w='[a-zA-Z0-9_.-]*'
    fs="$(echo @|tr @ '\034')"

    (
        sed -e '/- [^\“]'"[^\']"'.*: /s|\([ ]*\)- \([[:space:]]*\)|\1-\'$'\n''  \1\2|g' |

        sed -ne '/^--/s|--||g; s|\"|\\\"|g; s/[[:space:]]*$//g;' \
            -e "/#.*[\"\']/!s| #.*||g; /^#/s|#.*||g;" \
            -e "s|^\($s\)\($w\)$s:$s\"\(.*\)\"$s\$|\1$fs\2$fs\3|p" \
            -e "s|^\($s\)\($w\)${s}[:-]$s\(.*\)$s\$|\1$fs\2$fs\3|p" |

        awk -F"$fs" '{
            indent = length($1)/2;
            if (length($2) == 0) { conj[indent]="+";} else {conj[indent]="";}
            vname[indent] = $2;
            for (i in vname) {if (i > indent) {delete vname[i]}}
                if (length($3) > 0) {
                    vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
                    printf("%s%s%s%s=(\"%s\")\n", "",vn, $2, conj[indent-1],$3);
                }
            }' |

        sed -e 's/_=/+=/g' |

        awk 'BEGIN {
                FS="=";
                OFS="="
            }
            /(-|\.).*=/ {
                gsub("-|\\.", "_", $1)
            }
            { print }'
    ) < "$yaml_file"
}

# Created environment variables for secrets key invocations as well as the image repository
# Based on https://github.com/jasperes/bash-yaml
create_variables() {
    local yaml_file="$1"
    eval "$(parse_yaml "$yaml_file" | awk -v secret_deliminator="$secret_deliminator" '$0 ~ secret_deliminator {print}')"
}

# Get file path from root of Git repo to provide a well defined location to store secrets
get_path() {
    repository_path=`git rev-parse --show-prefix`
    repository_path=`echo $repository_path | sed 's/.$//'`
}

# Cleans the environment variable array to remove the "secret_deliminator" variable from being returned
clean_array() {
    delete=(secret_deliminator)
    for target in "${delete[@]}"; do
        for i in "${!envsarray[@]}"; do
            if [[ ${envsarray[i]} = "${delete[0]}" ]]; then
                unset 'envsarray[i]'
            fi
        done
    done

    for i in "${!envsarray[@]}"; do
        new_envsarray+=( "${envsarray[i]}" )
    done
    envsarray=("${new_envsarray[@]}")
    unset new_envsarray
}

# Prompts user for secret material and uploads to vault K/V Store
set_secrets() {
    report () { echo "${1%%=*}"; };

    envsarray=()
    while IFS= read -r line; do
        envsarray+=( "$line" )
    done < <( set -o posix +o allexport; set | grep "$secret_deliminator" | awk 'match($0, "\.=") {print substr($0, 1, RSTART)}' )

    clean_array

    for env in "${envsarray[@]}";
    do
        echo "Enter a secret value for $env"
        echo "Stored at $VAULT_PATH/$repository_path/$yml/$env"
        stty -echo
        read -r usersecret;
        stty echo
        vault kv put $VAULT_PATH/$repository_path/$yml/$env value=$usersecret
    done
}

# Pulls secret material from vault K/V store and saves it to a .dec file, needed by helm to update or deploy
get_secrets() { 
    report () { echo "${1%%=*}"; };

    envsarray=()
    while IFS= read -r line; do
        envsarray+=( "$line" )
    done < <( set -o posix +o allexport; set | grep "$secret_deliminator" | awk 'match($0, "\.=") {print substr($0, 1, RSTART)}' )

    clean_array

    yml_dec="$yml.dec"
    cp $yml $yml_dec

    for env in "${envsarray[@]}";
    do
        sec_values=`vault kv get $VAULT_PATH/$repository_path/$yml/$env | grep "value" | awk '/value/{print $2}'`
        for sec in "${sec_values[@]}";
        do
            #this will fail if "$secret_delminator" is on the first line of the file, but is required for GNU sed
            sed -i.dec "1,// s/$secret_deliminator/$sec/" $yml_dec
            rm "$yml_dec.dec"
        done
    done
}

encrypt_helper() {
    local dir=$(dirname "$1")
    local yml=$(basename "$1")
    cd "$dir"
    [[ -e "$yml" ]] || { echo "File does not exist: $dir/$yml"; exit 1; }
    local ymldec=$(sed -e "s/\\.yaml$/${DEC_SUFFIX}/" <<<"$yml")
    [[ -e $ymldec ]] || ymldec="$yml"
    
    if [[ -z "${VAULT_TOKEN}" ]]
    then
        if [[ $(grep -C10000 'sops:' "$ymldec" | grep -c 'version:') -gt 0 ]]
        then
        echo "Already encrypted: $ymldec"
        return
        fi
        if [[ $yml == $ymldec ]]
        then
        sops --encrypt --input-type yaml --output-type yaml --in-place "$yml"
        echo "Encrypted $yml"
        else
        sops --encrypt --input-type yaml --output-type yaml "$ymldec" > "$yml"
        echo "Encrypted $ymldec to $yml"
        fi
    else
        get_path
        create_variables $yml
        set_secrets
    fi
}

enc() {
    if is_help "$1"
    then
	enc_usage
	return
    fi
    yml="$1"
    if [[ ! -f "$yml" ]]
    then
	echo "$yml doesn't exist."
    else
	echo "Encrypting $yml"
	encrypt_helper "$yml"
    fi
}

# Name references ("declare -n" and "local -n") are a Bash 4 feature.
# For previous versions, work around using eval.
decrypt_helper() {
    local yml="$1" __ymldec __dec

    if [[ ${BASH_VERSINFO[0]} -lt 4 ]]
    then
	local __ymldec_var='' __dec_var=''
	[[ $# -ge 2 ]] && __ymldec_var=$2
	[[ $# -ge 3 ]] && __dec_var=$3
	[[ $__dec_var ]] && eval $__dec_var=0
    else
	[[ $# -ge 2 ]] && local -n __ymldec=$2
	[[ $# -ge 3 ]] && local -n __dec=$3
    fi

    __dec=0
    [[ -e "$yml" ]] || { echo "File does not exist: $yml"; exit 1; }

    if [[ -z "${VAULT_TOKEN}" ]]
    then
        if [[ $(grep -C10000 'sops:' "$yml" | grep -c 'version:') -eq 0 ]]
        then
        echo "Not encrypted: $yml"
        __ymldec="$yml"
        else
        __ymldec=$(sed -e "s/\\.yaml$/${DEC_SUFFIX}/" <<<"$yml")
        if [[ -e $__ymldec && $__ymldec -nt $yml ]]
        then
            echo "$__ymldec is newer than $yml"
        else
            sops --decrypt --input-type yaml --output-type yaml "$yml" > "$__ymldec" || { rm "$__ymldec"; exit 1; }
            __dec=1
        fi
        fi

        if [[ ${BASH_VERSINFO[0]} -lt 4 ]]
        then
        [[ $__ymldec_var ]] && eval $__ymldec_var="'$__ymldec'"
        [[ $__dec_var ]] && eval $__dec_var="'$__dec'"
        fi
        true # just so that decrypt_helper will exit with a true status on no error
    else
        get_path
        create_variables $yml
        get_secrets
    fi
}


dec() {
    if is_help "$1"
    then
	dec_usage
	return
    fi
    yml="$1"
    if [[ ! -f "$yml" ]]
    then
	echo "$yml doesn't exist."
    else
	echo "Decrypting $yml"
	decrypt_helper "$yml"
    fi
}

view_helper() {
    local yml="$1"
    [[ -e "$yml" ]] || { echo "File does not exist: $yml"; exit 1; }
    sops --decrypt --input-type yaml --output-type yaml "$yml"
}

view() {
    if is_help "$1"
    then
	view_usage
	return
    fi
    local yml="$1"
    view_helper "$yml"
}

edit_helper() {
    local yml="$1"
    [[ -e "$yml" ]] || { echo "File does not exist: $yml"; exit 1; }
    exec sops --input-type yaml --output-type yaml "$yml" < /dev/tty
}

edit() {
    local yml="$1"
    edit_helper "$yml"
}

clean() {
    if is_help "$1"
    then
	clean_usage
	return
    fi
    local basedir="$1"
    find "$basedir" -type f -name "secrets*${DEC_SUFFIX}" -print0 | xargs -r0 rm -v
}

helm_wrapper() {
    local cmd="$1" subcmd='' cmd_version=''
    shift
    if [[ $cmd == diff ]]
    then
	subcmd="$1"
	shift
	cmd_version=$(${HELM_BIN} diff version)
    fi

    # cache options for the helm command in a file so we don't need to parse the help each time
    local helm_version=$(${HELM_BIN} version --client --short)
    local cur_options_version="${helm_version}${cmd_version:+ ${cmd}: ${cmd_version}}"
    local optfile="$HELM_PLUGIN_DIR/helm.${cmd}${subcmd:+.$subcmd}.options" options_version='' options='' longoptions=''
    [[ -f $optfile ]] && . "$optfile"

    if [[ $cur_options_version != $options_version ]]
    then
	local re='(-([a-zA-Z0-9]), )?--([-_a-zA-Z0-9]+)( ([a-zA-Z0-9]+))?' line
	options='' longoptions=''

	# parse the helm command options and option args from the help output
	while read line
	do
	    if [[ $line =~ $re ]]
	    then
		local opt="${BASH_REMATCH[2]}" lopt="${BASH_REMATCH[3]}" optarg="${BASH_REMATCH[5]:+:}"
		[[ $opt ]] && options+="${opt}${optarg}"
		[[ $lopt ]] && longoptions+="${longoptions:+,}${lopt}${optarg}"
	    fi
	done <<<"$(${HELM_BIN} "$cmd" $subcmd --help | sed -e '1,/^Flags:/d' -e '/^Global Flags:/,$d' )"

	cat >"$optfile" <<EOF
options_version='$cur_options_version'
options='$options'
longoptions='$longoptions'
EOF
    fi
    
    # parse command line
    local parsed # separate line, otherwise the return value of getopt is ignored
    # if parsing fails, getopt returns non-0, and the shell exits due to "set -e"
    parsed=$(getopt --options="$options" --longoptions="$longoptions" --name="${HELM_BIN} $cmd${subcmd:+ ${subcmd}}" -- "$@")

    # collect cmd options with optional option arguments
    local -a cmdopts=() decfiles=()
    local yml ymldec decrypted
    eval set -- "$parsed"
    while [[ $# -gt 0 ]]
    do
	case "$1" in
	    --)
		# skip --, and what remains are the cmd args
		shift 
		break
		;;
            -f|--values)
		cmdopts+=("$1")
		yml="$2"
		if [[ $yml =~ ^(.*/)?secrets(\.[^.]+)*\.yaml$ ]]
		then
		    decrypt_helper $yml ymldec decrypted
		    cmdopts+=("$ymldec")
		    [[ $decrypted -eq 1 ]] && decfiles+=("$ymldec")
		else
		    cmdopts+=("$yml")
		fi
		shift # to also skip option arg
		;;
	    *)
		cmdopts+=("$1")
		;;
	esac
	shift
    done

    # run helm command with args and opts in correct order
    set +e # ignore errors
    ${HELM_BIN} ${TILLER_HOST:+--host "$TILLER_HOST" }"$cmd" $subcmd "$@" "${cmdopts[@]}"

    # cleanup on-the-fly decrypted files
    [[ ${#decfiles[@]} -gt 0 ]] && rm -v "${decfiles[@]}"
}

helm_command() {
    if [[ $# -lt 2 ]] || is_help "$2"
    then
	"${1}_usage"
	return
    fi
    helm_wrapper "$@"
}

case "${1:-help}" in
    enc)
	if [[ $# -lt 2 ]]
	then
	    enc_usage
	    echo "Error: secrets file required."
	    exit 1
	fi
	enc "$2"
	shift
	;;
    dec)
	if [[ $# -lt 2 ]]
	then
	    dec_usage
	    echo "Error: secrets file required."
	    exit 1
	fi
	dec "$2"
	;;
    view)
	if [[ $# -lt 2 ]]
	then
	    view_usage
	    echo "Error: secrets file required."
	    exit 1
	fi
	view "$2"
	;;
    edit)
	if [[ $# -lt 2 ]]
	then
	    edit_usage
	    echo "Error: secrets file required."
	    exit 1
	fi
	edit "$2"
	shift
	;;
    clean)
	if [[ $# -lt 2 ]]
	then
	    clean_usage
	    echo "Error: Chart package required."
	    exit 1
	fi
	clean "$2"
	;;
    install|upgrade|lint|diff)
	helm_command "$@"
	;;
    --help|-h|help)
	usage
	;;
    *)
	usage
	exit 1
	;;
esac

exit 0