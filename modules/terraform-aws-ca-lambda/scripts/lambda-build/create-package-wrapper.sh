set -e

eval "$(jq -r '@sh "source_code_path=\(.source_code_path) function_name=\(.function_name) runtime=\(.runtime) path_cwd=\(.path_cwd) platform=\(.platform)"')"

source $(dirname "$0")/create-package.sh 1>&2

echo '{}'
