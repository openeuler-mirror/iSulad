#!/bin/bash
#
# This script is the implementation portal for the iSulad project Personal level build static check.
# set -euxo pipefail
#######################################################################
##- @Copyright (C) Huawei Technologies., Ltd. 2019-2020. All rights reserved.
# - iSulad licensed under the Mulan PSL v2.
# - You can use this software according to the terms and conditions of the Mulan PSL v2.
# - You may obtain a copy of Mulan PSL v2 at:
# -     http://license.coscl.org.cn/MulanPSL2
# - THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# - IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# - PURPOSE.
# - See the Mulan PSL v2 for more details.
##- @Description: generate cetification
##- @Author: wujing
##- @Create: 2019-04-25
#######################################################################

CURRENT_PATH=$(dirname $(readlink -f "$0"))

function usage() {
    echo -e "\
=================================================================================================\033[1;37m
             _____ ______ ___   ______ ____ ______   ______ __  __ ______ ______ __ __
            / ___//_  __//   | /_  __//  _// ____/  / ____// / / // ____// ____// //_/
            \__ \  / /  / /| |  / /   / / / /      / /    / /_/ // __/  / /    / ,<
           ___/ / / /  / ___ | / /  _/ / / /___   / /___ / __  // /___ / /___ / /| |
          /____/ /_/  /_/  |_|/_/  /___/ \____/   \____//_/ /_//_____/ \____//_/ |_| \033[0m
================================================================================================="
    echo "Usage: $0 [options]"
    echo "Personal level build static check script for iSulad project"
    echo "Options:"
    echo "    -s, --codestyle          Perform codestyle(codedex) code static check"
    echo "    -c, --tidy-check         Perform clang-tidy code static check"
    echo "    -x, --tidy-fix           Quick fix code with clang-tidy"
    echo "    -a, --all                Perform all checks and statistics"
    echo "    -i, --incremental-check  Perform incremental check"
    echo "    -f, --quick-format       Incremental format code by astyle/clang-format"
    echo "    -k, --style-check        Check code style by astyle"
    echo "    --cpp-check              Use Cppcheck check code style"
    echo "    -h, --help               Script help information"
}

function err() {
    echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')]: $@" >&2
}

CODESTYLE_MASKED_RULE=(
    "Start-processing"
    "Done-processing"
    "Total-errors-found"
    "\[build/header_guard\]-\[5\]"
    "\[build/c++11\]-\[5\]"
    "\[whitespace/indent\]-\[3\]"
    "\[whitespace/braces\]-\[4\]"
    "\[readability/condition\]-\[2\]"
    "\[whitespace/braces\]-\[5\]"
    "\[build/c\+\+11\]-\[5\]"
    "\[build/include_order\]-\[4\]"
    "\[readability/multiline_string\]-\[5\]"
    "\[runtime/string\]-\[4\]"
    "\[whitespace/semicolon\]-\[5\]"
    "\[whitespace/comments\]-\[2\]"
    "\[build/c\+\+11\]-\[3\]"
    "\[whitespace/operators\]-\[4\]"
    "\[runtime/threadsafe_fn\]-\[2\]"
    "\[runtime/printf\]-\[4\]"
    "\[whitespace/line_length\]-\[2\]"
    "\[build/include_subdir\]-\[4\]"
)
function codestyle_check() {
    echo -e "\
=================================================================================================\033[1;33m
           ______ ____   ____   ____ _   __ ______ _____ ________  __ __     ______
          / ____// __ \ / __ \ /  _// | / // ____// ___//_  __/\ \/ // /    / ____/
         / /    / / / // / / / / / /  |/ // / __  \__ \  / /    \  // /    / __/
        / /___ / /_/ // /_/ /_/ / / /|  // /_/ / ___/ / / /     / // /___ / /___
        \____/ \____//_____//___//_/ |_/ \____/ /____/ /_/     /_//_____//_____/\033[0m
================================================================================================="

    if [[ $? -ne 0 ]]; then
        echo "please install cpplint tool first -- pip(3) install cpplint"
        exit 1
    fi
    local masked_rule=$(echo ${CODESTYLE_MASKED_RULE[@]} | sed -e "s/ /|/g" -e "s/-/ /g")
    local start_time=$(date +%s)
    local files
    if [[ ${1} == "all" ]]; then
        files=$(find ./src ./test -regextype posix-extended -regex ".*\.(cc|cpp)")
    else
        files=$(git diff --name-only HEAD | grep -E "*.cc$|*.cpp$")
    fi
    files=(${files// / })
    local total=${#files[@]}
    local failure_num=0
    local index=1
    for file in ${files[@]}; do
        cpplint "$file" 2>&1 | grep -vE "${masked_rule}"
        if [[ $? -eq 0 ]]; then
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;31m\033[5m%s\033[0m\n" \
                ${index} "${total}" "${file}" "[FAILED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
            failure_num=$((failure_num + 1))
        else
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
                ${index} "${total}" "${file}" "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        fi
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m, \033[1;32msuccess: $((total - failure_num))\033[0m, \033[1;31mfailure: ${failure_num}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
    if [[ ${failure_num} -ne 0 ]]; then
        exit -1
    fi
}

function clang_format() {
    echo -e "\
=================================================================================================\033[1;36m
         ______ __     ___     _   __ ______        ______ ____   ____   __  ___ ___   ______
        / ____// /    /   |   / | / // ____/       / ____// __ \ / __ \ /  |/  //   | /_  __/
       / /    / /    / /| |  /  |/ // / __ ______ / /_   / / / // /_/ // /|_/ // /| |  / /
      / /___ / /___ / ___ | / /|  // /_/ //_____// __/  / /_/ // _, _// /  / // ___ | / /
      \____//_____//_/  |_|/_/ |_/ \____/       /_/     \____//_/ |_|/_/  /_//_/  |_|/_/ \033[0m]
================================================================================================="
    local start_time=$(date +%s)
    local files=$(git diff --name-only HEAD | grep -E "*.h$|*.c$|*.cc$|*.cpp$")
    files=(${files// / })
    local total=${#files[@]}
    local failure_num=0
    local index=1
    for file in ${files[@]}; do
        clang-format -i "${file}"
        if [[ $? -ne 0 ]]; then
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;31m\033[5m%s\033[0m\n" \
                ${index} "${total}" "${file}" "[FAILED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
            failure_num=$((failure_num + 1))
        else
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
                ${index} "${total}" "${file}" "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        fi
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m, \033[1;32msuccess: $((total - failure_num))\033[0m, \033[1;31mfailure: ${failure_num}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
}

function do_astyle_fix() {
    astyle --options=none --lineend=linux --mode=c \
        --style=kr \
        --add-braces \
        --indent=spaces=4 \
        --indent-preprocessor \
        --indent-col1-comments \
        --indent-switches \
        --indent-cases \
        --min-conditional-indent=0 \
        --max-instatement-indent=120 \
        --max-code-length=120 \
        --break-after-logical \
        --pad-oper \
        --pad-header \
        --unpad-paren \
        --pad-comma \
        --lineend=linux \
        --align-reference=name \
        --close-templates \
        --indent-preproc-define \
        --indent-cases \
        --indent-switches \
        --attach-namespaces \
        --attach-classes \
        --attach-extern-c \
        --attach-closing-while \
        --indent-col1-comments \
        --break-one-line-headers \
        --close-templates < "${1}"
}

function astyle_fix() {
    [[ -z "${1}" || ! -r "${1}" ]] && exit -1
    tmp="$(mktemp --tmpdir=$(dirname "${1}"))"
    do_astyle_fix "${1}" > "${tmp}"
    sed -i 's/\*const/\* const/g' "${tmp}"
    mv "${tmp}" "${1}"
}

function astyle_format() {
    which astyle
    if [[ $? -ne 0 ]]; then
        echo "please install astyle tool first"
        exit 1
    fi
    echo -e "\
=================================================================================================\033[1;36m
        ___    _____ ________  __ __     ______       ______ ____   ____   __  ___ ___   ______
       /   |  / ___//_  __/\ \/ // /    / ____/      / ____// __ \ / __ \ /  |/  //   | /_  __/
      / /| |  \__ \  / /    \  // /    / __/ ______ / /_   / / / // /_/ // /|_/ // /| |  / /
     / ___ | ___/ / / /     / // /___ / /___/_____// __/  / /_/ // _, _// /  / // ___ | / /
    /_/  |_|/____/ /_/     /_//_____//_____/      /_/     \____//_/ |_|/_/  /_//_/  |_|/_/ \033[0m]
================================================================================================="
    local start_time=$(date +%s)
    local files=$(find ./src ./test -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    files=(${files// / })
    local total=${#files[@]}
    local failure_num=0
    local index=1
    for file in ${files[@]}; do
        astyle_fix "${file}"
        if [[ $? -ne 0 ]]; then
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;31m\033[5m%s\033[0m\n" \
                ${index} "${total}" "${file}" "[FAILED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
            failure_num=$((failure_num + 1))
        else
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
                ${index} "${total}" "${file}" "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        fi
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m, \033[1;32msuccess: $((total - failure_num))\033[0m, \033[1;31mfailure: ${failure_num}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
}

function script_fix() {
    shellcheck -s bash -f diff "${1}" 1> format.patch 2> /dev/null
    patch -p1 < format.patch
    rm format.patch

    shfmt -i 4 -ci -w -d -bn -sr "${1}"
}

function script_format() {
    which shellcheck && which shfmt
    if [[ $? -ne 0 ]]; then
        echo "please install shellcheck and shfmt tool first"
        exit 1
    fi
    echo -e "\
=================================================================================================\033[1;36m
       _____  ______ ____   ____ ____  ______      ______ ____   ____   __  ___ ___   ______
      / ___/ / ____// __ \ /  _// __ \/_  __/     / ____// __ \ / __ \ /  |/  //   | /_  __/
      \__ \ / /    / /_/ / / / / /_/ / / /______ / /_   / / / // /_/ // /|_/ // /| |  / /   
     ___/ // /___ / _, _/_/ / / ____/ / //_____// __/  / /_/ // _, _// /  / // ___ | / /    
    /____/ \____//_/ |_|/___//_/     /_/       /_/     \____//_/ |_|/_/  /_//_/  |_|/_/ \033[0m] 
================================================================================================="
    local start_time=$(date +%s)
    local files=$(find . -regextype posix-extended -regex ".*\.(bash|sh)")
    files=(${files// / })
    local total=${#files[@]}
    local failure_num=0
    local index=1
    for file in ${files[@]}; do
        script_fix "${file}"
        if [[ $? -ne 0 ]]; then
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;31m\033[5m%s\033[0m\n" \
                ${index} "${total}" "${file}" "[FAILED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
            failure_num=$((failure_num + 1))
        else
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
                ${index} "${total}" "${file}" "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        fi
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m, \033[1;32msuccess: $((total - failure_num))\033[0m, \033[1;31mfailure: ${failure_num}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
}

function quick_format() {
    if [[ $1 == "clang-format" ]]; then
        clang_format
    else
        astyle_format
    fi
    script_format

}

function do_astyle_check() {
    [[ -z "$1" || ! -r "$1" ]] && return -1

    do_astyle_fix "$1" | diff -pu --label="$1.orig" "$1" --label="$1" -
    if [[ $? -ne 0 ]]; then
        return -1
    fi
}

function style_check() {
    echo -e "\
=================================================================================================
    ███████╗████████╗██╗   ██╗██╗     ███████╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
    ██╔════╝╚══██╔══╝╚██╗ ██╔╝██║     ██╔════╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
    ███████╗   ██║    ╚████╔╝ ██║     █████╗      ██║     ███████║█████╗  ██║     █████╔╝
    ╚════██║   ██║     ╚██╔╝  ██║     ██╔══╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
    ███████║   ██║      ██║   ███████╗███████╗    ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
    ╚══════╝   ╚═╝      ╚═╝   ╚══════╝╚══════╝     ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
================================================================================================="
    local start_time=$(date +%s)
    local files
    if [[ ${1} == "all" ]]; then
        files=$(find ./src ./test -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    else
        files=$(git diff --name-only HEAD | grep -E "*.h$|*.c$|*.cc$|*.cpp$")
    fi
    files=(${files// / })
    local total=${#files[@]}
    local failure_num=0
    local index=1
    for file in ${files[@]}; do
        do_astyle_check "${file}"
        if [[ $? -ne 0 ]]; then
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;31m\033[5m%s\033[0m\n" \
                ${index} "${total}" "${file}" "[FAILED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
            failure_num=$((failure_num + 1))
        else
            printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
                ${index} "${total}" "${file}" "[PASS]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        fi
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m, \033[1;32msuccess: $((total - failure_num))\033[0m, \033[1;31mfailure: ${failure_num}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
    if [[ ${failure_num} -ne 0 ]]; then
        exit -1
    fi
}

CPPCHRECK_RULE=(
    "information"
    "warning"
    "performance"
    "style"
    # "unusedFunction"
    # "all"
)
CPPCHRCK_LOG="${CURRENT_PATH}/cppcheck.log"

function cpp_check() {
    echo -e "\
=================================================================================================\033[1;33m
                   ______ ____   ____     ______ __  __ ______ ______ __ __
                  / ____// __ \ / __ \   / ____// / / // ____// ____// //_/
                 / /    / /_/ // /_/ /  / /    / /_/ // __/  / /    / ,<
                / /___ / ____// ____/  / /___ / __  // /___ / /___ / /| |
                \____//_/    /_/       \____//_/ /_//_____/ \____//_/ |_|\033[0m
================================================================================================="
    echo "cpp check is in progress, please wait a few seconds..."
    printf "%0.s*" {1..97}
    printf "\n"
    local check_rule=$(echo ${CPPCHRECK_RULE[@]} | sed -e "s/ /,/g")
    local start_time=$(date +%s)
    result=$(cppcheck --enable="${check_rule}" -j $(nproc) -i ./build ./ 2>&1 | grep -vE "^Checking|done$|any_of algorithm instead of a raw loop")
    nums=$(echo "${result}" | wc -l)
    echo "${result}"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    if [[ ${nums} -eq 0 ]] || [[ -z ${result} ]]; then
        echo -e "\033[1;32mSuccess: clean code!\033[0m \033[1;33mSpend time: ${duration} seconds\033[0m"
    else
        printf "%0.s*" {1..97}
        printf "\n"
        echo -e "\033[1;31mFailure: There are ${nums} warnings that you need to handle\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
        exit -1
    fi
}

function clang_tidy_check() {
    which clang-tidy > /dev/null
    if [[ $? -ne 0 ]]; then
        echo "please install clang-tidy tool first"
        exit 1
    fi
    echo -e "\
=================================================================================================\033[1;33m
            ████████╗██╗██████╗ ██╗   ██╗     ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
            ╚══██╔══╝██║██╔══██╗╚██╗ ██╔╝    ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
               ██║   ██║██║  ██║ ╚████╔╝     ██║     ███████║█████╗  ██║     █████╔╝ 
               ██║   ██║██║  ██║  ╚██╔╝      ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
               ██║   ██║██████╔╝   ██║       ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
               ╚═╝   ╚═╝╚═════╝    ╚═╝        ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝\033[0m
================================================================================================="
    local start_time=$(date +%s)
    if [[ ! -f ${CURRENT_PATH}/../compile_commands.json ]]; then
        echo "compile_commands.json file not found in project root dirctory, generating..."
        mkdir -p "${CURRENT_PATH}"/../build
        cd "${CURRENT_PATH}"/../build || exit
        cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../
        cp compile_commands.json ../
        cd "${CURRENT_PATH}" || exit
    fi

    local files
    if [[ ${1} == "all" ]]; then
        files=$(find ./src ./test -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    elif [[ ${1} == "incremental" ]]; then
        files=$(git diff --name-only HEAD | grep -E "*.h$|*.c$|*.cc$|*.cpp$")
    elif [[ -f "$1" ]]; then
        files="$1"
    elif [[ -d "$1" ]]; then
        files=$(find "$1" -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    fi
    files=(${files// / })
    local total=${#files[@]}
    local index=1
    logfile=${CURRENT_PATH}/../clang-tidy-check.log
    echo "" > "${logfile}"
    if [[ ${total} -eq 1 ]]; then
        clang-tidy -checks='-*,abseil-*,bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*, \
        	google-*,hicpp-*,linuxkernel-*,llvm-*,llvmlibc-*,-llvm-header-guard,misc-*,modernize-*,performance-*,portability-*,readability-*' "${files[0]}"
        return 0
    fi

    for file in ${files[@]}; do
        echo ">>>>>>>>>>>>>>>>>>checking: ${file}" >> "${logfile}"
        clang-tidy -checks='-*,abseil-*,bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*, \
        	google-*,hicpp-*,linuxkernel-*,llvm-*,llvmlibc-*,-llvm-header-guard,misc-*,modernize-*,performance-*,portability-*,readability-*' "${file}" \
            >> "${logfile}" 2>&1
        echo ">>>>>>>>>>>>>>>>>>checked: ${file}" >> "${logfile}"
        printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
            ${index} "${total}" "${file}" "[CHECKED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
    echo -e "\033[1;31mCode analysis report ${logfile} is in the root directory of the project, please refer to the modification\033[0m"
}

function clang_tidy_fix() {
    which clang-tidy > /dev/null
    if [[ $? -ne 0 ]]; then
        echo "please install clang-tidy tool first"
        exit 1
    fi
    echo -e "\
=================================================================================================\033[1;33m
    ████████╗██╗██████╗ ██╗   ██╗     ██████╗ ██████╗ ██████╗ ███████╗    ███████╗██╗██╗  ██╗
    ╚══██╔══╝██║██╔══██╗╚██╗ ██╔╝    ██╔════╝██╔═══██╗██╔══██╗██╔════╝    ██╔════╝██║╚██╗██╔╝
       ██║   ██║██║  ██║ ╚████╔╝     ██║     ██║   ██║██║  ██║█████╗      █████╗  ██║ ╚███╔╝ 
       ██║   ██║██║  ██║  ╚██╔╝      ██║     ██║   ██║██║  ██║██╔══╝      ██╔══╝  ██║ ██╔██╗ 
       ██║   ██║██████╔╝   ██║       ╚██████╗╚██████╔╝██████╔╝███████╗    ██║     ██║██╔╝ ██╗
       ╚═╝   ╚═╝╚═════╝    ╚═╝        ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝\033[0m
================================================================================================="
    local start_time=$(date +%s)
    if [[ ! -f ${CURRENT_PATH}/../compile_commands.json ]]; then
        echo "compile_commands.json file not found in project root dirctory, generating..."
        mkdir -p "${CURRENT_PATH}"/../build
        cd "${CURRENT_PATH}"/../build || exit
        cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ../
        cp compile_commands.json ../
        cd "${CURRENT_PATH}" || exit
    fi

    local files
    if [[ ${1} == "fixdef" ]]; then
        if [[ ${CURRENT_PATH} != "/iSulad/tools" ]]; then
            echo "Please move project to /"
            exit 1
        fi
        files=$(find ./src ./test -regextype posix-extended -regex ".*\.(h)")
    elif [[ ${1} == "all" ]]; then
        files=$(find ./src ./test -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    elif [[ ${1} == "incremental" ]]; then
        files=$(git diff --name-only HEAD | grep -E "*.h$|*.c$|*.cc$|*.cpp$")
    elif [[ -f "$1" ]]; then
        files="$1"
    elif [[ -d "$1" ]]; then
        files=$(find "$1" -regextype posix-extended -regex ".*\.(h|c|cc|cpp)")
    fi
    files=(${files// / })
    local total=${#files[@]}
    local index=1
    if [[ ${total} -eq 1 ]]; then
        clang-tidy -checks='-*,abseil-*,bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*, \
        	google-*,hicpp-*,linuxkernel-*,llvm-*,llvmlibc-*,-llvm-header-guard,misc-*,modernize-*,performance-*,portability-*,readability-*' --fix "${files[0]}"
        return 0
    fi

    for file in ${files[@]}; do
        if [[ ${1} == "fixdef" ]]; then
            clang-tidy -checks='-*,llvm-header-guard' --fix "${file}" > /dev/null 2>&1
            sed -i 's/_ISULAD_SRC_//g ' "${file}" > /dev/null 2>&1
        else
            clang-tidy -checks='-*,abseil-*,bugprone-*,cert-*,clang-analyzer-*,cppcoreguidelines-*, \
                google-*,hicpp-*,linuxkernel-*,llvm-*,llvmlibc-*,-llvm-header-guard,misc-*,modernize-*,performance-*,portability-*,readability-*' --fix "${file}" > /dev/null 2>&1
        fi
        printf "[\033[1;36m%03d\033[0m\033[1;33m/\033[0m\033[1;34m%03d\033[0m]@%-80s \033[1;32m%-5s\033[0m\n" \
            ${index} "${total}" "${file}" "[REPAIRED]" | sed -e 's/ /-/g' -e 's/@/ /' -e 's/-/ /'
        index=$((index + 1))
    done
    printf "%0.s=" {1..96}
    printf "\n"
    local end_time=$(date +%s)
    local duration=$((${end_time} - ${start_time}))
    echo -e "\033[1;36mTotal files: ${total}\033[0m. \033[1;33mSpend time: ${duration} seconds\033[0m"
    echo -e "\033[1;31mThe code is repaired, please recompile and check\033[0m"
}

function incremental_check() {
    style_check "incremental"
    if [[ $? -ne 0 ]]; then
        exit -1
    fi
    codestyle_check "incremental"
    if [[ $? -ne 0 ]]; then
        exit -1
    fi
    cpp_check
    if [[ $? -ne 0 ]]; then
        return -1
    fi
}

function static_check_all() {
    style_check "all"
    if [[ $? -ne 0 ]]; then
        return -1
    fi
    codestyle_check "all"
    if [[ $? -ne 0 ]]; then
        return -1
    fi
    cpp_check
    if [[ $? -ne 0 ]]; then
        return -1
    fi
}

args=$(getopt -o sc:x:iaf:kh --long codestyle,tidy-check:,tidy-fix:,incremental-check,all,quick-format:,style-check,cpp-check,help -- "$@")
if [ $? != 0 ]; then
    echo "Terminating..." >&2
    exit 1
fi
eval set -- "$args"

while true; do
    case "$1" in
        -s | --codestyle)
            codestyle_check "all" || (err "failed to perfrom codestyle(codedex) code static check" && exit -1)
            shift
            ;;
        -c | --tidy-check)
            clang_tidy_check "$2" || (err "failed to perform clang-tidy code static check" && exit -1)
            shift 2
            ;;
        -x | --tidy-fix)
            clang_tidy_fix "$2" || (err "failed to quick fix code with clang-tidy" && exit -1)
            shift 2
            ;;
        -i | --incremental-check)
            incremental_check || (err "failed to perform incremental check" && exit -1)
            shift
            ;;
        -a | --all)
            static_check_all || (err "failed to perform all checks and statistics" && exit -1)
            shift
            ;;
        -f | --quick-format)
            quick_format "$2" || (err "failed to format code" && exit -1)
            shift 2
            ;;
        -k | --style-check)
            style_check "all" || (err "failed to check code style" && exit -1)
            shift
            ;;
        --cpp-check)
            cpp_check || (err "failed to check code style" && exit -1)
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            err "invalid parameter"
            exit -1
            ;;
    esac
done
