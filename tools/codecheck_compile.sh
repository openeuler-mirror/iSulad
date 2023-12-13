## 华为云codeArts执行版本检查时，规则集涉及到代码安全增强包需要编译脚本才能执行
BASEPATH=$( cd -- "$( dirname -- "${BASH_SOURCE[0]:-$0}" )" &> /dev/null && pwd )
ROOTDIR="$BASEPATH"
PROGRAM=$(basename "${BASH_SOURCE[0]:-$0}")
whoami
ls
cd docs/build_docs/guide/script
chmod +x ./install_iSulad_on_Ubuntu_20_04_LTS.sh
./install_iSulad_on_Ubuntu_20_04_LTS.sh