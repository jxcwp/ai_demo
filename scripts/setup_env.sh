#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN=${PYTHON_BIN:-python}
VENV_DIR=${VENV_DIR:-.venv}
PIP_INDEX_URL=${PIP_INDEX_URL:-}

$PYTHON_BIN -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip

if [[ -n "$PIP_INDEX_URL" ]]; then
  echo "[INFO] 使用镜像源安装: $PIP_INDEX_URL"
  pip install -i "$PIP_INDEX_URL" -r requirements.txt
else
  echo "[INFO] 使用默认源安装依赖"
  pip install -r requirements.txt
fi

echo "[INFO] 环境准备完成"
