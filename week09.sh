#!/bin/bash
# 이 스크립트는 /pintos/ 디렉토리에서 실행된다고 가정합니다
# cd ~; cd /workspaces/week09/pintos/threads; make clean; make; cd ..; ./week09.sh;

THREADS_DIR="threads"
BUILD_DIR="${THREADS_DIR}/build"

# 실행할 테스트 목록 (원하는 테스트만 추가/삭제하세요)
TESTS_TO_RUN=(
  "tests/threads/alarm-single"
  "tests/threads/alarm-multiple"
  "tests/threads/alarm-negative"
  "tests/threads/alarm-priority"
  "tests/threads/alarm-simultaneous"
  "tests/threads/alarm-zero"

  "tests/threads/priority-change"
  "tests/threads/priority-preempt"
  "tests/threads/priority-fifo"
  "tests/threads/priority-sema"
  "tests/threads/priority-condvar"
  
  "tests/threads/priority-donate-one"
  "tests/threads/priority-donate-multiple"
  "tests/threads/priority-donate-multiple2"
  "tests/threads/priority-donate-nest"
  "tests/threads/priority-donate-sema"
  "tests/threads/priority-donate-lower"
  "tests/threads/priority-donate-chain"

  # "tests/threads/mlfqs/mlfqs-load-1"
  # "tests/threads/mlfqs/mlfqs-load-60"
  # "tests/threads/mlfqs/mlfqs-load-avg"
  # "tests/threads/mlfqs/mlfqs-recent-1"
  # "tests/threads/mlfqs/mlfqs-fair-2"
  # "tests/threads/mlfqs/mlfqs-fair-20"
  # "tests/threads/mlfqs/mlfqs-block"
  # "tests/threads/mlfqs/mlfqs-nice-2"
  # "tests/threads/mlfqs/mlfqs-nice-10"
)

ALL_PASSED=true


check_root_dir() {
  if [ ! -d "${THREADS_DIR}" ]; then
    echo "Error: This script must be run from the 'pintos' root directory."
    echo "Failed to find directory: ${THREADS_DIR}"
    exit 1
  fi
}

enter_build_dir() {
  echo "Moving to ${BUILD_DIR}..."
  if [ ! -d "${BUILD_DIR}" ]; then
    echo "Error: Build directory '${BUILD_DIR}' not found."
    echo "Please run 'make' in '${THREADS_DIR}' first."
    exit 1
  fi

  cd "${BUILD_DIR}" || exit 1
  echo "Now in $(pwd)"
}

run_tests() {
  for TEST_NAME in "${TESTS_TO_RUN[@]}"; do
    echo "👀 테스트를 실행하고 있습니다. ${TEST_NAME}"
    make "${TEST_NAME}.result" &> /dev/null
  done
}

summarize_results() {
  for TEST_NAME in "${TESTS_TO_RUN[@]}"; do
    TEST_FILE="${TEST_NAME}.result"

    if [ -f "${TEST_FILE}" ]; then
      if grep -q "FAIL" "${TEST_FILE}"; then
        ALL_PASSED=false
        echo "❌ 실패: ${TEST_FILE}"
      else
        echo "✅ 통과: ${TEST_FILE}"
      fi
    else
      ALL_PASSED = false
      echo "❗️ 에러: ${TEST_FILE} 파일을 찾을 수 없습니다.)"
    fi
  done

  if ${ALL_PASSED}; then
    echo "모든 테스트가 통과했습니다."
  else
    echo "모든 테스트가 통과하지는 못했습니다."
  fi
}

return_root() {
  cd ../.. || exit 1
  echo "Returning to $(pwd)"
}

main() {
  check_root_dir
  enter_build_dir
  run_tests
  summarize_results
  return_root
}

main "$@"
