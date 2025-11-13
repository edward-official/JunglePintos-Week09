#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

/* MLFQS 스케줄러 계산에 사용될 고정 소수점(Fixed-Point) 연산을 정의합니다.
 * 부동소수점(floating-point)을 커널에서 사용할 수 없으므로, 정수를 사용하여 실수를 표현합니다.
 * 여기서는 17.14 형식을 사용하며, f = 2^14 입니다.
 * 형식: [부호(1비트)][정수부(17비트)][소수부(14비트)]
 */

/* 고정 소수점 표현을 위한 기본 타입 정의 */
typedef int fixed_t;

/* 14비트 소수부를 사용하므로, f = 2^14 */
#define F (1 << 14)

/* 정수를 고정 소수점으로 변환 */
#define INT_TO_FP(n) ((n) * F)

/* 고정 소수점을 정수로 변환 (소수점 이하 버림) */
#define FP_TO_INT_TRUNC(x) ((x) / F)

/* 고정 소수점을 정수로 변환 (가장 가까운 정수로 반올림) */
#define FP_TO_INT_ROUND(x) ((x) >= 0 ? ((x) + F / 2) / F : ((x) - F / 2) / F)

/* 고정 소수점 덧셈 */
#define FP_ADD(x, y) ((x) + (y))

/* 고정 소수점 뺄셈 */
#define FP_SUB(x, y) ((x) - (y))

/* 고정 소수점과 정수 덧셈 */
#define FP_ADD_INT(x, n) ((x) + (n) * F)

/* 고정 소수점과 정수 뺄셈 */
#define FP_SUB_INT(x, n) ((x) - (n) * F)

/* 고정 소수점 곱셈 */
/* 곱셈 시 오버플로우를 방지하기 위해 64비트 정수로 캐스팅 후 연산 */
#define FP_MUL(x, y) (((int64_t)(x)) * (y) / F)

/* 고정 소수점과 정수 곱셈 */
#define FP_MUL_INT(x, n) ((x) * (n))

/* 고정 소수점 나눗셈 */
/* 나눗셈 시 정밀도를 높이기 위해 F를 먼저 곱한 후 연산 */
#define FP_DIV(x, y) (((int64_t)(x)) * F / (y))

/* 고정 소수점과 정수 나눗셈 */
#define FP_DIV_INT(x, n) ((x) / (n))

#endif /* threads/fixed-point.h */
