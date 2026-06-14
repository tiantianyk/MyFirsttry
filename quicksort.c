/*
 * quicksort.c — 经典快速排序，C 语言实现
 *
 * 用法: quicksort [n1 n2 n3 ...]
 *       若不传参数则跑内置测试用例
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- 交换 ---------- */
static void swap(int *a, int *b)
{
    int t = *a;
    *a = *b;
    *b = t;
}

/* ---------- 分区：返回基准最终位置 ---------- */
static int partition(int a[], int lo, int hi)
{
    int pivot = a[hi];          /* 选最右为基准 */
    int i = lo - 1;             /* 小于基准的右边界 */

    for (int j = lo; j < hi; j++) {
        if (a[j] <= pivot) {
            i++;
            swap(&a[i], &a[j]);
        }
    }
    swap(&a[i + 1], &a[hi]);    /* 把基准放到正确位置 */
    return i + 1;
}

/* ---------- 递归快排 ---------- */
static void qsort_int(int a[], int lo, int hi)
{
    if (lo >= hi)
        return;
    int p = partition(a, lo, hi);
    qsort_int(a, lo, p - 1);
    qsort_int(a, p + 1, hi);
}

/* ---------- 对外接口 ---------- */
void quick_sort(int a[], int n)
{
    if (a == NULL || n < 2)
        return;
    qsort_int(a, 0, n - 1);
}

/* ---------- 打印数组 ---------- */
static void print_arr(const int a[], int n)
{
    for (int i = 0; i < n; i++)
        printf("%d%c", a[i], i + 1 < n ? ' ' : '\n');
}

/* ---------- 验证：是否升序 ---------- */
static int is_sorted(const int a[], int n)
{
    for (int i = 1; i < n; i++)
        if (a[i - 1] > a[i])
            return 0;
    return 1;
}

/* ---------- 内置测试 ---------- */
static void run_tests(void)
{
    int test0[] = {};
    int test1[] = {42};
    int test2[] = {5, 1};
    int test3[] = {3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5};
    int test4[] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
    int test5[] = {1, 2, 3, 4, 5};

    struct { int *a; int n; } cases[] = {
        {test0, 0}, {test1, 1}, {test2, 2},
        {test3, 11}, {test4, 10}, {test5, 5},
    };
    int n_cases = sizeof cases / sizeof cases[0];

    for (int i = 0; i < n_cases; i++) {
        printf("Case %d: ", i);
        print_arr(cases[i].a, cases[i].n);
        quick_sort(cases[i].a, cases[i].n);
        printf("  ->   ");
        print_arr(cases[i].a, cases[i].n);
        printf("  %s\n\n", is_sorted(cases[i].a, cases[i].n) ? "PASS" : "FAIL");
    }
}

/* ---------- main ---------- */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        run_tests();
        return 0;
    }

    int n = argc - 1;
    int *a = malloc(sizeof(int) * n);
    if (!a) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    for (int i = 0; i < n; i++) {
        char *end;
        long v = strtol(argv[i + 1], &end, 10);
        if (*end != '\0') {
            fprintf(stderr, "invalid number: %s\n", argv[i + 1]);
            free(a);
            return 1;
        }
        a[i] = (int)v;
    }

    printf("Before: ");
    print_arr(a, n);

    quick_sort(a, n);

    printf("After:  ");
    print_arr(a, n);
    printf("%s\n", is_sorted(a, n) ? "PASS" : "FAIL");

    free(a);
    return 0;
}
