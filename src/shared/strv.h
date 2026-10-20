/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Copyright 2010 Lennart Poettering
 */

#include <fnmatch.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

#include "shared/util.h"

char *strv_find(char **l, const char *name) _pure_;
char *strv_find_prefix(char **l, const char *name) _pure_;
char *strv_find_startswith(char **l, const char *name) _pure_;

void strv_free(char **l);
DEFINE_TRIVIAL_CLEANUP_FUNC(char **, strv_free);
#define _cleanup_strv_free_ _cleanup_(strv_freep)

char **strv_copy(char *const *l);
unsigned strv_length(char *const *l) _pure_;

int strv_extend_strv(char ***a, char **b);
int strv_extend_strv_concat(char ***a, char **b, const char *suffix);
int strv_extend(char ***l, const char *value);
int strv_extendf(char ***l, const char *format, ...) _printf_(2, 0);
int strv_push(char ***l, char *value);
int strv_push_prepend(char ***l, char *value);
int strv_consume(char ***l, char *value);
int strv_consume_prepend(char ***l, char *value);

char **strv_remove(char **l, const char *s);
char **strv_uniq(char **l);

#define strv_contains(l, s) (!!strv_find((l), (s)))

char **strv_new(const char *x, ...) _sentinel_;
char **strv_new_ap(const char *x, va_list ap);

static inline const char *STRV_IFNOTNULL(const char *x) {
  return x ? x : (const char *)-1;
}

static inline bool strv_isempty(char *const *l) { return !l || !*l; }

char **strv_split(const char *s, const char *separator);
int strv_split_quoted(char ***t, const char *s);
char **strv_split_newlines(const char *s);

char *strv_join(char **l, const char *separator);
char *strv_join_quoted(char **l);

char **strv_parse_nulstr(const char *s, size_t l);
char **strv_split_nulstr(const char *s);

bool strv_overlap(char **a, char **b) _pure_;

#define STRV_FOREACH(s, l) for ((s) = (l); (s) && *(s); (s)++)

#define STRV_FOREACH_BACKWARDS(s, l)                                           \
  STRV_FOREACH(s, l);                                                          \
  for ((s)--; (l) && ((s) >= (l)); (s)--)

#define STRV_FOREACH_PAIR(x, y, l)                                             \
  for ((x) = (l), (y) = (x + 1); (x) && *(x) && *(y); (x) += 2, (y) = (x + 1))

char **strv_sort(char **l);
void strv_print(char **l);

/* The compound literal must stay in the caller's block. A helper that
 * returns a pointer to it is a dangling pointer after the call. The cast is
 * split so cpplint does not treat it as a C-style cast, and clang-format is
 * kept from joining the lines. */
/* clang-format off */
#define STRV_MAKE(...) ((char\
**)((const char *[]){__VA_ARGS__, NULL}))
/* clang-format on */

#define STRV_MAKE_EMPTY ((char *[1]){NULL})

#define strv_from_stdarg_alloca(first)                                         \
  ({                                                                           \
    char **_l;                                                                 \
                                                                               \
    if (!first) {                                                              \
      void *_addr = &first;                                                    \
      memcpy(&_l, &_addr, sizeof(_l));                                         \
    } else {                                                                   \
      unsigned _n;                                                             \
      va_list _ap;                                                             \
                                                                               \
      _n = 1;                                                                  \
      va_start(_ap, first);                                                    \
      while (va_arg(_ap, char *))                                              \
        _n++;                                                                  \
      va_end(_ap);                                                             \
                                                                               \
      _l = newa(char *, _n + 1);                                               \
      memcpy(&_l[0], &first, sizeof(_l[0]));                                   \
      _n = 0;                                                                  \
      va_start(_ap, first);                                                    \
      for (;;) {                                                               \
        _l[++_n] = va_arg(_ap, char *);                                        \
        if (!_l[_n])                                                           \
          break;                                                               \
      }                                                                        \
      va_end(_ap);                                                             \
    }                                                                          \
    _l;                                                                        \
  })

#define STR_IN_SET(x, ...) strv_contains(STRV_MAKE(__VA_ARGS__), x)

#define FOREACH_STRING(x, ...)                                                 \
  for (char **_l = ({                                                          \
         char **_ll = STRV_MAKE(__VA_ARGS__);                                  \
         x = _ll ? _ll[0] : NULL;                                              \
         _ll;                                                                  \
       });                                                                     \
       _l && *_l; x = ({                                                       \
                    _l++;                                                      \
                    _l[0];                                                     \
                  }))

bool strv_fnmatch(char *const *patterns, const char *s, int flags);
