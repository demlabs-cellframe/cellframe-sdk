/* Copyright (C) 1991-2020 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include "dap_fnmatch.h"

struct STRUCT
{
  const char *pattern;
  const char *string;
  int no_leading_period;
};

#define L_func(CS)  CS
/* Global variable.  */
static int posixly_correct;
#  define CHAR_CLASS_MAX_LENGTH  6 /* Namely, `xdigit'.  */

/* Match STRING against the filename pattern PATTERN, returning zero if
   it matches, nonzero if not.  */
static int FCT (const char *pattern, const char *string,
        const char *string_end, int no_leading_period, int flags,
        struct STRUCT *ends, size_t alloca_used);
static int EXT (int opt, const char *pattern, const char *string,
        const char *string_end, int no_leading_period, int flags,
        size_t alloca_used);
static const char *END (const char *patternp);

static int
FCT (const char *pattern, const char *string, const char *string_end,
     int no_leading_period, int flags, struct STRUCT *ends, size_t alloca_used)
{
  const char *p = pattern, *n = string;
  unsigned char c;
#ifdef _LIBC
# if WIDE_CHAR_VERSION
  const char *collseq = (const char *)
    _NL_CURRENT(LC_COLLATE, _NL_COLLATE_COLLSEQWC);
# else
  const unsigned char *collseq = (const unsigned char *)
    _NL_CURRENT(LC_COLLATE, _NL_COLLATE_COLLSEQMB);
# endif
#endif

  while ((c = *p++) != '\0')
    {
      int new_no_leading_period = 0;
      c = FOLD (c);

      switch (c)
    {
    case '?':
      if (__builtin_expect (flags & FNM_EXTMATCH, 0) && *p == '(')
        {
          int res = EXT (c, p, n, string_end, no_leading_period,
                 flags, alloca_used);
          if (res != -1)
        return res;
        }

      if (n == string_end)
        return FNM_NOMATCH;
      else if (*n == '/' && (flags & FNM_FILE_NAME))
        return FNM_NOMATCH;
      else if (*n == '.' && no_leading_period)
        return FNM_NOMATCH;
      break;

    case '\\':
      if (!(flags & FNM_NOESCAPE))
        {
          c = *p++;
          if (c == '\0')
        /* Trailing \ loses.  */
        return FNM_NOMATCH;
          c = FOLD (c);
        }
      if (n == string_end || FOLD ((unsigned char) *n) != c)
        return FNM_NOMATCH;
      break;

    case '*':
      if (__builtin_expect (flags & FNM_EXTMATCH, 0) && *p == '(')
        {
          int res = EXT (c, p, n, string_end, no_leading_period,
                 flags, alloca_used);
          if (res != -1)
        return res;
        }
      else if (ends != NULL)
        {
          ends->pattern = p - 1;
          ends->string = n;
          ends->no_leading_period = no_leading_period;
          return 0;
        }

      if (n != string_end && *n == '.' && no_leading_period)
        return FNM_NOMATCH;

      for (c = *p++; c == '?' || c == '*'; c = *p++)
        {
          if (*p == '(' && (flags & FNM_EXTMATCH) != 0)
        {
          const char *endp = END (p);
          if (endp != p)
            {
              /* This is a pattern.  Skip over it.  */
              p = endp;
              continue;
            }
        }

          if (c == '?')
        {
          /* A ? needs to match one character.  */
          if (n == string_end)
            /* There isn't another character; no match.  */
            return FNM_NOMATCH;
          else if (*n == '/'
               && __builtin_expect (flags & FNM_FILE_NAME, 0))
            /* A slash does not match a wildcard under
               FNM_FILE_NAME.  */
            return FNM_NOMATCH;
          else
            /* One character of the string is consumed in matching
               this ? wildcard, so *??? won't match if there are
               less than three characters.  */
            ++n;
        }
        }

      if (c == '\0')
        /* The wildcard(s) is/are the last element of the pattern.
           If the name is a file name and contains another slash
           this means it cannot match, unless the FNM_LEADING_DIR
           flag is set.  */
        {
          int result = (flags & FNM_FILE_NAME) == 0 ? 0 : FNM_NOMATCH;

          if (flags & FNM_FILE_NAME)
        {
          if (flags & FNM_LEADING_DIR)
            result = 0;
          else
            {
              if (MEMCHR (n, '/', string_end - n) == NULL)
            result = 0;
            }
        }

          return result;
        }
      else
        {
          const char *endp;
          struct STRUCT end;

          end.pattern = NULL;
          endp = MEMCHR (n, (flags & FNM_FILE_NAME) ? '/' : '\0',
                 string_end - n);
          if (endp == NULL)
        endp = string_end;

          if (c == '['
          || (__builtin_expect (flags & FNM_EXTMATCH, 0) != 0
              && (c == '@' || c == '+' || c == '!')
              && *p == '('))
        {
          int flags2 = ((flags & FNM_FILE_NAME)
                ? flags : (flags & ~FNM_PERIOD));

          for (--p; n < endp; ++n, no_leading_period = 0)
            if (FCT (p, n, string_end, no_leading_period, flags2,
                 &end, alloca_used) == 0)
              goto found;
        }
          else if (c == '/' && (flags & FNM_FILE_NAME))
        {
          while (n < string_end && *n != '/')
            ++n;
          if (n < string_end && *n == '/'
              && (FCT (p, n + 1, string_end, flags & FNM_PERIOD, flags,
                   NULL, alloca_used) == 0))
            return 0;
        }
          else
        {
          int flags2 = ((flags & FNM_FILE_NAME)
                ? flags : (flags & ~FNM_PERIOD));

          if (c == '\\' && !(flags & FNM_NOESCAPE))
            c = *p;
          c = FOLD (c);
          for (--p; n < endp; ++n, no_leading_period = 0)
            if (FOLD ((unsigned char) *n) == c
            && (FCT (p, n, string_end, no_leading_period, flags2,
                 &end, alloca_used) == 0))
              {
              found:
            if (end.pattern == NULL)
              return 0;
            break;
              }
          if (end.pattern != NULL)
            {
              p = end.pattern;
              n = end.string;
              no_leading_period = end.no_leading_period;
              continue;
            }
        }
        }

      /* If we come here no match is possible with the wildcard.  */
      return FNM_NOMATCH;

    case '[':
      {
        /* Nonzero if the sense of the character class is inverted.  */
        const char *p_init = p;
        const char *n_init = n;
        int not;
        char cold;
        unsigned char fn;

        if (posixly_correct == 0)
          posixly_correct = getenv ("POSIXLY_CORRECT") != NULL ? 1 : -1;

        if (n == string_end)
          return FNM_NOMATCH;

        if (*n == '.' && no_leading_period)
          return FNM_NOMATCH;

        if (*n == L_func('/') && (flags & FNM_FILE_NAME))
          /* `/' cannot be matched.  */
          return FNM_NOMATCH;

        not = (*p == '!' || (posixly_correct < 0 && *p == '^'));
        if (not)
          ++p;

        fn = FOLD ((unsigned char) *n);

        c = *p++;
        for (;;)
          {
        if (!(flags & FNM_NOESCAPE) && c == L_func('\\'))
          {
            if (*p == L_func('\0'))
              return FNM_NOMATCH;
            c = FOLD ((unsigned char) *p);
            ++p;

            goto normal_bracket;
          }
        else if (c == L_func('[') && *p == L_func(':'))
          {
            /* Leave room for the null.  */
            char str[CHAR_CLASS_MAX_LENGTH + 1];
            size_t c1 = 0;
#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
            wctype_t wt;
#endif
            const char *startp = p;

            for (;;)
              {
            if (c1 == CHAR_CLASS_MAX_LENGTH)
              /* The name is too long and therefore the pattern
                 is ill-formed.  */
              return FNM_NOMATCH;

            c = *++p;
            if (c == L_func(':') && p[1] == L_func(']'))
              {
                p += 2;
                break;
              }
            if (c < L_func('a') || c >= L_func('z'))
              {
                /* This cannot possibly be a character class name.
                   Match it as a normal range.  */
                p = startp;
                c = L_func('[');
                goto normal_bracket;
              }
            str[c1++] = c;
              }
            str[c1] = L_func('\0');

#if defined _LIBC || (defined HAVE_WCTYPE_H && defined HAVE_WCHAR_H)
            wt = IS_CHAR_CLASS (str);
            if (wt == 0)
              /* Invalid character class name.  */
              return FNM_NOMATCH;

# if defined _LIBC && ! WIDE_CHAR_VERSION
            /* The following code is glibc specific but does
               there a good job in speeding up the code since
               we can avoid the btowc() call.  */
            if (_ISCTYPE ((unsigned char) *n, wt))
              goto matched;
# else
            if (ISWCTYPE (BTOWC ((unsigned char) *n), wt))
              goto matched;
# endif
#else
            if ((STREQ (str, L_func("alnum")) && ISALNUM ((unsigned char) *n))
            || (STREQ (str, L_func("alpha")) && ISALPHA ((unsigned char) *n))
            || (STREQ (str, L_func("blank")) && ISBLANK ((unsigned char) *n))
            || (STREQ (str, L_func("cntrl")) && ISCNTRL ((unsigned char) *n))
            || (STREQ (str, L_func("digit")) && ISDIGIT ((unsigned char) *n))
            || (STREQ (str, L_func("graph")) && ISGRAPH ((unsigned char) *n))
            || (STREQ (str, L_func("lower")) && ISLOWER ((unsigned char) *n))
            || (STREQ (str, L_func("print")) && ISPRINT ((unsigned char) *n))
            || (STREQ (str, L_func("punct")) && ISPUNCT ((unsigned char) *n))
            || (STREQ (str, L_func("space")) && ISSPACE ((unsigned char) *n))
            || (STREQ (str, L_func("upper")) && ISUPPER ((unsigned char) *n))
            || (STREQ (str, L_func("xdigit")) && ISXDIGIT ((unsigned char) *n)))
              goto matched;
#endif
            c = *p++;
          }
#ifdef _LIBC
        else if (c == L_func('[') && *p == L_func('='))
          {
            /* It's important that STR be a scalar variable rather
               than a one-element array, because GCC (at least 4.9.2
               -O2 on x86-64) can be confused by the array and
               diagnose a "used initialized" in a dead branch in the
               findidx function.  */
            unsigned char str;
            uint32_t nrules =
              _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
            const char *startp = p;

            c = *++p;
            if (c == L_func('\0'))
              {
            p = startp;
            c = L_func('[');
            goto normal_bracket;
              }
            str = c;

            c = *++p;
            if (c != L_func('=') || p[1] != L_func(']'))
              {
            p = startp;
            c = L_func('[');
            goto normal_bracket;
              }
            p += 2;

            if (nrules == 0)
              {
            if ((unsigned char) *n == str)
              goto matched;
              }
            else
              {
            const int32_t *table;
# if WIDE_CHAR_VERSION
            const int32_t *weights;
            const wint_t *extra;
# else
            const unsigned char *weights;
            const unsigned char *extra;
# endif
            const int32_t *indirect;
            int32_t idx;
            const unsigned char *cp = (const unsigned char *) &str;

# if WIDE_CHAR_VERSION
            table = (const int32_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEWC);
            weights = (const int32_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_WEIGHTWC);
            extra = (const wint_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_EXTRAWC);
            indirect = (const int32_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_INDIRECTWC);
# else
            table = (const int32_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_TABLEMB);
            weights = (const unsigned char *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_WEIGHTMB);
            extra = (const unsigned char *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_EXTRAMB);
            indirect = (const int32_t *)
              _NL_CURRENT (LC_COLLATE, _NL_COLLATE_INDIRECTMB);
# endif

            idx = FINDIDX (table, indirect, extra, &cp, 1);
            if (idx != 0)
              {
                /* We found a table entry.  Now see whether the
                   character we are currently at has the same
                   equivalance class value.  */
                int len = weights[idx & 0xffffff];
                int32_t idx2;
                const unsigned char *np = (const unsigned char *) n;

                idx2 = FINDIDX (table, indirect, extra,
                        &np, string_end - n);
                if (idx2 != 0
                && (idx >> 24) == (idx2 >> 24)
                && len == weights[idx2 & 0xffffff])
                  {
                int cnt = 0;

                idx &= 0xffffff;
                idx2 &= 0xffffff;

                while (cnt < len
                       && (weights[idx + 1 + cnt]
                       == weights[idx2 + 1 + cnt]))
                  ++cnt;

                if (cnt == len)
                  goto matched;
                  }
              }
              }

            c = *p++;
          }
#endif
        else if (c == L_func('\0'))
          {
            /* [ unterminated, treat as normal character.  */
            p = p_init;
            n = n_init;
            c = L_func('[');
            goto normal_match;
          }
        else
          {
            int is_range = 0;

#ifdef _LIBC
            int is_seqval = 0;

            if (c == L_func('[') && *p == L_func('.'))
              {
            uint32_t nrules =
              _NL_CURRENT_WORD (LC_COLLATE, _NL_COLLATE_NRULES);
            const char *startp = p;
            size_t c1 = 0;

            while (1)
              {
                c = *++p;
                if (c == L_func('.') && p[1] == L_func(']'))
                  {
                p += 2;
                break;
                  }
                if (c == '\0')
                  return FNM_NOMATCH;
                ++c1;
              }

            /* We have to handling the symbols differently in
               ranges since then the collation sequence is
               important.  */
            is_range = *p == L_func('-') && p[1] != L_func('\0');

            if (nrules == 0)
              {
                /* There are no names defined in the collation
                   data.  Therefore we only accept the trivial
                   names consisting of the character itself.  */
                if (c1 != 1)
                  return FNM_NOMATCH;

                if (!is_range && *n == startp[1])
                  goto matched;

                cold = startp[1];
                c = *p++;
              }
            else
              {
                int32_t table_size;
                const int32_t *symb_table;
                const unsigned char *extra;
                int32_t idx;
                int32_t elem;
# if WIDE_CHAR_VERSION
                char *wextra;
# endif

                table_size =
                  _NL_CURRENT_WORD (LC_COLLATE,
                        _NL_COLLATE_SYMB_HASH_SIZEMB);
                symb_table = (const int32_t *)
                  _NL_CURRENT (LC_COLLATE,
                       _NL_COLLATE_SYMB_TABLEMB);
                extra = (const unsigned char *)
                  _NL_CURRENT (LC_COLLATE,
                       _NL_COLLATE_SYMB_EXTRAMB);

                for (elem = 0; elem < table_size; elem++)
                  if (symb_table[2 * elem] != 0)
                {
                  idx = symb_table[2 * elem + 1];
                  /* Skip the name of collating element.  */
                  idx += 1 + extra[idx];
# if WIDE_CHAR_VERSION
                  /* Skip the byte sequence of the
                     collating element.  */
                  idx += 1 + extra[idx];
                  /* Adjust for the alignment.  */
                  idx = (idx + 3) & ~3;

                  wextra = (char *) &extra[idx + 4];

                  if (/* Compare the length of the sequence.  */
                      c1 == wextra[0]
                      /* Compare the wide char sequence.  */
                      && WMEMCMP (startp + 1, &wextra[1],
                          c1) == 0)
                    /* Yep, this is the entry.  */
                    break;
# else
                  if (/* Compare the length of the sequence.  */
                      c1 == extra[idx]
                      /* Compare the byte sequence.  */
                      && memcmp (startp + 1,
                         &extra[idx + 1], c1) == 0)
                    /* Yep, this is the entry.  */
                    break;
# endif
                }

                if (elem < table_size)
                  {
                /* Compare the byte sequence but only if
                   this is not part of a range.  */
                if (! is_range

# if WIDE_CHAR_VERSION
                    && WMEMCMP (n, &wextra[1], c1) == 0
# else
                    && memcmp (n, &extra[idx + 1], c1) == 0
# endif
                    )
                  {
                    n += c1 - 1;
                    goto matched;
                  }

                /* Get the collation sequence value.  */
                is_seqval = 1;
# if WIDE_CHAR_VERSION
                cold = wextra[1 + wextra[idx]];
# else
                idx += 1 + extra[idx];
                /* Adjust for the alignment.  */
                idx = (idx + 3) & ~3;
                cold = *((int32_t *) &extra[idx]);
# endif

                c = *p++;
                  }
                else if (c1 == 1)
                  {
                /* No valid character.  Match it as a
                   single byte.  */
                if (!is_range && *n == startp[1])
                  goto matched;

                cold = startp[1];
                c = *p++;
                  }
                else
                  return FNM_NOMATCH;
              }
              }
            else
#endif
              {
            c = FOLD (c);
              normal_bracket:

            /* We have to handling the symbols differently in
               ranges since then the collation sequence is
               important.  */
            is_range = (*p == L_func('-') && p[1] != L_func('\0')
                    && p[1] != L_func(']'));

            if (!is_range && c == fn)
              goto matched;

            /* This is needed if we goto normal_bracket; from
               outside of is_seqval's scope.  */
            //is_seqval = 0;
            cold = c;
            c = *p++;
              }

            if (c == L_func('-') && *p != L_func(']'))
              {
#if _LIBC
            /* We have to find the collation sequence
               value for C.  Collation sequence is nothing
               we can regularly access.  The sequence
               value is defined by the order in which the
               definitions of the collation values for the
               various characters appear in the source
               file.  A strange concept, nowhere
               documented.  */
            uint32_t fcollseq;
            uint32_t lcollseq;
            unsigned char cend = *p++;

# if WIDE_CHAR_VERSION
            /* Search in the `names' array for the characters.  */
            fcollseq = __collseq_table_lookup (collseq, fn);
            if (fcollseq == ~((uint32_t) 0))
              /* XXX We don't know anything about the character
                 we are supposed to match.  This means we are
                 failing.  */
              goto range_not_matched;

            if (is_seqval)
              lcollseq = cold;
            else
              lcollseq = __collseq_table_lookup (collseq, cold);
# else
            fcollseq = collseq[fn];
            lcollseq = is_seqval ? cold : collseq[(unsigned char) cold];
# endif

            is_seqval = 0;
            if (cend == L_func('[') && *p == L_func('.'))
              {
                uint32_t nrules =
                  _NL_CURRENT_WORD (LC_COLLATE,
                        _NL_COLLATE_NRULES);
                const char *startp = p;
                size_t c1 = 0;

                while (1)
                  {
                c = *++p;
                if (c == L_func('.') && p[1] == L_func(']'))
                  {
                    p += 2;
                    break;
                  }
                if (c == '\0')
                  return FNM_NOMATCH;
                ++c1;
                  }

                if (nrules == 0)
                  {
                /* There are no names defined in the
                   collation data.  Therefore we only
                   accept the trivial names consisting
                   of the character itself.  */
                if (c1 != 1)
                  return FNM_NOMATCH;

                cend = startp[1];
                  }
                else
                  {
                int32_t table_size;
                const int32_t *symb_table;
                const unsigned char *extra;
                int32_t idx;
                int32_t elem;
# if WIDE_CHAR_VERSION
                char *wextra;
# endif

                table_size =
                  _NL_CURRENT_WORD (LC_COLLATE,
                            _NL_COLLATE_SYMB_HASH_SIZEMB);
                symb_table = (const int32_t *)
                  _NL_CURRENT (LC_COLLATE,
                           _NL_COLLATE_SYMB_TABLEMB);
                extra = (const unsigned char *)
                  _NL_CURRENT (LC_COLLATE,
                           _NL_COLLATE_SYMB_EXTRAMB);

                for (elem = 0; elem < table_size; elem++)
                  if (symb_table[2 * elem] != 0)
                    {
                      idx = symb_table[2 * elem + 1];
                      /* Skip the name of collating
                     element.  */
                      idx += 1 + extra[idx];
# if WIDE_CHAR_VERSION
                      /* Skip the byte sequence of the
                     collating element.  */
                      idx += 1 + extra[idx];
                      /* Adjust for the alignment.  */
                      idx = (idx + 3) & ~3;

                      wextra = (char *) &extra[idx + 4];

                      if (/* Compare the length of the
                         sequence.  */
                      c1 == wextra[0]
                      /* Compare the wide char sequence.  */
                      && WMEMCMP (startp + 1, &wextra[1],
                              c1) == 0)
                    /* Yep, this is the entry.  */
                    break;
# else
                      if (/* Compare the length of the
                         sequence.  */
                      c1 == extra[idx]
                      /* Compare the byte sequence.  */
                      && memcmp (startp + 1,
                             &extra[idx + 1], c1) == 0)
                    /* Yep, this is the entry.  */
                    break;
# endif
                    }

                if (elem < table_size)
                  {
                    /* Get the collation sequence value.  */
                    is_seqval = 1;
# if WIDE_CHAR_VERSION
                    cend = wextra[1 + wextra[idx]];
# else
                    idx += 1 + extra[idx];
                    /* Adjust for the alignment.  */
                    idx = (idx + 3) & ~3;
                    cend = *((int32_t *) &extra[idx]);
# endif
                  }
                else if (c1 == 1)
                  {
                    cend = startp[1];
                    c = *p++;
                  }
                else
                  return FNM_NOMATCH;
                  }
              }
            else
              {
                if (!(flags & FNM_NOESCAPE) && cend == L_func('\\'))
                  cend = *p++;
                if (cend == L_func('\0'))
                  return FNM_NOMATCH;
                cend = FOLD (cend);
              }

            /* XXX It is not entirely clear to me how to handle
               characters which are not mentioned in the
               collation specification.  */
            if (
# if WIDE_CHAR_VERSION
                lcollseq == 0xffffffff ||
# endif
                lcollseq <= fcollseq)
              {
                /* We have to look at the upper bound.  */
                uint32_t hcollseq;

                if (is_seqval)
                  hcollseq = cend;
                else
                  {
# if WIDE_CHAR_VERSION
                hcollseq =
                  __collseq_table_lookup (collseq, cend);
                if (hcollseq == ~((uint32_t) 0))
                  {
                    /* Hum, no information about the upper
                       bound.  The matching succeeds if the
                       lower bound is matched exactly.  */
                    if (lcollseq != fcollseq)
                      goto range_not_matched;

                    goto matched;
                  }
# else
                hcollseq = collseq[cend];
# endif
                  }

                if (lcollseq <= hcollseq && fcollseq <= hcollseq)
                  goto matched;
              }
# if WIDE_CHAR_VERSION
              range_not_matched:
# endif
#else
            /* We use a boring value comparison of the character
               values.  This is better than comparing using
               `strcoll' since the latter would have surprising
               and sometimes fatal consequences.  */
            unsigned char cend = *p++;

            if (!(flags & FNM_NOESCAPE) && cend == L_func('\\'))
              cend = *p++;
            if (cend == L_func('\0'))
              return FNM_NOMATCH;

            /* It is a range.  */
            if (cold <= fn && fn <= cend)
              goto matched;
#endif

            c = *p++;
              }
          }

        if (c == L_func(']'))
          break;
          }

        if (!not)
          return FNM_NOMATCH;
        break;

      matched:
        /* Skip the rest of the [...] that already matched.  */
        while ((c = *p++) != L_func (']'))
          {
        if (c == L_func('\0'))
          /* [... (unterminated) loses.  */
          return FNM_NOMATCH;

        if (!(flags & FNM_NOESCAPE) && c == L_func('\\'))
          {
            if (*p == L_func('\0'))
              return FNM_NOMATCH;
            /* XXX 1003.2d11 is unclear if this is right.  */
            ++p;
          }
        else if (c == L_func('[') && *p == L_func(':'))
          {
            int c1 = 0;
            const char *startp = p;

            while (1)
              {
            c = *++p;
            if (++c1 == CHAR_CLASS_MAX_LENGTH)
              return FNM_NOMATCH;

            if (*p == L_func(':') && p[1] == L_func(']'))
              break;

            if (c < L_func('a') || c >= L_func('z'))
              {
                p = startp - 2;
                break;
              }
              }
            p += 2;
          }
        else if (c == L_func('[') && *p == L_func('='))
          {
            c = *++p;
            if (c == L_func('\0'))
              return FNM_NOMATCH;
            c = *++p;
            if (c != L_func('=') || p[1] != L_func(']'))
              return FNM_NOMATCH;
            p += 2;
          }
        else if (c == L_func('[') && *p == L_func('.'))
          {
            while (1)
              {
            c = *++p;
            if (c == L_func('\0'))
              return FNM_NOMATCH;

            if (c == L_func('.') && p[1] == L_func(']'))
              break;
              }
            p += 2;
          }
          }
        if (not)
          return FNM_NOMATCH;
      }
      break;

    case L_func('+'):
    case L_func('@'):
    case L_func('!'):
      if (__builtin_expect (flags & FNM_EXTMATCH, 0) && *p == '(')
        {
          int res = EXT (c, p, n, string_end, no_leading_period, flags,
                 alloca_used);
          if (res != -1)
        return res;
        }
      goto normal_match;

    case L_func('/'):
      if (NO_LEADING_PERIOD (flags))
        {
          if (n == string_end || c != (unsigned char) *n)
        return FNM_NOMATCH;

          new_no_leading_period = 1;
          break;
        }
      /* FALLTHROUGH */
    default:
    normal_match:
      if (n == string_end || c != FOLD ((unsigned char) *n))
        return FNM_NOMATCH;
    }

      no_leading_period = new_no_leading_period;
      ++n;
    }

  if (n == string_end)
    return 0;

  if ((flags & FNM_LEADING_DIR) && n != string_end && *n == L_func('/'))
    /* The FNM_LEADING_DIR flag says that "foo*" matches "foobar/frobozz".  */
    return 0;

  return FNM_NOMATCH;
}


const char *
END (const char *pattern)
{
  const char *p = pattern;

  while (1)
    if (*++p == L_func('\0'))
      /* This is an invalid pattern.  */
      return pattern;
    else if (*p == L_func('['))
      {
    /* Handle brackets special.  */
    if (posixly_correct == 0)
      posixly_correct = getenv ("POSIXLY_CORRECT") != NULL ? 1 : -1;

    /* Skip the not sign.  We have to recognize it because of a possibly
       following ']'.  */
    if (*++p == L_func('!') || (posixly_correct < 0 && *p == L_func('^')))
      ++p;
    /* A leading ']' is recognized as such.  */
    if (*p == L_func(']'))
      ++p;
    /* Skip over all characters of the list.  */
    while (*p != L_func(']'))
      if (*p++ == L_func('\0'))
        /* This is no valid pattern.  */
        return pattern;
      }
    else if ((*p == L_func('?') || *p == L_func('*') || *p == L_func('+') || *p == L_func('@')
          || *p == L_func('!')) && p[1] == L_func('('))
      {
    p = END (p + 1);
    if (*p == L_func('\0'))
      /* This is an invalid pattern.  */
      return pattern;
      }
    else if (*p == L_func(')'))
      break;

  return p + 1;
}


static int
EXT (int opt, const char *pattern, const char *string, const char *string_end,
     int no_leading_period, int flags, size_t alloca_used)
{
  const char *startp;
  int level;
  struct patternlist
  {
    struct patternlist *next;
    char malloced;
    char str[0];
  } *list = NULL;
  struct patternlist **lastp = &list;
  size_t pattern_len = STRLEN (pattern);
  int any_malloced = 0;
  const char *p;
  const char *rs;
  int retval = 0;

  /* Parse the pattern.  Store the individual parts in the list.  */
  level = 0;
  for (startp = p = pattern + 1; level >= 0; ++p)
    if (*p == L_func('\0'))
      {
    /* This is an invalid pattern.  */
    retval = -1;
    goto out;
      }
    else if (*p == L_func('['))
      {
    /* Handle brackets special.  */
    if (posixly_correct == 0)
      posixly_correct = getenv ("POSIXLY_CORRECT") != NULL ? 1 : -1;

    /* Skip the not sign.  We have to recognize it because of a possibly
       following ']'.  */
    if (*++p == L_func('!') || (posixly_correct < 0 && *p == L_func('^')))
      ++p;
    /* A leading ']' is recognized as such.  */
    if (*p == L_func(']'))
      ++p;
    /* Skip over all characters of the list.  */
    while (*p != L_func(']'))
      if (*p++ == L_func('\0'))
        {
          /* This is no valid pattern.  */
          retval = -1;
          goto out;
        }
      }
    else if ((*p == L_func('?') || *p == L_func('*') || *p == L_func('+') || *p == L_func('@')
          || *p == L_func('!')) && p[1] == L_func('('))
      /* Remember the nesting level.  */
      ++level;
    else if (*p == L_func(')'))
      {
    if (level-- == 0)
      {
        /* This means we found the end of the pattern.  */
#define NEW_PATTERN \
        struct patternlist *newp;                         \
        size_t slen = (opt == '?' || opt == '@'             \
               ? pattern_len : (p - startp + 1));             \
        slen = sizeof (struct patternlist) + (slen * sizeof (char));      \
        int malloced = ! __libc_use_alloca (alloca_used + slen);          \
        if (__builtin_expect (malloced, 0))                   \
          {                                   \
        newp = malloc (slen);                         \
        if (newp == NULL)                         \
          {                               \
            retval = -2;                          \
            goto out;                             \
          }                               \
        any_malloced = 1;                         \
          }                                   \
        else                                  \
          newp = alloca_account (slen, alloca_used);              \
        newp->next = NULL;                            \
        newp->malloced = malloced;                        \
        *((char *) MEMPCPY (newp->str, startp, p - startp)) = L_func('\0');    \
        *lastp = newp;                            \
        lastp = &newp->next
        NEW_PATTERN;
      }
      }
    else if (*p == L_func('|'))
      {
    if (level == 0)
      {
        NEW_PATTERN;
        startp = p + 1;
      }
      }
  assert (list != NULL);
  assert (p[-1] == L_func(')'));
#undef NEW_PATTERN

  switch (opt)
    {
    case '*':
      if (FCT (p, string, string_end, no_leading_period, flags, NULL,
           alloca_used) == 0)
    goto success;
      /* FALLTHROUGH */

    case '+':
      do
    {
      for (rs = string; rs <= string_end; ++rs)
        /* First match the prefix with the current pattern with the
           current pattern.  */
        if (FCT (list->str, string, rs, no_leading_period,
             flags & FNM_FILE_NAME ? flags : flags & ~FNM_PERIOD,
             NULL, alloca_used) == 0
        /* This was successful.  Now match the rest with the rest
           of the pattern.  */
        && (FCT (p, rs, string_end,
             rs == string
             ? no_leading_period
             : rs[-1] == '/' && NO_LEADING_PERIOD (flags) ? 1 : 0,
             flags & FNM_FILE_NAME
             ? flags : flags & ~FNM_PERIOD, NULL, alloca_used) == 0
            /* This didn't work.  Try the whole pattern.  */
            || (rs != string
            && FCT (pattern - 1, rs, string_end,
                rs == string
                ? no_leading_period
                : (rs[-1] == '/' && NO_LEADING_PERIOD (flags)
                   ? 1 : 0),
                flags & FNM_FILE_NAME
                ? flags : flags & ~FNM_PERIOD, NULL,
                alloca_used) == 0)))
          /* It worked.  Signal success.  */
          goto success;
    }
      while ((list = list->next) != NULL);

      /* None of the patterns lead to a match.  */
      retval = FNM_NOMATCH;
      break;

    case '?':
      if (FCT (p, string, string_end, no_leading_period, flags, NULL,
           alloca_used) == 0)
    goto success;
      /* FALLTHROUGH */

    case '@':
        do {
            /* I cannot believe it but `strcat' is actually acceptable
             here.  Match the entire string with the prefix from the
             pattern list and the rest of the pattern following the
             pattern list.  */
            if(FCT(STRCAT(list->str, p), string, string_end,
                    no_leading_period,
                    flags & FNM_FILE_NAME ? flags : flags & ~FNM_PERIOD,
                    NULL, alloca_used) == 0)
                /* It worked.  Signal success.  */
                goto success;
        } while((list = list->next) != NULL);

        /* None of the patterns lead to a match.  */
        retval = FNM_NOMATCH;
        break;

    case '!':
      for (rs = string; rs <= string_end; ++rs)
    {
      struct patternlist *runp;

      for (runp = list; runp != NULL; runp = runp->next)
        if (FCT (runp->str, string, rs,  no_leading_period,
             flags & FNM_FILE_NAME ? flags : flags & ~FNM_PERIOD,
             NULL, alloca_used) == 0)
          break;

      /* If none of the patterns matched see whether the rest does.  */
      if (runp == NULL
          && (FCT (p, rs, string_end,
               rs == string
               ? no_leading_period
               : rs[-1] == '/' && NO_LEADING_PERIOD (flags) ? 1 : 0,
               flags & FNM_FILE_NAME ? flags : flags & ~FNM_PERIOD,
               NULL, alloca_used) == 0))
        /* This is successful.  */
        goto success;
    }

      /* None of the patterns together with the rest of the pattern
     lead to a match.  */
      retval = FNM_NOMATCH;
      break;

    default:
      assert (! "Invalid extended matching operator");
      retval = -1;
      break;
    }

 success:
 out:
  if (any_malloced)
    while (list != NULL)
      {
    struct patternlist *old = list;
    list = list->next;
    if (old->malloced)
      free (old);
      }

  return retval;
}


#undef FOLD
#undef FCT
#undef EXT
#undef END
#undef STRUCT
#undef MEMPCPY
#undef MEMCHR
#undef STRCOLL
#undef STRLEN
#undef STRCAT
#undef L
#undef BTOWC
#undef WIDE_CHAR_VERSION
#undef FINDIDX
