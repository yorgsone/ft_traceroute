#ifndef FT__GETOPT__H
#define FT__GETOPT__H

# include "../libft.h"

extern const int no_argument;
extern const int required_argument;
extern const int optional_argument;

extern char* optarg;
extern int optind, opterr, optopt;

struct option {
  const char* name;
  int has_arg;
  int* flag;
  int val;
};

int ft_getopt(int argc, char* const argv[], const char* optstring);

#endif
