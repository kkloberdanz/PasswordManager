#ifndef INPUT_OKAY_H
#define INPUT_OKAY_H

#define MIN_LEN_USERNAME  5
#define MAX_LEN_USERNAME 32

#define MIN_LEN_PASSWORD  8
#define MAX_LEN_PASSWORD 32

#include <regex.h>
#include "util.h"

int password_okay(char*);
int username_okay(char*);


#endif /* INPUT_OKAY_H */
