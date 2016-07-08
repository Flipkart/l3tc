#ifndef _HTAB_COMMON_H
#define _HTAB_COMMON_H

#if HAVE_CONFIG_H
#  include <config.h>
#endif

#include <uthash.h>

typedef void (value_destructor_t)(void *v);

#endif
