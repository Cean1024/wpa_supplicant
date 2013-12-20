/*
 * WPA Supplicant - Common definitions
 * Copyright (c) 2004-2005, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#ifndef DEFS_H
#define DEFS_H

#ifdef CONFIG_NATIVE_WINDOWS
#ifdef FALSE
#undef FALSE
#endif
#ifdef TRUE
#undef TRUE
#endif
#endif /* CONFIG_NATIVE_WINDOWS */
typedef enum { FALSE = 0, TRUE = 1 } Boolean;

#endif /* DEFS_H */
