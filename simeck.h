#ifndef SIMECK_H
#define SIMECK_H

#include "stdint.h"

#define GETBIT(x, k) ((x & ( 1 << k )) >> k)
#define FLIPBIT(x, k) (x ^ ( 1 << k )) 
#define LROT16(x, r) (((x) << (r)) | ((x) >> (16 - (r))))
#define LROT24(x, r) ((((x) << (r)) % (1 << 24)) | ((x) >> (24 - (r))))
#define LROT32(x, r) (((x) << (r)) | ((x) >> (32 - (r))))

#define RROT16(x, r) (((x) >> (r)) | ((x) << (16 - (r))))
#define RROT24(x, r) (((x) >> (r)) | (((x) << (24 - (r))) % (1 << 24)))
#define RROT32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))

#define ROUND32(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT16((lft), 5)) ^ LROT16((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

#define ROUND48(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT24((lft), 5)) ^ LROT24((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)

#define ROUND64(key, lft, rgt, tmp) do { \
    tmp = (lft); \
    lft = ((lft) & LROT32((lft), 5)) ^ LROT32((lft), 1) ^ (rgt) ^ (key); \
    rgt = (tmp); \
} while (0)


#endif // SIMECK_H
