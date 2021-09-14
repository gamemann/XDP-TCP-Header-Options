#pragma once

#ifndef htons
    #define htons(x) ((__be16)___constant_swab16((x)))
#endif

#define NULL ((void*)0)