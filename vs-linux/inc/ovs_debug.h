/*
 * debug.h
 *
 *  Created on: 2015Äê9ÔÂ9ÈÕ
 *      Author:
 */

#ifndef _OVS_DEBUG_H_
#define _OVS_DEBUG_H_
#include <stdbool.h>

struct se_log_switch {
    unsigned int log_switch;
    int index;
};

unsigned int get_debug_switch(void);
void open_debug_switch(int index, unsigned int log_switch);
void close_debug_switch(int index);
bool check_log_index(int index);

enum debug_level{
    SE_DEBUG_LEVEL_NONE = 0,
    SE_DEBUG_LEVEL_INFO = 0x01,
    SE_DEBUG_LEVEL_WARN = 0x02,
    SE_DEBUG_LEVEL_ERROR = 0x04,
    SE_DEBUG_LEVEL_ALL   = 0X07
};

#ifdef _IS_LINUX_
   #define SE_DEBUG_PRINT(debug_level, m_format, ...) 
#else
#define SE_DEBUG_PRINT(debug_level, m_format, ...)  \
    do { \
        if (debug_level & get_debug_switch()) \
        { \
            printf(m_format, ##__VA_ARGS__); \
        } \
    }while(0)

#endif

#endif /* _OVS_DEBUG_H_ */
