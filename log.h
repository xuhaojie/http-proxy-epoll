#ifndef HTTPS_PROXY_LOG_H
#define HTTPS_PROXY_LOG_H

#include <threads.h>

extern thread_local unsigned short thread_id__;

void log_(const char* filename, int lineno, const char* fn_name, const char* fmt, ...);

#ifndef NO_LOG
#define DEBUG_LOG(...) log_(__FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define DEBUG_LOG(...) (void)0
#endif

#endif  // HTTPS_PROXY_LOG_H
