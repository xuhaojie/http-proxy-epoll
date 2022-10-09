#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>

// log level
enum LOG_LEVEL
{
	LOG_LEVEL_FATAL = 0,
	LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARNING = 2,
	LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4,
	LOG_LEVEL_TRACE = 5,
};
 
extern unsigned long g_ulLogLevel;

#define LOG_PRINT(level, level_name, fmt, ...) do{\
	if(level <= g_ulLogLevel)\
	{\
		printf("[File:%s Line:%3d] [%s] "fmt, __FILE__, __LINE__, level_name, ##__VA_ARGS__);\
	}\
}while(0);

#define LOG_FATAL(fmt, ...) LOG_PRINT(LOG_LEVEL_FATAL, "FATAL", fmt, ##__VA_ARGS__) 
#define LOG_ERROR(fmt, ...) LOG_PRINT(LOG_LEVEL_ERROR, "ERROR", fmt, ##__VA_ARGS__) 
#define LOG_WARN(fmt, ...) LOG_PRINT(LOG_LEVEL_WARNING, "WARN", fmt, ##__VA_ARGS__)  
#define LOG_INFO(fmt, ...) LOG_PRINT(LOG_LEVEL_INFO, "INFO", fmt, ##__VA_ARGS__) 
#define LOG_DEBUG(fmt, ...) LOG_PRINT(LOG_LEVEL_DEBUG, "DEBUG", fmt, ##__VA_ARGS__) 
#define LOG_TRACE(fmt, ...) LOG_PRINT(LOG_LEVEL_TRACE, "TRACE", fmt, ##__VA_ARGS__) 

#endif //___LOG_H___
