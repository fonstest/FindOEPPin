#pragma once
#include "stdafx.h"




   
#define LOG_WRITE_TO_FILE 1 //if it is uncommented the result will be saved on file otherwise they'll be printed to stdout
//#define LOG_FILENAME "C:\\pin\\PinUnpackerDependencies\\ScyllaWrapperLog.txt"
  

class Log
{

public:
	static Log* getInstance();
	void Log::closeLogFile();
	void Log::closeReportFile();
	FILE* Log::getLogFile();
	void Log::initLogPath(WCHAR * cur_path);
	static WCHAR * LOG_FILENAME;



private:
	Log::Log();
	static Log* instance;
	FILE *log_file;

};

