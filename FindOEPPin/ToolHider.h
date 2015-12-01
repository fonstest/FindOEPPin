#pragma once

#include "Pin.h"
namespace W{
	#include "windows.h"
}


class ToolHider
{
public:
	ToolHider(void);
	~ToolHider(void);
	void avoidEvasion(INS ins);
};

