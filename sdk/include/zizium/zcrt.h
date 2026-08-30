// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "zizium/process.h"
#include "zizium/status.h"

#if defined(_WIN32) && defined(ZI_BUILD_ZICRT)
#define ZI_CRT_API __declspec(dllexport)
#elif defined(_WIN32)
#define ZI_CRT_API __declspec(dllimport)
#else
#define ZI_CRT_API
#endif

ZI_CRT_API ZiStatus ZiCrtInitialiseProcess(const ZiProcessParameters* parameters);
