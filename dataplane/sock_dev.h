#pragma once

#include <cstdint>

#define SOCK_DEV_PREFIX "sock_dev:"

int sock_dev_create(const char* path, uint8_t numa_node);
