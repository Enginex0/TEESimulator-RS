#pragma once

#include <cstdint>

namespace transaction_policy {

constexpr bool isDaemonTransaction(uint32_t uid, int32_t pid, int32_t daemon_pid) {
    return uid == 0 && pid > 0 && pid == daemon_pid;
}

constexpr bool bypassSystemUid(uint32_t uid) {
    return uid < 10000 && uid != 1027;
}

}
