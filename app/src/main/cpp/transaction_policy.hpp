#pragma once

#include <cstdint>

namespace transaction_policy {

constexpr bool isDaemonTransaction(uint32_t uid, int32_t pid, int32_t daemon_pid) {
    return uid == 0 && pid > 0 && pid == daemon_pid;
}

constexpr bool bypassSystemUid(uint32_t uid) {
    return uid < 10000 && uid != 1027 && uid != 2000;
}

constexpr bool bypassTransaction(uint32_t uid, bool dynamic_bypass, bool system_maintenance) {
    if (uid == 1000 && system_maintenance) return false;
    return bypassSystemUid(uid) || dynamic_bypass;
}

}
