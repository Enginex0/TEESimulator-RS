#include "../../main/cpp/transaction_policy.hpp"
#include <cassert>

int main() {
    using namespace transaction_policy;
    assert(isDaemonTransaction(0, 123, 123));
    assert(!isDaemonTransaction(0, 124, 123));
    assert(!isDaemonTransaction(1000, 123, 123));
    assert(!isDaemonTransaction(0, 0, 0));
    assert(bypassSystemUid(0));
    assert(bypassSystemUid(1000));
    assert(!bypassSystemUid(1027));
    assert(!bypassSystemUid(10000));
}
