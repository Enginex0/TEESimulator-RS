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
    assert(!bypassSystemUid(2000));
    assert(!bypassSystemUid(10000));
    assert(bypassTransaction(1000, false, false));
    assert(!bypassTransaction(1000, false, true));
    assert(!bypassTransaction(1000, true, true));
    assert(bypassTransaction(0, false, true));
    assert(!bypassTransaction(2000, false, false));
    assert(bypassTransaction(10123, true, false));
    assert(!bypassTransaction(10123, false, false));
}
