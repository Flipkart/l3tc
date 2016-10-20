set -e
export test_passed='no'
function do_test {
    SUDO_ASKPASS=/bin/false sudo -A $* 1>/dev/null 2>/dev/null
}
trap '/bin/bash -c "echo -n $test_passed"' EXIT

do_test ip link show
ns=l3tc_capability_test_ns
set +e
do_test ip netns del $ns
set -e
do_test ip netns add $ns
do_test ip netns exec $ns ip link show
do_test ip netns del $ns

test_passed='yes'
