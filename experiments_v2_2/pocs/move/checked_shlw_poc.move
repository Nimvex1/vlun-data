#[test_only]
module integer_mate::checked_shlw_poc_tests {
    use integer_mate::math_u256;

    // Control: a value strictly below 2^192 shifts correctly on EVERY revision.
    // Guards the polarity below against being vacuously true.
    #[test]
    fun control_below_the_boundary_still_shifts() {
        let (r, oob) = math_u256::checked_shlw(0xffffffffffffffffffffffffffffffffffffffffffffffff);
        // (2^192 - 1) << 64, no overflow, no bits lost
        assert!(r == 0xffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000, 1);
        assert!(!oob, 2);
    }

    // The violation: n == 2^192 exactly. The vulnerable comparison is n > mask,
    // so this value passes the check and is shifted, silently discarding the
    // result. The fix changes the comparison to n >= mask, so the same call
    // reports overflow instead. This test asserts the VULNERABLE behaviour: it
    // must pass on the parent revision and fail on the fix commit.
    #[test]
    fun boundary_exactly_2_pow_192_shifts_silently() {
        let (r, oob) = math_u256::checked_shlw(0x1000000000000000000000000000000000000000000000000);
        assert!(r == 0, 3);
        assert!(!oob, 4);
    }
}
