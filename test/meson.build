
test_srcs = files(
    'test_char_array.c',
    'test_fuzz.c',
    'test_fuzz_autoshrink.c',
    'test_fuzz_autoshrink_bulk.c',
    'test_fuzz_autoshrink_int_array.c',
    'test_fuzz_autoshrink_ll.c',
    'test_fuzz_aux.c',
    'test_fuzz_bloom.c',
    'test_fuzz_error.c',
    'test_fuzz_integration.c',
    'test_fuzz_no_fork.c',
    'test_fuzz_prng.c',
)

test_fuzz_exe = executable(
    'test_fuzz',
    [srcs, test_srcs],
    include_directories: [
        incdirs,
    ],
    dependencies: deps,
)

test(
    'prng_should_return_same_series_from_same_seeds',
    test_fuzz_exe,
    args: ['-t', 'prng_should_return_same_series_from_same_seeds'],
    suite: 'prng',
    timeout: 5,
)

test(
    'basic_sampling',
    test_fuzz_exe,
    args: ['-t', 'basic_sampling'],
    suite: 'prng',
    timeout: 5,
)

test(
    'bit_sampling_two_bytes',
    test_fuzz_exe,
    args: ['-t', 'bit_sampling_two_bytes'],
    suite: 'prng',
    timeout: 5,
)

test(
    'bit_sampling_bytes',
    test_fuzz_exe,
    args: ['-t', 'bit_sampling_bytes'],
    suite: 'prng',
    timeout: 5,
)

test(
    'bit_sampling_odd_sizes',
    test_fuzz_exe,
    args: ['-t', 'bit_sampling_odd_sizes'],
    suite: 'prng',
    timeout: 5,
)

test(
    'seed_with_upper_32_bits_masked_should_produce_different_value',
    test_fuzz_exe,
    args: [
        '-t',
        'seed_with_upper_32_bits_masked_should_produce_different_value',
    ],
    suite: 'prng',
    timeout: 5,
)

test(
    'check_random_choice_0',
    test_fuzz_exe,
    args: ['-t', 'check_random_choice_0'],
    suite: 'prng',
    timeout: 5,
)

test(
    'check_random_choice_distribution__slow',
    test_fuzz_exe,
    args: ['-t', 'check_random_choice_distribution__slow'],
    suite: 'prng',
    timeout: 300,
    priority: 1,
)

test(
    'll_drop_nothing',
    test_fuzz_exe,
    args: ['-t', 'll_drop_nothing'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_drop_nothing_but_do_truncate',
    test_fuzz_exe,
    args: ['-t', 'll_drop_nothing_but_do_truncate'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_drop_first',
    test_fuzz_exe,
    args: ['-t', 'll_drop_first'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_drop_third_and_fourth',
    test_fuzz_exe,
    args: ['-t', 'll_drop_third_and_fourth'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_drop_last',
    test_fuzz_exe,
    args: ['-t', 'll_drop_last'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_mutate_shift',
    test_fuzz_exe,
    args: ['-t', 'll_mutate_shift'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_mutate_mask',
    test_fuzz_exe,
    args: ['-t', 'll_mutate_mask'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_mutate_swap',
    test_fuzz_exe,
    args: ['-t', 'll_mutate_swap'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_mutate_sub',
    test_fuzz_exe,
    args: ['-t', 'll_mutate_sub'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_mutate_retries_when_change_has_no_effect',
    test_fuzz_exe,
    args: ['-t', 'll_mutate_retries_when_change_has_no_effect'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'll_prop',
    test_fuzz_exe,
    args: ['-t', 'll_prop'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'ia_prop',
    test_fuzz_exe,
    args: ['-t', 'ia_prop'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'bulk_random_bits',
    test_fuzz_exe,
    args: ['-t', 'bulk_random_bits'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'double_abs_lt1',
    test_fuzz_exe,
    args: ['-t', 'double_abs_lt1'],
    suite: 'autoshrink',
    timeout: 5,
)

test(
    'a_squared_lte_fixed',
    test_fuzz_exe,
    args: ['-t', 'a_squared_lte_fixed'],
    suite: 'aux',
    timeout: 5,
)

test(
    'a_squared_lt_b',
    test_fuzz_exe,
    args: ['-t', 'a_squared_lt_b'],
    suite: 'aux',
    timeout: 5,
)

test(
    'pass_autoscaling',
    test_fuzz_exe,
    args: ['-t', 'pass_autoscaling'],
    suite: 'aux',
    timeout: 30,
    priority: 1,
)

test(
    'get_hook_env',
    test_fuzz_exe,
    args: ['-t', 'get_hook_env'],
    suite: 'aux',
    timeout: 5,
)

test(
    'gen_and_print',
    test_fuzz_exe,
    args: ['-t', 'gen_and_print'],
    suite: 'aux',
    timeout: 5,
)

test(
    'all_marked_should_remain_marked',
    test_fuzz_exe,
    args: ['-t', 'all_marked_should_remain_marked'],
    suite: 'bloom',
    timeout: 5,
)

test(
    'alloc_returns_skip',
    test_fuzz_exe,
    args: ['-t', 'alloc_returns_skip'],
    suite: 'error',
    timeout: 5,
)

test(
    'alloc_returns_error',
    test_fuzz_exe,
    args: ['-t', 'alloc_returns_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'alloc_returns_skip_during_autoshrink',
    test_fuzz_exe,
    args: ['-t', 'alloc_returns_skip_during_autoshrink'],
    suite: 'error',
    timeout: 5,
)

test(
    'alloc_returns_error_during_autoshrink',
    test_fuzz_exe,
    args: ['-t', 'alloc_returns_error_during_autoshrink'],
    suite: 'error',
    timeout: 5,
)

test(
    'second_alloc_returns_skip',
    test_fuzz_exe,
    args: ['-t', 'second_alloc_returns_skip'],
    suite: 'error',
    timeout: 5,
)

test(
    'shrinking_error',
    test_fuzz_exe,
    args: ['-t', 'shrinking_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'error_from_both_autoshrink_and_shrink_cb',
    test_fuzz_exe,
    args: ['-t', 'error_from_both_autoshrink_and_shrink_cb'],
    suite: 'error',
    timeout: 5,
)

test(
    'run_pre_hook_error',
    test_fuzz_exe,
    args: ['-t', 'run_pre_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'run_post_hook_error',
    test_fuzz_exe,
    args: ['-t', 'run_post_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'trial_pre_hook_error',
    test_fuzz_exe,
    args: ['-t', 'trial_pre_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'trial_post_hook_error',
    test_fuzz_exe,
    args: ['-t', 'trial_post_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'shrink_pre_hook_error',
    test_fuzz_exe,
    args: ['-t', 'shrink_pre_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'shrink_post_hook_error',
    test_fuzz_exe,
    args: ['-t', 'shrink_post_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'shrink_trial_post_hook_error',
    test_fuzz_exe,
    args: ['-t', 'shrink_trial_post_hook_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'trial_skip',
    test_fuzz_exe,
    args: ['-t', 'trial_skip'],
    suite: 'error',
    timeout: 5,
)

test(
    'trial_error',
    test_fuzz_exe,
    args: ['-t', 'trial_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'trial_error_during_autoshrink',
    test_fuzz_exe,
    args: ['-t', 'trial_error_during_autoshrink'],
    suite: 'error',
    timeout: 5,
)

test(
    'counterexample_error',
    test_fuzz_exe,
    args: ['-t', 'counterexample_error'],
    suite: 'error',
    timeout: 5,
)

test(
    'fail_but_pass_when_rerurn',
    test_fuzz_exe,
    args: ['-t', 'fail_but_pass_when_rerun'],
    suite: 'error',
    timeout: 5,
)

test(
    'generated_unsigned_int_are_positive',
    test_fuzz_exe,
    args: ['-t', 'generated_unsigned_int_are_positive'],
    suite: 'integration',
    timeout: 5,
)

test(
    'generated_int_list_with_cons_is_longer',
    test_fuzz_exe,
    args: ['-t', 'generated_int_list_with_cons_is_longer'],
    suite: 'integration',
    timeout: 5,
)

test(
    'generated_int_list_does_not_repeat_values',
    test_fuzz_exe,
    args: ['-t', 'generated_int_list_does_not_repeat_values'],
    suite: 'integration',
    timeout: 5,
)

test(
    'two_generated_lists_do_not_match',
    test_fuzz_exe,
    args: ['-t', 'two_generated_lists_do_not_match'],
    suite: 'integration',
    timeout: 5,
)

test(
    'always_seeds_must_be_run',
    test_fuzz_exe,
    args: ['-t', 'always_seeds_must_be_run'],
    suite: 'integration',
    timeout: 5,
)

test(
    'overconstrained_state_spaces_should_be_detected',
    test_fuzz_exe,
    args: ['-t', 'overconstrained_state_spaces_should_be_detected'],
    suite: 'integration',
    timeout: 5,
)

test(
    'save_seed_and_error_before_generating_args',
    test_fuzz_exe,
    args: ['-t', 'save_seed_and_error_before_generating_args'],
    suite: 'integration',
    timeout: 5,
)

test(
    'gen_pre_halt',
    test_fuzz_exe,
    args: ['-t', 'gen_pre_halt'],
    suite: 'integration',
    timeout: 5,
)

test(
    'only_shrink_three_times',
    test_fuzz_exe,
    args: ['-t', 'only_shrink_three_times'],
    suite: 'integration',
    timeout: 5,
)

test(
    'save_local_minimum_and_re_run',
    test_fuzz_exe,
    args: ['-t', 'save_local_minimum_and_re_run'],
    suite: 'integration',
    timeout: 5,
)

test(
    'repeat_local_minimum_once',
    test_fuzz_exe,
    args: ['-t', 'repeat_local_minimum_once'],
    suite: 'integration',
    timeout: 5,
)

test(
    'repeat_first_successful_shrink_once_then_halt',
    test_fuzz_exe,
    args: ['-t', 'repeat_first_successful_shrink_once_then_halt'],
    suite: 'integration',
    timeout: 5,
)

test(
    'shrink_crash',
    test_fuzz_exe,
    args: ['-t', 'shrink_crash'],
    suite: 'integration',
    timeout: 5,
)

test(
    'shrink_infinite_loop',
    test_fuzz_exe,
    args: ['-t', 'shrink_infinite_loop'],
    suite: 'integration',
    timeout: 5,
)

test(
    'shrink_abort_immediately_to_stress_forking__slow',
    test_fuzz_exe,
    args: ['-t', 'shrink_abort_immediately_to_stress_forking__slow'],
    suite: 'integration',
    timeout: 80,
    priority: 1,
)

test(
    'shrink_and_SIGUSR1_on_timeout',
    test_fuzz_exe,
    args: ['-t', 'shrink_and_SIGUSR1_on_timeout'],
    suite: 'integration',
    timeout: 5,
)

test(
    'shrink_and_SIGUSR1_on_timeout_then_SIGKILL',
    test_fuzz_exe,
    args: ['-t', 'shrink_and_SIGUSR1_on_timeout_then_SIGKILL'],
    suite: 'integration',
    timeout: 5,
)

test(
    'forking_hook',
    test_fuzz_exe,
    args: ['-t', 'forking_hook'],
    suite: 'integration',
    timeout: 5,
)

test(
    'fork_privilege_drop_cpu_limit__slow',
    test_fuzz_exe,
    args: ['-t', 'fork_privilege_drop_cpu_limit__slow'],
    suite: 'integration',
    timeout: 30,
    priority: 1,
)

test(
    'repeat_with_verbose_set_after_shrinking',
    test_fuzz_exe,
    args: ['-t', 'repeat_with_verbose_set_after_shrinking'],
    suite: 'integration',
    timeout: 5,
)

test(
    'expected_seed_should_be_used_first',
    test_fuzz_exe,
    args: ['-t', 'expected_seed_should_be_used_first'],
    suite: 'integration',
    timeout: 5,
)

test(
    'trial_post_hook_gets_correct_args',
    test_fuzz_exe,
    args: ['-t', 'trial_post_hook_gets_correct_args'],
    suite: 'integration',
    timeout: 5,
)

test(
    'free_callback_should_be_optional',
    test_fuzz_exe,
    args: ['-t', 'free_callback_should_be_optional'],
    suite: 'integration',
    timeout: 5,
)

test(
    'char_fail_shrinkage',
    test_fuzz_exe,
    args: ['-t', 'char_fail_shrinkage'],
    suite: 'char_array',
    timeout: 5,
)

test(
    'skip_forking_tests_when_fork_is_not_supported',
    test_fuzz_exe,
    args: ['-t', 'skip_forking_tests_when_fork_is_not_supported'],
    suite: 'no_fork',
    timeout: 5,
)
