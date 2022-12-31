// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#ifndef FUZZ_TYPES_INTERNAL_H
#define FUZZ_TYPES_INTERNAL_H

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#if !defined(_WIN32)
#include <sys/types.h>
#endif

#if !defined(FUZZ_PUBLIC)
#define FUZZ_PUBLIC
#endif

#if defined(_WIN32)
// The LOG macro makes use of a compile-time known conditional, so we disable
// the MSVC warning "conditional expression is constant" (4127)
//
// Error 4996 is the "this function is deprecated" warning for standard C
// stuff.
#pragma warning(disable : 4127 4996)
#endif

#define FUZZ_MAX_TACTICS ((uint32_t)-1)
#define DEFAULT_uint64_t 0xa600d64b175eedLLU

#define FUZZ_LOG_LEVEL 0
#define LOG(LEVEL, ...)                                                       \
	do {                                                                  \
		if (LEVEL <= FUZZ_LOG_LEVEL) {                                \
			printf(__VA_ARGS__);                                  \
		}                                                             \
	} while (0)

#if !defined(FUZZ_MAX_ARITY)
#define FUZZ_MAX_ARITY 7
#endif

struct fuzz;
struct fuzz_pre_run_info;
struct fuzz_post_run_info;
struct fuzz_pre_gen_args_info;
struct fuzz_pre_trial_info;
struct fuzz_post_fork_info;
struct fuzz_post_trial_info;
struct fuzz_counterexample_info;
struct fuzz_pre_shrink_info;
struct fuzz_post_shrink_info;
struct fuzz_post_shrink_trial_info;

struct fuzz_bloom; // bloom filter
struct fuzz_rng;   // pseudorandom number generator

struct seed_info {
	const uint64_t run_seed;

	// Optional array of seeds to always run.
	// Can be used for regression tests.
	const size_t    always_seed_count; // number of seeds
	const uint64_t* always_seeds;      // seeds to always run
};

struct fork_info {
	const bool   enable;
	const size_t timeout;
	const int    signal;
	const size_t exit_timeout;
};

struct prop_info {
	const char* name; // property name, can be NULL
	// property function under test. Each funX represents a property
	// function which takes X arguments.
	union {
		int (*fun1)(struct fuzz*, void* arg1);
		int (*fun2)(struct fuzz*, void* arg1, void* arg2);
		int (*fun3)(struct fuzz*, void* arg1, void* arg2, void* arg3);
		int (*fun4)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4);
		int (*fun5)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5);
		int (*fun6)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5, void* arg6);
		int (*fun7)(struct fuzz*, void* arg1, void* arg2, void* arg3,
				void* arg4, void* arg5, void* arg6,
				void* arg7);
	} u;
	const size_t trial_count;

	// Type info for ARITY arguments.
	const uint8_t          arity; // number of arguments
	struct fuzz_type_info* type_info[FUZZ_MAX_ARITY];
};

// Hook function types
typedef int fuzz_pre_run_hook_cb(
		const struct fuzz_pre_run_info* info, void* env);
typedef int fuzz_post_run_hook_cb(
		const struct fuzz_post_run_info* info, void* env);
typedef int fuzz_hook_gen_args_pre_cb(
		const struct fuzz_pre_gen_args_info* info, void* env);
typedef int fuzz_hook_trial_pre_cb(
		const struct fuzz_pre_trial_info* info, void* env);
typedef int fuzz_hook_fork_post_cb(
		const struct fuzz_post_fork_info* info, void* env);
typedef int fuzz_hook_trial_post_cb(
		const struct fuzz_post_trial_info* info, void* env);
typedef int fuzz_hook_counterexample_cb(
		const struct fuzz_counterexample_info* info, void* env);
typedef int fuzz_hook_shrink_pre_cb(
		const struct fuzz_pre_shrink_info* info, void* env);
typedef int fuzz_hook_shrink_post_cb(
		const struct fuzz_post_shrink_info* info, void* env);
typedef int fuzz_hook_shrink_trial_post_cb(
		const struct fuzz_post_shrink_trial_info* info, void* env);

struct hook_info {
	fuzz_pre_run_hook_cb*           pre_run;
	fuzz_post_run_hook_cb*          post_run;
	fuzz_hook_gen_args_pre_cb*      pre_gen_args;
	fuzz_hook_trial_pre_cb*         trial_pre;
	fuzz_hook_fork_post_cb*         fork_post;
	fuzz_hook_trial_post_cb*        trial_post;
	fuzz_hook_counterexample_cb*    counterexample;
	fuzz_hook_shrink_pre_cb*        shrink_pre;
	fuzz_hook_shrink_post_cb*       shrink_post;
	fuzz_hook_shrink_trial_post_cb* shrink_trial_post;
	void*                           env;
};

struct counter_info {
	size_t pass;
	size_t fail;
	size_t skip;
	size_t dup;
};

struct prng_info {
	struct fuzz_rng* rng; // random number generator
	uint64_t         buf; // buffer for PRNG bits
	uint8_t          bits_available;
	// Bit pool, only used during autoshrinking.
	struct autoshrink_bit_pool* bit_pool;
};

enum arg_type {
	ARG_BASIC,
	ARG_AUTOSHRINK,
};

struct arg_info {
	void* instance;

	enum arg_type type;
	union {
		struct {
			struct autoshrink_env* env;
		} as;
	} u;
};

// Result from an individual trial.
struct trial_info {
	const int       trial; // N'th trial
	uint64_t        seed;  // Seed used
	size_t          shrink_count;
	size_t          successful_shrinks;
	size_t          failed_shrinks;
	struct arg_info args[FUZZ_MAX_ARITY];
};

enum worker_state {
	WS_INACTIVE,
	WS_ACTIVE,
	WS_STOPPED,
};

struct worker_info {
	enum worker_state state;
	int               fds[2];
	pid_t             pid;
	int               wstatus;
};

// Handle to state for the entire run.
struct fuzz {
	FILE*                               out;
	struct fuzz_bloom*                  bloom; // bloom filter
	struct fuzz_print_trial_result_env* print_trial_result_env;

	struct prng_info    prng;
	struct prop_info    prop;
	struct seed_info    seeds;
	struct fork_info    fork;
	struct hook_info    hooks;
	struct counter_info counters;
	struct trial_info   trial;
	struct worker_info  workers[1];
};

#endif
