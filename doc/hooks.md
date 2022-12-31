# Using Hooks to Customize Fuzzing

To customize the behaviour of a fuzzing trial, hook functions can be defined
which will be called at certain times. Namely, the following hooks are defined
in `struct fuzz_config` in the `hooks` member, and can be set to whatever
function you want to run it at the predefined time.

For most cases, using the default hooks will be good enough. The hook API
exists mainly for cases where fuzzing will be plugged into a larger
pre-existing system which some specific behaviour is required.

```c
// Executes before any trials begin
int (*pre_run)(const struct fuzz_pre_run_info* info, void* env);

// Executes after the whole run is finished
int (*post_run)(const struct fuzz_post_run_info* info, void* env);

// Executes before a specific trial's arguments are generated
int (*pre_gen_args)(const struct fuzz_pre_gen_args_info* info, void* env);

// Executes before running the trial, with the generated arguments
int (*pre_trial)(const struct fuzz_pre_trial_info* info, void* env);

// For forking tests, executes in the child process after forking
int (*post_fork)(const struct fuzz_post_fork_info* info, void* env);

// Executes after each trial is run
int (*post_trial)(const struct fuzz_post_trial_info* info, void* env);

// Executes when a counterexample is found which causes a trial to fail, but
// before attempting to shrink the counterexample
int (*counterexample)(const struct fuzz_counterexample_info* info, void* env);

// Executes before each shrink attempt
int (*pre_shrink)(const struct fuzz_pre_shrink_info* info, void* env);

// Executes after each shrink attempt
int (*post_shrink)(const struct fuzz_post_shrink_info* info, void* env);

// Executes after each trial which uses shrank arguments
int (*post_shrink_trial)(const struct fuzz_post_shrink_trial_info* info, void* env);
```

The definitions of each `struct X_info` in `fuzz.h` will determine what you can
do with each of these hooks.

A useful built in hook not executed by default is `fuzz_hook_first_fail_halt`,
which will cause the fuzzing to stop after finding and shrinking a single
counterexample. It's a pre-trial hook defined like so in `fuzz.h`:

```c
// Halt trials after the first failure.
FUZZ_PUBLIC
int fuzz_hook_first_fail_halt(const struct fuzz_pre_trial_info* info, void* env);
```
