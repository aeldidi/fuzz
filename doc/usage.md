# Usage

First, `#include "fuzz.h"` in your code that uses fuzz.

Then, define a property function:

```c
    static enum fuzz_trial_res
    prop_encoded_and_decoded_data_should_match(struct fuzz *t, void *arg1) {
        struct buffer *input = (struct buffer *)arg1;
        // [compress & uncompress input, compare output & original input]
        // return FUZZ_RESULT_OK, FAIL, SKIP, or ERROR
    }
```

This should take one or more generated arguments and return
`FUZZ_RESULT_OK`, `FUZZ_RESULT_FAIL` if a counter-example to the
property was found, `FUZZ_RESULT_SKIP` if the combination of argument(s)
should be skipped, or `FUZZ_RESULT_ERROR` if the whole fuzz run should
halt and return an error.

Then, define how to generate the input argument(s) by providing a struct
with callbacks. (This definition can be shared between properties.)

For example:

```c
    static struct fuzz_type_info random_buffer_info = {
        // allocate a buffer based on random bitstream
        .alloc = random_buffer_alloc_cb,
        // free the buffer
        .free = random_buffer_free_cb,
        // get a hash based on the buffer
        .hash = random_buffer_hash_cb,
        // return a simpler variant of a buffer, or an error
        .shrink = random_buffer_shrink_cb,
        // print an instance
        .print = random_buffer_print_cb,
    };
```

All of these callbacks except 'alloc' are optional. For more details,
see the **Type Info Callbacks** subsection below.

If *autoshrinking* is used, type-generic shrinking and hashing
can be handled internally:

```c
    static struct fuzz_type_info random_buffer_info = {
        .alloc = random_buffer_alloc_cb,
        .free = random_buffer_free_cb,
        .print = random_buffer_print_cb,
        .autoshrink_config = {
            .enable = true,
        },
    };
```

Note that this has implications for how the `alloc` callback is written.
For details, see "Auto-shrinking" in [shrinking.md](shrinking.md).

Finally, call `fuzz_run` with a configuration struct:

```c
    bool test_encode_decode_roundtrip(void) {
        struct repeat_once_env env = { .fail = false };

        // Get a seed based on the current time
        fuzz_seed seed = fuzz_seed_of_time();

        // Property test configuration.
        // Note that the number of type_info struct pointers in
        // the .type_info field MUST match the field number
        // for the property function (here, prop1).
        struct fuzz_run_config config = {
            .name = __func__,
            .prop1 = prop_encoded_and_decoded_data_should_match,
            .type_info = { &random_buffer_info },
            .seed = seed,
        };

        // Run the property test.
        enum fuzz_run_res res = fuzz_run(&config);
        return res == FUZZ_RUN_PASS;
    }
```

The return value will indicate whether it was able to find any failures.

The config struct has several optional fields. The most commonly
customized ones are:

- trials: How many trials to run (default: 100).

- seed: The seed for the randomly generated input.

- hooks: There are several hooks that can be used to control the test
  runner behavior -- see the **Hooks** subsection below.

- fork: For details about forking, see [forking.md](forking.md).

## Type Info Callbacks

All of the callbacks are passed the `void *env` field from their
`fuzz_type_info` struct. This pointer is completely opaque to fuzz,
but can be cast to an arbitrary struct to pass other test-specifc state
to the callbacks. If its contents vary from trial to trial and it
influences the property test, it should be considered another input and
hashed accordingly.

### alloc - allocate an instance from a random bit stream

```c
    // Returns one of
    // FUZZ_RESULT_OK,
    // FUZZ_RESULT_SKIP, or
    // FUZZ_RESULT_ERROR
    typedef int
    fuzz_alloc_cb(struct fuzz *t, void *env, void **instance);
```

This is the only required callback.

Construct an argument instance, based off of the random bit stream.
To request random bits, use `fuzz_random_bits(t, bit_count)` or
`fuzz_random_bits_bulk(t, bit_count, buffer)`. The bitstream is
produced from a known seed, so it can be constructed again if
necessary. These streams of random bits are not expected to be
consistent between versions of the library.

To choose a random unsigned int, use `fuzz_random_choice(t, LIMIT)`,
which will return approximately evenly distributed `uint64_t`
values less than LIMIT. For example, `fuzz_random_choice(t, 5)` will
return values from `[0, 1, 2, 3, 4]`.

- On success, write the instance into `(*instance*)` and return
  `FUZZ_RESULT_OK`.

- If the current bit stream should be skipped, return
  `FUZZ_RESULT_SKIP`.

- To halt the entire test run with an error, return `FUZZ_RESULT_ERROR`.

If **autoshrinking** is used, there is an additional constraint: smaller
random bit values should lead to simpler instances. In particular, a
bitstream of all `0` bits should produce a minimal value for the type.
For more details, see [shrinking.md](shrinking.md).

### free - free an instance and any associated resources

```c
    typedef void
    fuzz_free_cb(void *instance, void *env);
```

Free the memory and other resources associated with the instance. If not
provided, fuzz will just leak resources. If only a single
`free(instance)` is needed, use `fuzz_generic_free_cb`.

### hash - get a hash for an instance

```c
    typedef uint64_t
    fuzz_hash_cb(const void *instance, void *env);
```

Using the included `fuzz_hash_*` functionality, produce a hash value
based on a given instance. This will usually consist of
`fuzz_hash_init(&h)`, then calling `fuzz_hash_sink(&h, &field,
sizeof(field))` on the instance's contents, and then returning
the result from `fuzz_hash_done(&h)`.

If provided, fuzz will use these hashes to avoid testing combinations
of arguments that have already been tried. Note that if the contents of
`env` impacts how instances are constructed / simplified, it should also
be fed into the hash.

### shrink - produce a simpler copy of an instance

```c
    // Returns one of
    // FUZZ_SHRINK_OK,
    // FUZZ_SHRINK_DEAD_END,
    // FUZZ_SHRINK_NO_MORE_TACTICS, or
    // FUZZ_SHRINK_ERROR,
    typedef int
    fuzz_shrink_cb(struct fuzz *t, const void *instance,
        uint32_t tactic, void *env, void **output);
```

For a given instance, producer a simpler copy, using the numerical value
in TACTIC to choose between multiple options. If not provided, fuzz
will just report the initially generated counter-example arguments
as-is. This is equivalent to a shrink callback that always returns
`FUZZ_SHRINK_NO_MORE_TACTICS`.

If a simpler instance can be produced, write it into `(*output)` and
return `FUZZ_SHRINK_OK`. If the current tactic is unusable, return
`FUZZ_SHRINK_DEAD_END`, and if all known tactics have been tried,
return `FUZZ_SHRINK_NO_MORE_TACTICS`.

If shrinking succeeds, fuzz will reset the tactic counter back to
0, so tactics that simplify by larger steps should be tried first,
and then later tactics can get them unstuck.

For more information about shrinking, recommendations for writing custom
shrinkers, using autoshrinking, and so on, see
[shrinking.md](shrinking.md).

### print - print an instance to the output stream

```c
    typedef void
    fuzz_print_cb(FILE *f, const void *instance, void *env);
```

Print the instance to a given file stream, behaving like:

```c
    fprintf(f, "%s", instance_to_string(instance, env));
```

If not provided, fuzz will just print the random number seeds that led
to discovering counter-examples.

## Hooks

`fuzz_run_config` has several **hook** fields, which can be used to
control fuzz's behavior. Each of these hooks takes some hook-specific struct
as its first parameter, and a user-controlled environment pointer as its second
parameter.

Each one of these is called with a callback-specific `info` struct (with
progress info such as the currently generated argument instances, the
result of the trial that just ran, etc.) and the `.hooks.env` field,
and returns an enum that indicates whether fuzz should continue,
halt everything with an error, or other callback-specific actions.

To get the `.hooks.env` pointer in the property function or `type_info`
callbacks, use `fuzz_hook_get_env(t)`: This environment can be used to
pass in a logging level for the trial, save extra details to print in a
hook later, pass in a size limit for the generated instance, etc.

Note that the environment shouldn't be changed within a run in a way
that affects trial passes/fails -- for example, changing the iteration
count as a property is re-run for shrinking will distort how changing
the input affects the property, making shrinking less effective.

For all of the details, see their type definitions in: `fuzz.h`.

The default hooks just print their results.
