project(
    'fuzz',
    'c',
    default_options: [
        'c_std=c99',
        'warning_level=3',
    ],
)

cc = meson.get_compiler('c')
deps = []

if host_machine.system() != 'windows'
    deps += cc.find_library('m')
    add_project_arguments(
        [
            '-D_POSIX_C_SOURCE=200809L',
        ],
        language: 'c',
    )
endif

srcs = files(
    'src/autoshrink.c',
    'src/autoshrink.h',
    'src/aux.c',
    'src/aux_builtin.c',
    'src/bloom.c',
    'src/bloom.h',
    'src/call.c',
    'src/call.h',
    'src/fuzz.c',
    'src/fuzz.h',
    'src/hash.c',
    'src/polyfill.c',
    'src/polyfill.h',
    'src/random.c',
    'src/random.h',
    'src/rng.c',
    'src/rng.h',
    'src/run.c',
    'src/run.h',
    'src/shrink.c',
    'src/shrink.h',
    'src/trial.c',
    'src/trial.h',
    'src/types_internal.h',
)

amalgamate_exe = executable(
    'amalgamate_exe',
    files('tools/amalgamate.c'),
)

fuzz_c = custom_target(
    'fuzz.c',
    input: srcs,
    output: 'fuzz.c',
    command: [amalgamate_exe, meson.source_root() / 'src'],
)

srcs = [fuzz_c]

incdirs = include_directories('src/')
subdir('test/')

alias_target('amalgamate', fuzz_c)
