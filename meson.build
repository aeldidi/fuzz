project('theft', 'c',
	default_options: [
		'c_std=c99',
		'warning_level=3',
	],
)

cc = meson.get_compiler('c')
deps = []

if host_machine.system() == 'windows'
	deps += cc.find_library('ws2_32')
	if cc.get_id() == 'msvc'
		add_project_arguments(
			[
				'-DTHEFT_PUBLIC=__declspec(dllexport)',
			],
			language: 'c',
		)
	endif
else
	deps += cc.find_library('m')
	add_project_arguments(
		[
			'-D_POSIX_C_SOURCE=200809L',
			'-DTHEFT_PUBLIC=',
		],
		language: 'c',
	)
endif

srcs = files(
	'src/theft_hash.c',
	'src/theft_bloom.c',
	'src/theft.c',
	'src/theft_call.c',
	'src/theft_autoshrink.c',
	'src/theft_random.c',
	'src/theft_rng.c',
	'src/theft_run.c',
	'src/theft_trial.c',
	'src/theft_aux.c',
	'src/theft_aux_builtin.c',
	'src/theft_shrink.c',
	'src/polyfill.c',
)

incdirs = include_directories(
	'src/',
	'inc/'
)

theft_lib = library('theft',
	srcs,
	include_directories: incdirs,
	dependencies: deps,
)

theft = declare_dependency(
	link_with: theft_lib,
	include_directories: include_directories('inc/'),
)

install_headers(
	'inc/theft_types.h',
	'inc/theft.h',
)

greatest = include_directories('vendor/')
subdir('test/')
