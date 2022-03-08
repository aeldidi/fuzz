
test_srcs = files(
	'test_theft_autoshrink_bulk.c',
	'test_theft_error.c',
	'test_theft_aux.c',
	'test_theft_autoshrink.c',
	'test_theft_prng.c',
	'test_theft_autoshrink_int_array.c',
	'test_theft_autoshrink_ll.c',
	'test_theft_integration.c',
	'test_char_array.c',
	'test_theft.c',
	'test_theft_bloom.c',
)

test_theft_exe = executable('test_theft',
	[srcs, test_srcs],
	include_directories: [
		greatest,
		incdirs,
	],
	dependencies: deps,
)
test('theft', test_theft_exe,
	timeout: 300,
)
