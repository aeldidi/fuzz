// SPDX-License-Identifier: ISC
// SPDX-FileCopyrightText: 2014-19 Scott Vokes <vokes.s@gmail.com>
#include "greatest.h"

SUITE_EXTERN(prng);
SUITE_EXTERN(autoshrink);
SUITE_EXTERN(aux);
SUITE_EXTERN(bloom);
SUITE_EXTERN(error);
SUITE_EXTERN(integration);
SUITE_EXTERN(char_array);
SUITE_EXTERN(no_fork);

// Add all the definitions that need to be in the test runner's main file.
GREATEST_MAIN_DEFS();

int
main(int argc, char** argv)
{
	GREATEST_MAIN_BEGIN(); // command-line arguments, initialization.
	RUN_SUITE(prng);
	RUN_SUITE(autoshrink);
	RUN_SUITE(aux);
	RUN_SUITE(bloom);
	RUN_SUITE(error);
	RUN_SUITE(integration);
	RUN_SUITE(char_array);
	RUN_SUITE(no_fork);
	GREATEST_MAIN_END(); // display results
}
