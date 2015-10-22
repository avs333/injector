Inject code to process memory, link it and run in a separate thread.

/data/test/injector32 [options ...] <file> [libraries...]

/data/test/injector32 cleanup <pid> <start_addr> <len>

<file> -- non-linked object file

[libraries...] -- full paths to libraries it uses

Options:

-e <entry_point> -- start symbol in <file> (default is "main")

-i <word> -- argument to pass to <entry_point> (default is 0)

-s <size> -- stack size of execution thread (default is 524288)

-p <pid> OR -n <proc_name> -- target pid or process name (default is current process)

-v -- verbose output: includes debugging information (may be repeated)

-q -- quiet output: only errors and cleanup string if any


