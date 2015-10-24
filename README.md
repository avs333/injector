Inject code to process memory, link it and run in a separate thread.

/data/test/injector32 [options ...] `<file>` [libraries...]<br>
/data/test/injector32 cleanup `<pid>` `<start_addr>` `<len>`

`<file>` -- non-linked object file<br>
[libraries...] -- full paths to libraries it uses

Options:<br>
-e `<entry_point>` -- start symbol in `<file>` (default is "main")<br>
-i `<word>` -- argument to pass to `<entry_point>` (default is 0)<br>
-s `<size>` -- stack size of execution thread (default is 524288)<br>
-p `<pid>` OR -n `<proc_name>` -- target pid or process name (default is current process)<br>
-w -- wait until the thread has exited (take care to undo process changes if any!)<br>
-v -- verbose output: includes debugging information (may be repeated)<br>
-q -- quiet output: only errors and cleanup string if any


