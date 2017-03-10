# American Fuzzy Lop

Homepage: <http://lcamtuf.coredump.cx/afl/>

> American fuzzy lop is a security-oriented fuzzer that employs a
> novel type of compile-time instrumentation and genetic algorithms to
> automatically discover clean, interesting test cases that trigger new
> internal states in the targeted binary. This substantially improves
> the functional coverage for the fuzzed code. The compact synthesized
> corpora produced by the tool are also useful for seeding other,
> more labor- or resource-intensive testing regimes down the road.

Very useful tool for testing an extensive amount of random inputs.

# AddressSanitizer

Homepage: <https://github.com/google/sanitizers/wiki/AddressSanitizer>

> AddressSanitizer (aka ASan) is a memory error detector for C/C++. It finds:
>
> - Use after free (dangling pointer dereference)
> - Heap buffer overflow
> - Stack buffer overflow
> - Global buffer overflow
> - Use after return
> - Initialization order bugs
> - Memory leaks

This, in combination with [other](#memorysanitizer) [sanitizers](#threadsanitizer),
allows for powerful debugging capabilities.

# TriforceAFL

Homepage: <https://github.com/nccgroup/TriforceAFL>

> AFL/QEMU fuzzing with full-system emulation.
>
> This is a patched version of AFL that supports full-system
> fuzzing using QEMU. The included QEMU has been updated to allow tracing
> of branches when running a system emulator for x86_64.
> Extra instructions have been added to start AFL's forkserver,
> make fuzz settings, and mark the start and stop of test cases.

Very useful tool for testing an extensive amount of random inputs.

# Astrée

Homepage: <http://www.astree.ens.fr/>

> Astrée is a static program analyzer aiming at proving the absence of Run
> Time Errors (RTE) in programs written in the C programming language.
> On personal computers, such errors, commonly found in programs, usually
> result in unpleasant error messages and the termination of the application,
> and sometimes in a system crash. In embedded applications, such errors may
> have graver consequences.
>
> Astrée analyzes structured C programs, with complex memory usages, but
> without dynamic memory allocation and recursion. This encompasses many
> embedded programs as found in earth transportation, nuclear energy,
> medical instrumentation, aeronautic, and aerospace applications, in
> particular synchronous control/command such as electric flight control,
> or space vessels maneuvers.

I have never used this tool. It is a proprietary product, and the distributor
must be contacted in order to request a quote for the program.

# BLAST

Homepage: <http://forge.ispras.ru/projects/blast>

> BLAST (Berkeley Lazy Abstraction Software verification Tool) is a static
> software verification tool for C language that solves the reachability
> problem, i.e. whether a given program location can be reached from an
> entry point (main function) by a valid execution.
>
> Verification of safety properties may be reduced to the reachability,
> and BLAST is used for such verification in the Linux Driver Verification
> project.

I have never used this tool. It is free software. The release notes
contain more information about the capabilities of this tool.

# Checked C

Homepage: <https://github.com/Microsoft/CheckedC>

> Checked C is an extension to C that adds static and dynamic checking to
> detect or prevent common programming errors such as buffer overruns,
> out-of-bounds memory accesses, and incorrect type casts.

I have never used this tool, but it looks interesting.

# Clang Static Analyzer

Homepage: <http://clang-analyzer.llvm.org/>

> The Clang Static Analyzer is a source code analysis tool that finds bugs
> in C, C++, and Objective-C programs.

I have never used this tool, but it looks interesting. There is a web
browser interface to trace code paths.

# Coccinelle

Homepage: <http://coccinelle.lip6.fr/>

> Coccinelle is a program matching and transformation engine which
> provides the language SmPL (Semantic Patch Language) for specifying
> desired matches and transformations in C code. Coccinelle was initially
> targeted towards performing collateral evolutions in Linux. Such
> evolutions comprise the changes that are needed in client code in
> response to evolutions in library APIs, and may include modifications
> such as renaming a function, adding a function argument whose value is
> somehow context-dependent, and reorganizing a data structure. Beyond
> collateral evolutions, Coccinelle is successfully used (by us and others)
> for finding and fixing bugs in systems code.

I have never used this tool. It looks more complex than useful.

# Coverity

Homepage: <https://scan.coverity.com/faq>

> Coverity Scan is a service by which Coverity provides the results of analysis
> on open source coding projects to open source code developers that have
> registered their products with Coverity Scan.

# Cppcheck

Homepage: <http://cppcheck.sourceforge.net/>

> Cppcheck is a static analysis tool for C/C++ code. Unlike C/C++ compilers
> and many other analysis tools it does not detect syntax errors in the
> code. Cppcheck primarily detects the types of bugs that the compilers
> normally do not detect. The goal is to detect only real errors in the code
> (i.e. have zero false positives).
>
> Detect various kinds of bugs in your code:
>
> - Out of bounds checking
> - Memory leaks checking
> - Detect possible null pointer dereferences
> - Check for uninitialized variables
> - Check for invalid usage of STL
> - Checking exception safety
> - Warn if obsolete or unsafe functions are used
> - Warn about unused or redundant code
> - Detect various suspicious code indicating bugs

I have never used this tool. It is free software, and looks useful.

# CScout

Homepage: <http://www.spinellis.gr/cscout/>

> CScout is a source code analyzer and refactoring browser for collections
> of C programs. It can process workspaces of multiple projects (we define
> a project as a collection of C source files that are linked together)
> mapping the complexity introduced by the C preprocessor back into the
> original C source code files.

# Eclair

Homepage: <http://bugseng.com/products/eclair>

> ECLAIR is a general platform for software verification. Applications
> range from coding rule validation, to automatic generation of
> test cases, to the proof of absence of run-time errors or generation
> of counterexamples, and to the specification of code matchers and
> rewriters based both syntactic and semantic conditions.

I have never used this product. It is a proprietary product, and the
distributor must be contacted in order to request a quote for the program.

# Frama-C

Homepage: <http://frama-c.com/>

> Frama-C is a suite of tools dedicated to the analysis of the source code of
> software written in C.
>
> Frama-C gathers several static analysis techniques in a single collaborative
> framework. The collaborative approach of Frama-C allows static analyzers to
> build upon the results already computed by other analyzers in the framework.
> Thanks to this approach, Frama-C provides sophisticated tools, such as a slicer
> and dependency analysis.

Appears to have a number of features similar to LLVM instrumentation.

# Gdb

Homepage: <https://www.gnu.org/software/gdb/>

> GDB, the GNU Project debugger, allows you to see what is going on
> ``inside'' another program while it executes --- or what another program
> was doing at the moment it crashed.
>
> GDB can do four main kinds of things (plus other things in support
> of these) to help you catch bugs in the act:
>
> - Start your program, specifying anything that might affect its behavior.
> - Make your program stop on specified conditions.
> - Examine what has happened, when your program has stopped.
> - Change things in your program, so you can experiment
> with correcting the effects of one bug and go on to
> learn about another.

This is a very useful program. It is free software.

# Indent

Homepage: <https://www.gnu.org/software/indent/>

> The indent program can be used to make code easier to read. It
> can also convert from one style of writing C to another. indent
> understands a substantial amount about the syntax of C, but it also
> attempts to cope with incomplete and misformed syntax.

This is a very useful program. It is free software.

# KernelAddressSanitizer

Homepage: <https://www.kernel.org/doc/Documentation/kasan.txt>

> KernelAddressSANitizer (KASAN) is a dynamic memory error detector. It provides
> a fast and comprehensive solution for finding use-after-free and out-of-bounds
> bugs.
>
> KASAN uses compile-time instrumentation for checking every memory access,
> therefore you will need a GCC version 4.9.2 or later. GCC 5.0 or later is
> required for detection of out-of-bounds accesses to stack or global variables.
>
> Currently KASAN is supported only for x86_64 architecture.

Linux Kernel port of [AddressSanatizer](#addresssanatizer).

# KernelThreadSanitizer

Homepage: <https://github.com/google/ktsan>

> A dynamic data race error detector for Linux kernel. Currently in development.

Linux Kernel port of [ThreadSanatizer](#threadsanatizer).

# libFuzzer

Homepage: <http://llvm.org/docs/LibFuzzer.html>

> LibFuzzer is in-process, coverage-guided, evolutionary fuzzing engine.
>
> LibFuzzer is linked with the library under test, and feeds fuzzed inputs to the
> library via a specific fuzzing entrypoint (aka "target function"); the fuzzer
> then tracks which areas of the code are reached, and generates mutations on the
> corpus of input data in order to maximize the code coverage. The code coverage
> information for libFuzzer is provided by LLVM's SanitizerCoverage
> instrumentation.

# MemorySanitizer

Homepage: <https://github.com/google/sanitizers/wiki/MemorySanitizer>

> MemorySanitizer (MSan) is a detector of uninitialized memory reads
> in C/C++ programs.
>
> Uninitialized values occur when stack- or heap-allocated memory
> is read before it is written. MSan detects cases where such values
> affect program execution.
>
> MemorySanitizer is bit-exact: it can track uninitialized bits in
> a bitfield. It will tolerate copying of uninitialized memory, and
> also simple logic and arithmetic operations with it. In general,
> MemorySanitizer silently tracks the spread of uninitialized data in
> memory, and reports a warning when a code branch is taken (or not
> taken) depending on an uninitialized value.

This, in combination with [other](#addresssanitizer) [sanitizers](#threadsanitizer),
allows for powerful debugging capabilities.

# Parasoft C/C++Test

Homepage: <https://www.parasoft.com/product/cpptest/>

> Parasoft C/C++test is an integrated development testing solution for C and
> C++. It automates a broad range of software quality practices -- including
> static code analysis, unit testing, code review, coverage analysis,
> runtime error detection and more. It can be used in both host-based
> and target-based code analysis and test flows, which is critical for
> embedded and cross-platform development.

I have never used this product. It is a proprietary product, and the
distributor must be contacted in order to request a quote for the program.

# Splint

Homepage: <http://splint.org/>

> Splint is a tool for statically checking C programs for security
> vulnerabilities and coding mistakes. With minimal effort, Splint can
> be used as a better lint. If additional effort is invested adding
> annotations to programs, Splint can perform stronger checking than
> can be done by any standard lint.

This is the spiritual successor to the well-known `lint` program.

# STACK

Homepage: <http://css.csail.mit.edu/stack/>

> STACK is a static checker that detects unstable code in C/C++ programs.
> Optimization-unstable code (unstable code for short) is an emerging class of
> software bugs: code that is unexpectedly eliminated by compiler optimizations
> due to undefined behavior in the program. Unstable code is present in many
> systems.

# Syzkaller

Homepage: <https://github.com/google/syzkaller>

> syzkaller is a distributed, unsupervised, coverage-guided Linux syscall
> fuzzer. It is meant to be used with KASAN (CONFIG_KASAN=y), KTSAN
> (CONFIG_KTSAN=y), or KUBSAN (patch).

The list of found bugs leads me to believe that the coverage this tool
achieves is comprehensive.

# ThreadSanitizer

Homepage: <https://github.com/google/sanitizers/wiki/ThreadSanitizerCppManual>

> ThreadSanitizer (aka TSan) is a data race detector for C/C++. Data
> races are one of the most common and hardest to debug types of bugs
> in concurrent systems. A data race occurs when two threads access
> the same variable concurrently and at least one of the accesses
> is write. C++11 standard officially bans data races as undefined
> behavior.

This, in combination with [other](#addresssanitizer) [sanitizers](#memorysanitizer),
allows for powerful debugging capabilities.

# UBSAN

Homepage: <https://developerblog.redhat.com/2014/10/16/gcc-undefined-behavior-sanitizer-ubsan/>

> A run-time checker for the C and C++ languages. In order to check your
> program with ubsan, compile and link the program with -fsanitize=undefined
> option. Such instrumented binaries have to be executed; if ubsan detects
> any problem, it outputs a "runtime error:" message, and in most cases
> continues executing the program.

Looks useful.

# Valgrind

Homepage: <http://valgrind.org/>

> Valgrind is an instrumentation framework for building dynamic analysis
> tools. There are Valgrind tools that can automatically detect many
> memory management and threading bugs, and profile your programs in
> detail.
>
> The Valgrind distribution currently includes six production-quality
> tools: a memory error detector, two thread error detectors, a cache and
> branch-prediction profiler, a call-graph generating cache and
> branch-prediction profiler, and a heap profiler.
>
> It also includes three experimental tools: a stack/global array overrun
> detector, a second heap profiler that examines how heap blocks are used,
> and a SimPoint basic block vector generator.

This is a useful tool to detect leaks in applications with dynamically
allocated memory. The other tools included in the distribution are useful
as well.

# Veracode

Homepage: <https://www.veracode.com/products/binary-static-analysis-sast>

> SAST identifies critical vulnerabilities such as SQL injection,
> cross-site scripting (XSS), buffer overflows, unhandled error
> conditions and potential back-doors. Binary SAST technology
> delivers actionable information that prioritizes flaws according
> to severity and provides detailed remediation information to help
> developers address them quickly.

I have never used this product. It is a proprietary product, and the
distributor must be contacted in order to request a quote for the program.
