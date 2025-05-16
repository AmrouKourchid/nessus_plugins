#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3938-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(210583);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/08");

  script_cve_id(
    "CVE-2023-45288",
    "CVE-2023-45289",
    "CVE-2023-45290",
    "CVE-2024-24783",
    "CVE-2024-24784",
    "CVE-2024-24785",
    "CVE-2024-24787",
    "CVE-2024-24788",
    "CVE-2024-24789",
    "CVE-2024-24790",
    "CVE-2024-24791",
    "CVE-2024-34155",
    "CVE-2024-34156",
    "CVE-2024-34158"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3938-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : go1.22-openssl (SUSE-SU-2024:3938-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:3938-1 advisory.

    This update ships go1.22-openssl 1.22.7.1 (jsc#SLE-18320)

    - Update to version 1.22.7.1 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.7-1-openssl-fips.

      * Update to Go 1.22.7 (#229)

    - go1.22.7 (released 2024-09-05) includes security fixes to the
      encoding/gob, go/build/constraint, and go/parser packages, as
      well as bug fixes to the fix command and the runtime.

      CVE-2024-34155 CVE-2024-34156 CVE-2024-34158:
      - go#69142 go#69138 bsc#1230252 security: fix CVE-2024-34155 go/parser: stack exhaustion in all Parse*
    functions (CVE-2024-34155)
      - go#69144 go#69139 bsc#1230253 security: fix CVE-2024-34156 encoding/gob: stack exhaustion in
    Decoder.Decode (CVE-2024-34156)
      - go#69148 go#69141 bsc#1230254 security: fix CVE-2024-34158 go/build/constraint: stack exhaustion in
    Parse (CVE-2024-34158)
      - go#68811 os: TestChtimes failures
      - go#68825 cmd/fix: fails to run on modules whose go directive value is in '1.n.m' format introduced in
    Go 1.21.0
      - go#68972 cmd/cgo: aix c-archive corrupting stack

    - go1.22.6 (released 2024-08-06) includes fixes to the go command,
      the compiler, the linker, the trace command, the covdata command,
      and the bytes, go/types, and os/exec packages.

      * go#68594 cmd/compile: internal compiler error with zero-size types
      * go#68546 cmd/trace/v2: pprof profiles always empty
      * go#68492 cmd/covdata: too many open files due to defer f.Close() in for loop
      * go#68475 bytes: IndexByte can return -4294967295 when memory usage is above 2^31 on js/wasm
      * go#68370 go/types: assertion failure in recent range statement checking logic
      * go#68331 os/exec: modifications to Path ignored when *Cmd is created using Command with an absolute
    path on Windows
      * go#68230 cmd/compile: inconsistent integer arithmetic result on Go 1.22+arm64 with/without -race
      * go#68222 cmd/go: list with -export and -covermode=atomic fails to build
      * go#68198 cmd/link: issues with Xcode 16 beta

    - Update to version 1.22.5.3 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.5-3-openssl-fips.

      * Only load openssl if fips == '1'
        Avoid loading openssl whenever GOLANG_FIPS is not 1.
        Previously only an unset variable would cause the library load
        to be skipped, but users may also expect to be able to set eg.
        GOLANG_FIPS=0 in environments without openssl.

    - Update to version 1.22.5.2 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.5-2-openssl-fips.

      * Only load OpenSSL when in FIPS mode

    - Update to version 1.22.5.1 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.5-1-openssl-fips.

      * Update to go1.22.5

    - go1.22.5 (released 2024-07-02) includes security fixes to the
      net/http package, as well as bug fixes to the compiler, cgo, the
      go command, the linker, the runtime, and the crypto/tls,
      go/types, net, net/http, and os/exec packages.

      CVE-2024-24791:
      * go#68200 go#67555 bsc#1227314 security: fix CVE CVE-2024-24791 net/http: expect: 100-continue handling
    is broken in various ways
      * go#65983 cmd/compile: hash of unhashable type
      * go#65994 crypto/tls: segfault when calling tlsrsakex.IncNonDefault()
      * go#66598 os/exec: calling Cmd.Start after setting Cmd.Path manually to absolute path without '.exe' no
    longer implicitly adds '.exe' in Go 1.22
      * go#67298 runtime: 'fatal: morestack on g0' on amd64 after upgrade to Go 1.21, stale bounds
      * go#67715 cmd/cgo/internal/swig,cmd/go,x/build: swig cgo tests incompatible with C++ toolchain on
    builders
      * go#67798 cmd/compile: internal compiler error: unexpected type: <nil> (<nil>) in for-range
      * go#67820 cmd/compile: package-level variable initialization with constant dependencies doesn't match
    order specified in Go spec
      * go#67850 go/internal/gccgoimporter: go building failing with gcc 14.1.0
      * go#67934 net: go DNS resolver fails to connect to local DNS server
      * go#67945 cmd/link: using -fuzz with test that links with cgo on darwin causes linker failure
      * go#68052 cmd/go: go list -u -m all fails loading module retractions: module requires go >= 1.N+1
    (running go 1.N)
      * go#68122 cmd/link: runtime.mach_vm_region_trampoline: unsupported dynamic relocation for symbol
    libc_mach_task_self_ (type=29 (R_GOTPCREL) stype=46 (SDYNIMPORT))

    - Update to version 1.22.4.1 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.4-1-openssl-fips.

      * Update to go1.22.4

    - go1.22.4 (released 2024-06-04) includes security fixes to the
      archive/zip and net/netip packages, as well as bug fixes to the
      compiler, the go command, the linker, the runtime, and the os
      package.

      CVE-2024-24789 CVE-2024-24790:
      * go#67554 go#66869 bsc#1225973 security: fix CVE-2024-24789 archive/zip: EOCDR comment length handling
    is inconsistent with other ZIP implementations
      * go#67682 go#67680 bsc#1225974 security: fix CVE-2024-24790 net/netip: unexpected behavior from Is
    methods for IPv4-mapped IPv6 addresses
      * go#67188 runtime/metrics: /memory/classes/heap/unused:bytes spikes
      * go#67212 cmd/compile: SIGBUS unaligned access on mips64 via qemu-mips64
      * go#67236 cmd/go: mod tidy reports toolchain not available with 'go 1.21'
      * go#67258 runtime: unexpected fault address 0
      * go#67311 cmd/go: TestScript/gotoolchain_issue66175 fails on tip locally
      * go#67314 cmd/go,cmd/link: TestScript/build_issue48319 and TestScript/build_plugin_reproducible failing
    on LUCI gotip-darwin-amd64-longtest builder due to non-reproducible LC_UUID
      * go#67352 crypto/x509: TestPlatformVerifier failures on Windows due to broken connections
      * go#67460 cmd/compile: internal compiler error: panic with range over integer value
      * go#67527 cmd/link: panic: machorelocsect: size mismatch
      * go#67650 runtime: SIGSEGV after performing clone(CLONE_PARENT) via C constructor prior to runtime
    start
      * go#67696 os: RemoveAll susceptible to symlink race

    - Update to version 1.22.3.3 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.3-3-openssl-fips.

      * config: update openssl backend (#201)

    - Update to version 1.22.3.2 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.3-2-openssl-fips.

      * patches: restore signature of HashSign/HashVerify (#199)

    - Update to version 1.22.3.1 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.3-1-openssl-fips.

      * Update to go1.22.3
      * fix: rename patch file
      * Backport change https://go-review.googlesource.com/c/go/+/554615 to Go1.22 (#193)
        runtime: crash asap and extend total sleep time for slow machine in test
        Running with few threads usually does not need 500ms to crash, so let it
        crash as soon as possible. While the test may caused more time on slow
        machine, try to expand the sleep time in test.
      * cmd/go: re-enable CGO for Go toolchain commands (#190)
      * crypto/ecdsa: Restore HashSign and HashVerify (#189)

    - go1.22.3 (released 2024-05-07) includes security fixes to the go
      command and the net package, as well as bug fixes to the
      compiler, the runtime, and the net/http package.

      CVE-2024-24787 CVE-2024-24788:
      * go#67122 go#67119 bsc#1224017 security: fix CVE-2024-24787 cmd/go: arbitrary code execution during
    build on darwin
      * go#67040 go#66754 bsc#1224018 security: fix CVE-2024-24788 net: high cpu usage in extractExtendedRCode
      * go#67018 cmd/compile: Go 1.22.x failed to be bootstrapped from 386 to ppc64le
      * go#67017 cmd/compile: changing a hot concrete method to interface method triggers a PGO ICE
      * go#66886 runtime: deterministic fallback hashes across process boundary
      * go#66698 net/http: TestRequestLimit/h2 becomes significantly more expensive and slower after
    x/net@v0.23.0

    - Update to version 1.22.2.1 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.2-1-openssl-fips.

      * Update to go1.22.2

    - go1.22.2 (released 2024-04-03) includes a security fix to the
      net/http package, as well as bug fixes to the compiler, the go
      command, the linker, and the encoding/gob, go/types, net/http,
      and runtime/trace packages.

      CVE-2023-45288:
      * go#66298 go#65051 bsc#1221400 security: fix CVE-2023-45288 net/http, x/net/http2: close connections
    when receiving too many headers
      * go#65858 cmd/compile: unreachable panic with GODEBUG=gotypesalias=1
      * go#66060 cmd/link: RISC-V external link, failed to find text symbol for HI20 relocation
      * go#66076 cmd/compile: out-of-bounds panic with uint32 conversion and modulus operation in Go 1.22.0 on
    arm64
      * go#66134 cmd/compile: go test . results in CLOSURE ... <unknown line number>: internal compiler error:
    assertion failed
      * go#66137 cmd/go: go 1.22.0: go test throws errors when processing folders not listed in coverpkg
    argument
      * go#66178 cmd/compile: ICE: panic: interface conversion: ir.Node is *ir.ConvExpr, not *ir.IndexExpr
      * go#66201 runtime/trace: v2 traces contain an incorrect timestamp scaling factor on Windows
      * go#66255 net/http: http2 round tripper nil pointer dereference causes panic causing deadlock
      * go#66256 cmd/go: git shallow fetches broken at CL 556358
      * go#66273 crypto/x509: Certificate no longer encodable using encoding/gob in Go1.22
      * go#66412 cmd/link: bad carrier sym for symbol runtime.elf_savegpr0.args_stackmap on ppc64le

    - Update to version 1.22.1.2 cut from the go1.22-fips-release
      branch at the revision tagged go1.22.1-2-openssl-fips.

      * config: Update openssl v2 module (#178)

    - Remove subpackage go1.x-openssl-libstd for compiled shared object
      libstd.so.

      * Continue to build experimental libstd only on go1.x Tumbleweed.
      * Removal fixes build errors on go1.x-openssl Factory and ALP.
      * Use of libstd.so is experimental and not recommended for
        general use, Go currently has no ABI.
      * Feature go build -buildmode=shared is deprecated by upstream,
        but not yet removed.

    - Initial package go1.22-openssl version 1.22.1.1 cut from the
      go1.22-fips-release branch at the revision tagged
      go1.22.1-1-openssl-fips.

      * Go upstream merged branch dev.boringcrypto in go1.19+.
      * In go1.x enable BoringCrypto via GOEXPERIMENT=boringcrypto.
      * In go1.x-openssl enable FIPS mode (or boring mode as the
        package is named) either via an environment variable
        GOLANG_FIPS=1 or by virtue of booting the host in FIPS mode.
      * When the operating system is operating in FIPS mode, Go
        applications which import crypto/tls/fipsonly limit operations
        to the FIPS ciphersuite.
      * go1.x-openssl is delivered as two large patches to go1.x
        applying necessary modifications from the golang-fips/go GitHub
        project for the Go crypto library to use OpenSSL as the
        external cryptographic library in a FIPS compliant way.
      * go1.x-openssl modifies the crypto/* packages to use OpenSSL for
        cryptographic operations.
      * go1.x-openssl uses dlopen() to call into OpenSSL.
      * SUSE RPM packaging introduces a fourth version digit go1.x.y.z
        corresponding to the golang-fips/go patchset tagged revision.
      * Patchset improvements can be updated independently of upstream
        Go maintenance releases.

    - go1.22.1 (released 2024-03-05) includes security fixes to the
      crypto/x509, html/template, net/http, net/http/cookiejar, and
      net/mail packages, as well as bug fixes to the compiler, the go
      command, the runtime, the trace command, and the go/types and
      net/http packages.

      CVE-2023-45289 CVE-2023-45290 CVE-2024-24783 CVE-2024-24784 CVE-2024-24785:
      * go#65831 go#65390 bsc#1220999 security: fix CVE-2024-24783 crypto/x509: Verify panics on certificates
    with an unknown public key algorithm
      * go#65849 go#65083 bsc#1221002 security: fix CVE-2024-24784 net/mail: comments in display names are
    incorrectly handled
      * go#65850 go#65383 bsc#1221001 security: fix CVE-2023-45290 net/http: memory exhaustion in
    Request.ParseMultipartForm
      * go#65859 go#65065 bsc#1221000 security: fix CVE-2023-45289 net/http, net/http/cookiejar: incorrect
    forwarding of sensitive headers and cookies on HTTP redirect
      * go#65969 go#65697 bsc#1221003 security: fix CVE-2024-24785 html/template: errors returned from
    MarshalJSON methods may break template escaping
      * go#65352 cmd/go: go generate fails silently when run on a package in a nested workspace module
      * go#65471 internal/testenv: TestHasGoBuild failures on the LUCI noopt builders
      * go#65474 internal/testenv: support LUCI mobile builders in testenv tests
      * go#65577 cmd/trace/v2: goroutine analysis page doesn't identify goroutines consistently
      * go#65618 cmd/compile: Go 1.22 build fails with 1.21 PGO profile on internal/saferio change
      * go#65619 cmd/compile: Go 1.22 changes support for modules that declare go 1.0
      * go#65641 cmd/cgo/internal/testsanitizers,x/build: LUCI clang15 builders failing
      * go#65644 runtime: crash in race detector when execution tracer reads from CPU profile buffer
      * go#65728 go/types: nil pointer dereference in Alias.Underlying()
      * go#65759 net/http: context cancellation can leave HTTP client with deadlocked HTTP/1.1 connections in
    Go1.22
      * go#65760 runtime: Go 1.22.0 fails to build from source on armv7 Alpine Linux
      * go#65818 runtime: go1.22.0 test with -race will SIGSEGV or SIGBUS or Bad Pointer
      * go#65852 cmd/go: 'missing ziphash' error with go.work
      * go#65883 runtime: scheduler sometimes starves a runnable goroutine on wasm platforms

      * bsc#1219988 ensure VERSION file is present in GOROOT
        as required by go tool dist and go tool distpack

    - go1.22 (released 2024-02-06) is a major release of Go.
      go1.22.x minor releases will be provided through February 2024.
      https://github.com/golang/go/wiki/Go-Release-Cycle
      go1.22 arrives six months after go1.21. Most of its changes are
      in the implementation of the toolchain, runtime, and libraries.
      As always, the release maintains the Go 1 promise of
      compatibility. We expect almost all Go programs to continue to
      compile and run as before.

      * Language change: go1.22 makes two changes to for loops.
        Previously, the variables declared by a for loop were created
        once and updated by each iteration. In go1.22, each iteration
        of the loop creates new variables, to avoid accidental sharing
        bugs. The transition support tooling described in the proposal
        continues to work in the same way it did in Go 1.21.
      * Language change: For loops may now range over integers
      * Language change: go1.22 includes a preview of a language change
        we are considering for a future version of Go:
        range-over-function iterators. Building with
        GOEXPERIMENT=rangefunc enables this feature.
      * go command: Commands in workspaces can now use a vendor
        directory containing the dependencies of the workspace. The
        directory is created by go work vendor, and used by build
        commands when the -mod flag is set to vendor, which is the
        default when a workspace vendor directory is present.  Note
        that the vendor directory's contents for a workspace are
        different from those of a single module: if the directory at
        the root of a workspace also contains one of the modules in the
        workspace, its vendor directory can contain the dependencies of
        either the workspace or of the module, but not both.
      * go get is no longer supported outside of a module in the legacy
        GOPATH mode (that is, with GO111MODULE=off). Other build
        commands, such as go build and go test, will continue to work
        indefinitely for legacy GOPATH programs.
      * go mod init no longer attempts to import module requirements
        from configuration files for other vendoring tools (such as
        Gopkg.lock).
      * go test -cover now prints coverage summaries for covered
        packages that do not have their own test files. Prior to Go
        1.22 a go test -cover run for such a package would report: ?
        mymod/mypack [no test files] and now with go1.22, functions in
        the package are treated as uncovered: mymod/mypack coverage:
        0.0% of statements Note that if a package contains no
        executable code at all, we can't report a meaningful coverage
        percentage; for such packages the go tool will continue to
        report that there are no test files.
      * trace: The trace tool's web UI has been gently refreshed as
        part of the work to support the new tracer, resolving several
        issues and improving the readability of various sub-pages. The
        web UI now supports exploring traces in a thread-oriented
        view. The trace viewer also now displays the full duration of
        all system calls.  These improvements only apply for viewing
        traces produced by programs built with go1.22 or newer. A
        future release will bring some of these improvements to traces
        produced by older version of Go.
      * vet: References to loop variables The behavior of the vet tool
        has changed to match the new semantics (see above) of loop
        variables in go1.22. When analyzing a file that requires go1.22
        or newer (due to its go.mod file or a per-file build
        constraint), vetcode> no longer reports references to loop
        variables from within a function literal that might outlive the
        iteration of the loop. In Go 1.22, loop variables are created
        anew for each iteration, so such references are no longer at
        risk of using a variable after it has been updated by the loop.
      * vet: New warnings for missing values after append The vet tool
        now reports calls to append that pass no values to be appended
        to the slice, such as slice = append(slice). Such a statement
        has no effect, and experience has shown that is nearly always a
        mistake.
      * vet: New warnings for deferring time.Since The vet tool now
        reports a non-deferred call to time.Since(t) within a defer
        statement. This is equivalent to calling time.Now().Sub(t)
        before the defer statement, not when the deferred function is
        called. In nearly all cases, the correct code requires
        deferring the time.Since call.
      * vet: New warnings for mismatched key-value pairs in log/slog
        calls The vet tool now reports invalid arguments in calls to
        functions and methods in the structured logging package,
        log/slog, that accept alternating key/value pairs. It reports
        calls where an argument in a key position is neither a string
        nor a slog.Attr, and where a final key is missing its value.
      * runtime: The runtime now keeps type-based garbage collection
        metadata nearer to each heap object, improving the CPU
        performance (latency or throughput) of Go programs by
        1-3%. This change also reduces the memory overhead of the
        majority Go programs by approximately 1% by deduplicating
        redundant metadata. Some programs may see a smaller improvement
        because this change adjusts the size class boundaries of the
        memory allocator, so some objects may be moved up a size class.
        A consequence of this change is that some objects' addresses
        that were previously always aligned to a 16 byte (or higher)
        boundary will now only be aligned to an 8 byte boundary. Some
        programs that use assembly instructions that require memory
        addresses to be more than 8-byte aligned and rely on the memory
        allocator's previous alignment behavior may break, but we
        expect such programs to be rare. Such programs may be built
        with GOEXPERIMENT=noallocheaders to revert to the old metadata
        layout and restore the previous alignment behavior, but package
        owners should update their assembly code to avoid the alignment
        assumption, as this workaround will be removed in a future
        release.
      * runtime: On the windows/amd64 port, programs linking or loading
        Go libraries built with -buildmode=c-archive or
        -buildmode=c-shared can now use the SetUnhandledExceptionFilter
        Win32 function to catch exceptions not handled by the Go
        runtime. Note that this was already supported on the
        windows/386 port.
      * compiler: Profile-guided Optimization (PGO) builds can now
        devirtualize a higher proportion of calls than previously
        possible. Most programs from a representative set of Go
        programs now see between 2 and 14% improvement from enabling
        PGO.
      * compiler: The compiler now interleaves devirtualization and
        inlining, so interface method calls are better optimized.
      * compiler: go1.22 also includes a preview of an enhanced
        implementation of the compiler's inlining phase that uses
        heuristics to boost inlinability at call sites deemed
        'important' (for example, in loops) and discourage inlining at
        call sites deemed 'unimportant' (for example, on panic
        paths). Building with GOEXPERIMENT=newinliner enables the new
        call-site heuristics; see issue #61502 for more info and to
        provide feedback.
      * linker: The linker's -s and -w flags are now behave more
        consistently across all platforms. The -w flag suppresses DWARF
        debug information generation. The -s flag suppresses symbol
        table generation. The -s flag also implies the -w flag, which
        can be negated with -w=0. That is, -s -w=0 will generate a
        binary with DWARF debug information generation but without the
        symbol table.
      * linker: On ELF platforms, the -B linker flag now accepts a
        special form: with -B gobuildid, the linker will generate a GNU
        build ID (the ELF NT_GNU_BUILD_ID note) derived from the Go
        build ID.
      * linker: On Windows, when building with -linkmode=internal, the
        linker now preserves SEH information from C object files by
        copying the .pdata and .xdata sections into the final
        binary. This helps with debugging and profiling binaries using
        native tools, such as WinDbg. Note that until now, C functions'
        SEH exception handlers were not being honored, so this change
        may cause some programs to behave differently.
        -linkmode=external is not affected by this change, as external
        linkers already preserve SEH information.
      * bootstrap: As mentioned in the Go 1.20 release notes, go1.22
        now requires the final point release of Go 1.20 or later for
        bootstrap. We expect that Go 1.24 will require the final point
        release of go1.22 or later for bootstrap.
      * core library: New math/rand/v2 package: go1.22 includes the
        first v2 package in the standard library, math/rand/v2. The
        changes compared to math/rand are detailed in proposal
        go#61716. The most important changes are:
        - The Read method, deprecated in math/rand, was not carried
          forward for math/rand/v2. (It remains available in
          math/rand.) The vast majority of calls to Read should use
          crypto/rands Read instead. Otherwise a custom Read can be
          constructed using the Uint64 method.
        - The global generator accessed by top-level functions is
          unconditionally randomly seeded. Because the API guarantees
          no fixed sequence of results, optimizations like per-thread
          random generator states are now possible.
        - The Source interface now has a single Uint64 method; there is
          no Source64 interface.
        - Many methods now use faster algorithms that were not possible
          to adopt in math/rand because they changed the output
          streams.
        - The Intn, Int31, Int31n, Int63, and Int64n top-level
          functions and methods from math/rand are spelled more
          idiomatically in math/rand/v2: IntN, Int32, Int32N, Int64,
          and Int64N. There are also new top-level functions and
          methods Uint32, Uint32N, Uint64, Uint64N, Uint, and UintN.
        - The new generic function N is like Int64N or Uint64N but
          works for any integer type. For example a random duration
          from 0 up to 5 minutes is rand.N(5*time.Minute).
        - The Mitchell & Reeds LFSR generator provided by math/rands
          Source has been replaced by two more modern pseudo-random
          generator sources: ChaCha8 PCG. ChaCha8 is a new,
          cryptographically strong random number generator roughly
          similar to PCG in efficiency. ChaCha8 is the algorithm used
          for the top-level functions in math/rand/v2. As of go1.22,
          math/rand's top-level functions (when not explicitly seeded)
          and the Go runtime also use ChaCha8 for randomness.
        - We plan to include an API migration tool in a future release,
          likely Go 1.23.
      * core library: New go/version package: The new go/version
        package implements functions for validating and comparing Go
        version strings.
      * core library: Enhanced routing patterns: HTTP routing in the
        standard library is now more expressive. The patterns used by
        net/http.ServeMux have been enhanced to accept methods and
        wildcards. This change breaks backwards compatibility in small
        ways, some obviouspatterns with '{' and '}' behave
        differently and some less sotreatment of escaped paths has
        been improved. The change is controlled by a GODEBUG field
        named httpmuxgo121. Set httpmuxgo121=1 to restore the old
        behavior.
      * Minor changes to the library As always, there are various minor
        changes and updates to the library, made with the Go 1 promise
        of compatibility in mind. There are also various performance
        improvements, not enumerated here.
      * archive/tar: The new method Writer.AddFS adds all of the files
        from an fs.FS to the archive.
      * archive/zip: The new method Writer.AddFS adds all of the files
        from an fs.FS to the archive.
      * bufio: When a SplitFunc returns ErrFinalToken with a nil token,
        Scanner will now stop immediately. Previously, it would report
        a final empty token before stopping, which was usually not
        desired. Callers that do want to report a final empty token can
        do so by returning []byte{} rather than nil.
      * cmp: The new function Or returns the first in a sequence of
        values that is not the zero value.
      * crypto/tls: ConnectionState.ExportKeyingMaterial will now
        return an error unless TLS 1.3 is in use, or the
        extended_master_secret extension is supported by both the
        server and client. crypto/tls has supported this extension
        since Go 1.20. This can be disabled with the tlsunsafeekm=1
        GODEBUG setting.
      * crypto/tls: By default, the minimum version offered by
        crypto/tls servers is now TLS 1.2 if not specified with
        config.MinimumVersion, matching the behavior of crypto/tls
        clients. This change can be reverted with the tls10server=1
        GODEBUG setting.
      * crypto/tls: By default, cipher suites without ECDHE support are
        no longer offered by either clients or servers during pre-TLS
        1.3 handshakes. This change can be reverted with the
        tlsrsakex=1 GODEBUG setting.
      * crypto/x509: The new CertPool.AddCertWithConstraint method can
        be used to add customized constraints to root certificates to
        be applied during chain building.
      * crypto/x509: On Android, root certificates will now be loaded
        from /data/misc/keychain/certs-added as well as
        /system/etc/security/cacerts.
      * crypto/x509: A new type, OID, supports ASN.1 Object Identifiers
        with individual components larger than 31 bits. A new field
        which uses this type, Policies, is added to the Certificate
        struct, and is now populated during parsing. Any OIDs which
        cannot be represented using a asn1.ObjectIdentifier will appear
        in Policies, but not in the old PolicyIdentifiers field. When
        calling CreateCertificate, the Policies field is ignored, and
        policies are taken from the PolicyIdentifiers field. Using the
        x509usepolicies=1 GODEBUG setting inverts this, populating
        certificate policies from the Policies field, and ignoring the
        PolicyIdentifiers field. We may change the default value of
        x509usepolicies in Go 1.23, making Policies the default field
        for marshaling.
      * database/sql: The new Null[T] type provide a way to scan
        nullable columns for any column types.
      * debug/elf: Constant R_MIPS_PC32 is defined for use with MIPS64
        systems. Additional R_LARCH_* constants are defined for use
        with LoongArch systems.
      * encoding: The new methods AppendEncode and AppendDecode added
        to each of the Encoding types in the packages encoding/base32,
        encoding/base64, and encoding/hex simplify encoding and
        decoding from and to byte slices by taking care of byte slice
        buffer management.
      * encoding: The methods base32.Encoding.WithPadding and
        base64.Encoding.WithPadding now panic if the padding argument
        is a negative value other than NoPadding.
      * encoding/json: Marshaling and encoding functionality now
        escapes '\b' and '\f' characters as \b and \f instead of \u0008
        and \u000c.
      * go/ast: The following declarations related to syntactic
        identifier resolution are now deprecated: Ident.Obj, Object,
        Scope, File.Scope, File.Unresolved, Importer, Package,
        NewPackage. In general, identifiers cannot be accurately
        resolved without type information. Consider, for example, the
        identifier K in T{K: ''}: it could be the name of a local
        variable if T is a map type, or the name of a field if T is a
        struct type. New programs should use the go/types package to
        resolve identifiers; see Object, Info.Uses, and Info.Defs for
        details.
      * go/ast: The new ast.Unparen function removes any enclosing
        parentheses from an expression.
      * go/types: The new Alias type represents type
        aliases. Previously, type aliases were not represented
        explicitly, so a reference to a type alias was equivalent to
        spelling out the aliased type, and the name of the alias was
        lost. The new representation retains the intermediate
        Alias. This enables improved error reporting (the name of a
        type alias can be reported), and allows for better handling of
        cyclic type declarations involving type aliases. In a future
        release, Alias types will also carry type parameter
        information. The new function Unalias returns the actual type
        denoted by an Alias type (or any other Type for that matter).
      * go/types: Because Alias types may break existing type switches
        that do not know to check for them, this functionality is
        controlled by a GODEBUG field named gotypesalias. With
        gotypesalias=0, everything behaves as before, and Alias types
        are never created. With gotypesalias=1, Alias types are created
        and clients must expect them. The default is gotypesalias=0. In
        a future release, the default will be changed to
        gotypesalias=1. Clients of go/types are urged to adjust their
        code as soon as possible to work with gotypesalias=1 to
        eliminate problems early.
      * go/types: The Info struct now exports the FileVersions map
        which provides per-file Go version information.
      * go/types: The new helper method PkgNameOf returns the local
        package name for the given import declaration.
      * go/types: The implementation of SizesFor has been adjusted to
        compute the same type sizes as the compiler when the compiler
        argument for SizesFor is 'gc'. The default Sizes implementation
        used by the type checker is now types.SizesFor('gc', 'amd64').
      * go/types: The start position (Pos) of the lexical environment
        block (Scope) that represents a function body has changed: it
        used to start at the opening curly brace of the function body,
        but now starts at the function's func token.
      * html/template: Javascript template literals may now contain Go
        template actions, and parsing a template containing one will no
        longer return ErrJSTemplate. Similarly the GODEBUG setting
        jstmpllitinterp no longer has any effect.
      * io: The new SectionReader.Outer method returns the ReaderAt,
        offset, and size passed to NewSectionReader.
      * log/slog: The new SetLogLoggerLevel function controls the level
        for the bridge between the `slog` and `log` packages. It sets
        the minimum level for calls to the top-level `slog` logging
        functions, and it sets the level for calls to `log.Logger` that
        go through `slog`.
      * math/big: The new method Rat.FloatPrec computes the number of
        fractional decimal digits required to represent a rational
        number accurately as a floating-point number, and whether
        accurate decimal representation is possible in the first place.
      * net: When io.Copy copies from a TCPConn to a UnixConn, it will
        now use Linux's splice(2) system call if possible, using the
        new method TCPConn.WriteTo.
      * net: The Go DNS Resolver, used when building with
        '-tags=netgo', now searches for a matching name in the Windows
        hosts file, located at %SystemRoot%\System32\drivers\etc\hosts,
        before making a DNS query.
      * net/http: The new functions ServeFileFS, FileServerFS, and
        NewFileTransportFS are versions of the existing ServeFile,
        FileServer, and NewFileTransport, operating on an fs.FS.
      * net/http: The HTTP server and client now reject requests and
        responses containing an invalid empty Content-Length
        header. The previous behavior may be restored by setting
        GODEBUG field httplaxcontentlength=1.
      * net/http: The new method Request.PathValue returns path
        wildcard values from a request and the new method
        Request.SetPathValue sets path wildcard values on a request.
      * net/http/cgi: When executing a CGI process, the PATH_INFO
        variable is now always set to the empty string or a value
        starting with a / character, as required by RFC 3875. It was
        previously possible for some combinations of Handler.Root and
        request URL to violate this requirement.
      * net/netip: The new AddrPort.Compare method compares two
        AddrPorts.
      * os: On Windows, the Stat function now follows all reparse
        points that link to another named entity in the system. It was
        previously only following IO_REPARSE_TAG_SYMLINK and
        IO_REPARSE_TAG_MOUNT_POINT reparse points.
      * os: On Windows, passing O_SYNC to OpenFile now causes write
        operations to go directly to disk, equivalent to O_SYNC on Unix
        platforms.
      * os: On Windows, the ReadDir, File.ReadDir, File.Readdir, and
        File.Readdirnames functions now read directory entries in
        batches to reduce the number of system calls, improving
        performance up to 30%.
      * os: When io.Copy copies from a File to a net.UnixConn, it will
        now use Linux's sendfile(2) system call if possible, using the
        new method File.WriteTo.
      * os/exec: On Windows, LookPath now ignores empty entries
        in %PATH%, and returns ErrNotFound (instead of ErrNotExist)
        if no executable file extension is found to resolve an
        otherwise-unambiguous name.
      * os/exec: On Windows, Command and Cmd.Start no longer call
        LookPath if the path to the executable is already absolute and
        has an executable file extension. In addition, Cmd.Start no
        longer writes the resolved extension back to the Path field, so
        it is now safe to call the String method concurrently with a
        call to Start.
      * reflect: The Value.IsZero method will now return true for a
        floating-point or complex negative zero, and will return true
        for a struct value if a blank field (a field named _) somehow
        has a non-zero value. These changes make IsZero consistent with
        comparing a value to zero using the language == operator.
      * reflect: The PtrTo function is deprecated, in favor of
        PointerTo.
      * reflect: The new function TypeFor returns the Type that
        represents the type argument T. Previously, to get the
        reflect.Type value for a type, one had to use
        reflect.TypeOf((*T)(nil)).Elem(). This may now be written as
        reflect.TypeFor[T]().
      * runtime/metrics: Four new histogram metrics
        /sched/pauses/stopping/gc:seconds,
        /sched/pauses/stopping/other:seconds,
        /sched/pauses/total/gc:seconds, and
        /sched/pauses/total/other:seconds provide additional details
        about stop-the-world pauses. The 'stopping' metrics report the
        time taken from deciding to stop the world until all goroutines
        are stopped. The 'total' metrics report the time taken from
        deciding to stop the world until it is started again.
      * runtime/metrics: The /gc/pauses:seconds metric is deprecated,
        as it is equivalent to the new /sched/pauses/total/gc:seconds
        metric.
      * runtime/metrics: /sync/mutex/wait/total:seconds now includes
        contention on runtime-internal locks in addition to sync.Mutex
        and sync.RWMutex.
      * runtime/pprof: Mutex profiles now scale contention by the
        number of goroutines blocked on the mutex. This provides a more
        accurate representation of the degree to which a mutex is a
        bottleneck in a Go program. For instance, if 100 goroutines are
        blocked on a mutex for 10 milliseconds, a mutex profile will
        now record 1 second of delay instead of 10 milliseconds of
        delay.
      * runtime/pprof: Mutex profiles also now include contention on
        runtime-internal locks in addition to sync.Mutex and
        sync.RWMutex. Contention on runtime-internal locks is always
        reported at runtime._LostContendedRuntimeLock. A future release
        will add complete stack traces in these cases.
      * runtime/pprof: CPU profiles on Darwin platforms now contain the
        process's memory map, enabling the disassembly view in the
        pprof tool.
      * runtime/trace: The execution tracer has been completely
        overhauled in this release, resolving several long-standing
        issues and paving the way for new use-cases for execution
        traces.
      * runtime/trace: Execution traces now use the operating system's
        clock on most platforms (Windows excluded) so it is possible to
        correlate them with traces produced by lower-level
        components. Execution traces no longer depend on the
        reliability of the platform's clock to produce a correct
        trace. Execution traces are now partitioned regularly
        on-the-fly and as a result may be processed in a streamable
        way. Execution traces now contain complete durations for all
        system calls. Execution traces now contain information about
        the operating system threads that goroutines executed on. The
        latency impact of starting and stopping execution traces has
        been dramatically reduced. Execution traces may now begin or
        end during the garbage collection mark phase.
      * runtime/trace: To allow Go developers to take advantage of
        these improvements, an experimental trace reading package is
        available at golang.org/x/exp/trace. Note that this package
        only works on traces produced by programs built with go1.22 at
        the moment. Please try out the package and provide feedback on
        the corresponding proposal issue.
      * runtime/trace: If you experience any issues with the new
        execution tracer implementation, you may switch back to the old
        implementation by building your Go program with
        GOEXPERIMENT=noexectracer2. If you do, please file an issue,
        otherwise this option will be removed in a future release.
      * slices: The new function Concat concatenates multiple slices.
      * slices: Functions that shrink the size of a slice (Delete,
        DeleteFunc, Compact, CompactFunc, and Replace) now zero the
        elements between the new length and the old length.
      * slices: Insert now always panics if the argument i is out of
        range. Previously it did not panic in this situation if there
        were no elements to be inserted.
      * syscall: The syscall package has been frozen since Go 1.4 and
        was marked as deprecated in Go 1.11, causing many editors to
        warn about any use of the package. However, some non-deprecated
        functionality requires use of the syscall package, such as the
        os/exec.Cmd.SysProcAttr field. To avoid unnecessary complaints
        on such code, the syscall package is no longer marked as
        deprecated. The package remains frozen to most new
        functionality, and new code remains encouraged to use
        golang.org/x/sys/unix or golang.org/x/sys/windows where
        possible.
      * syscall: On Linux, the new SysProcAttr.PidFD field allows
        obtaining a PID FD when starting a child process via
        StartProcess or os/exec.
      * syscall: On Windows, passing O_SYNC to Open now causes write
        operations to go directly to disk, equivalent to O_SYNC on Unix
        platforms.
      * testing/slogtest: The new Run function uses sub-tests to run
        test cases, providing finer-grained control.
      * Ports: Darwin: On macOS on 64-bit x86 architecture (the
        darwin/amd64 port), the Go toolchain now generates
        position-independent executables (PIE) by default. Non-PIE
        binaries can be generated by specifying the -buildmode=exe
        build flag. On 64-bit ARM-based macOS (the darwin/arm64 port),
        the Go toolchain already generates PIE by default. go1.22 is
        the last release that will run on macOS 10.15 Catalina. Go 1.23
        will require macOS 11 Big Sur or later.
      * Ports: Arm: The GOARM environment variable now allows you to
        select whether to use software or hardware floating
        point. Previously, valid GOARM values were 5, 6, or 7. Now
        those same values can be optionally followed by ,softfloat or
        ,hardfloat to select the floating-point implementation. This
        new option defaults to softfloat for version 5 and hardfloat
        for versions 6 and 7.
      * Ports: Loong64: The loong64 port now supports passing function
        arguments and results using registers. The linux/loong64 port
        now supports the address sanitizer, memory sanitizer, new-style
        linker relocations, and the plugin build mode.
      * OpenBSD go1.22 adds an experimental port to OpenBSD on
        big-endian 64-bit PowerPC (openbsd/ppc64).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221003");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225973");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225974");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227314");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230254");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019791.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0961ae5");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45289");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24783");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24784");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24785");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34158");
  script_set_attribute(attribute:"solution", value:
"Update the affected go1.22-openssl, go1.22-openssl-doc and / or go1.22-openssl-race packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24790");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.22-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.22-openssl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:go1.22-openssl-race");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'go1.22-openssl-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-doc-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-doc-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-race-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-race-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'go1.22-openssl-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-doc-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-doc-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-race-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-race-1.22.7.1-150600.13.3.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'go1.22-openssl-1.22.7.1-150600.13.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'go1.22-openssl-doc-1.22.7.1-150600.13.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'go1.22-openssl-race-1.22.7.1-150600.13.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'go1.22-openssl / go1.22-openssl-doc / go1.22-openssl-race');
}
