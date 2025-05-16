#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0211-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(203015);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/23");

  script_cve_id("CVE-2023-45142", "CVE-2024-22189");

  script_name(english:"openSUSE 15 Security Update : caddy (openSUSE-SU-2024:0211-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0211-1 advisory.

    Update to version 2.8.4:

      * cmd: fix regression in auto-detect of Caddyfile (#6362)
      * Tag v2.8.3 was mistakenly made on the v2.8.2 commit and is skipped

    Update to version 2.8.2:

      * cmd: fix auto-detetction of .caddyfile extension (#6356)
      * caddyhttp: properly sanitize requests for root path (#6360)
      * caddytls: Implement certmagic.RenewalInfoGetter

    Update to version 2.8.1:

      * caddyhttp: Fix merging consecutive `client_ip` or `remote_ip` matchers (#6350)
      * core: MkdirAll appDataDir in InstanceID with 0o700 (#6340)

    Update to version 2.8.0:

      * acmeserver: Add `sign_with_root` for Caddyfile (#6345)
      * caddyfile: Reject global request matchers earlier (#6339)
      * core: Fix bug in AppIfConfigured (fix #6336)
      * fix a typo (#6333)
      * autohttps: Move log WARN to INFO, reduce confusion (#6185)
      * reverseproxy: Support HTTP/3 transport to backend (#6312)
      * context: AppIfConfigured returns error; consider not-yet-provisioned modules (#6292)
      * Fix lint error about deprecated method in smallstep/certificates/authority
      * go.mod: Upgrade dependencies
      * caddytls: fix permission requirement with AutomationPolicy (#6328)
      * caddytls: remove ClientHelloSNICtxKey (#6326)
      * caddyhttp: Trace individual middleware handlers (#6313)
      * templates: Add `pathEscape` template function and use it in file browser (#6278)
      * caddytls: set server name in context (#6324)
      * chore: downgrade minimum Go version in go.mod (#6318)
      * caddytest: normalize the JSON config (#6316)
      * caddyhttp: New experimental handler for intercepting responses (#6232)
      * httpcaddyfile: Set challenge ports when http_port or https_port are used
      * logging: Add support for additional logger filters other than hostname (#6082)
      * caddyhttp: Log 4xx as INFO; 5xx as ERROR (close #6106)
      * caddyhttp: Alter log message when request is unhandled (close #5182)
      * reverseproxy: Pointer to struct when loading modules; remove LazyCertPool (#6307)
      * tracing: add trace_id var (`http.vars.trace_id` placeholder) (#6308)
      * go.mod: CertMagic v0.21.0
      * reverseproxy: Implement health_follow_redirects (#6302)
      * caddypki: Allow use of root CA without a key. Fixes #6290 (#6298)
      * go.mod: Upgrade to quic-go v0.43.1
      * reverseproxy: HTTP transport: fix PROXY protocol initialization (#6301)
      * caddytls: Ability to drop connections (close #6294)
      * httpcaddyfile: Fix expression matcher shortcut in snippets (#6288)
      * caddytls: Evict internal certs from cache based on issuer (#6266)
      * chore: add warn logs when using deprecated fields (#6276)
      * caddyhttp: Fix linter warning about deprecation
      * go.mod: Upgrade to quic-go v0.43.0
      * fileserver: Set 'Vary: Accept-Encoding' header (see #5849)
      * events: Add debug log
      * reverseproxy: handle buffered data during hijack (#6274)
      * ci: remove `android` and `plan9` from cross-build workflow (#6268)
      * run `golangci-lint run --fix --fast` (#6270)
      * caddytls: Option to configure certificate lifetime (#6253)
      * replacer: Implement `file.*` global replacements (#5463)
      * caddyhttp: Address some Go 1.20 features (#6252)
      * Quell linter (false positive)
      * reverse_proxy: Add grace_period for SRV upstreams to Caddyfile (#6264)
      * doc: add `verifier` in `ClientAuthentication` caddyfile marshaler doc (#6263)
      * caddytls: Add Caddyfile support for on-demand permission module (close #6260)
      * reverseproxy: Remove long-deprecated buffering properties
      * reverseproxy: Reuse buffered request body even if partially drained
      * reverseproxy: Accept EOF when buffering
      * logging: Fix default access logger (#6251)
      * fileserver: Improve Vary handling (#5849)
      * cmd: Only validate config is proper JSON if config slice has data (#6250)
      * staticresp: Use the evaluated response body for sniffing JSON content-type (#6249)
      * encode: Slight fix for the previous commit
      * encode: Improve Etag handling (fix #5849)
      * httpcaddyfile: Skip automate loader if disable_certs is specified (fix #6148)
      * caddyfile: Populate regexp matcher names by default (#6145)
      * caddyhttp: record num. bytes read when response writer is hijacked (#6173)
      * caddyhttp: Support multiple logger names per host (#6088)
      * chore: fix some typos in comments (#6243)
      * encode: Configurable compression level for zstd (#6140)
      * caddytls: Remove shim code supporting deprecated lego-dns (#6231)
      * connection policy: add `local_ip`  matcher (#6074)
      * reverseproxy: Wait for both ends of websocket to close (#6175)
      * caddytls: Upgrade ACMEz to v2; support ZeroSSL API; various fixes (#6229)
      * caddytls: Still provision permission module if ask is specified
      * fileserver: read etags from precomputed files (#6222)
      * fileserver: Escape # and ? in img src (fix #6237)
      * reverseproxy: Implement modular CA provider for TLS transport (#6065)
      * caddyhttp: Apply auto HTTPS redir to all interfaces (fix #6226)
      * cmd: Fix panic related to config filename (fix #5919)
      * cmd: Assume Caddyfile based on filename prefix and suffix (#5919)
      * admin: Make `Etag` a header, not a trailer (#6208)
      * caddyhttp: remove duplicate strings.Count in path matcher (fixes #6233) (#6234)
      * caddyconfig: Use empty struct instead of bool in map (close #6224) (#6227)
      * gitignore: Add rule for caddyfile.go (#6225)
      * chore: Fix broken links in README.md (#6223)
      * chore: Upgrade some dependencies (#6221)
      * caddyhttp: Add plaintext response to `file_server browse` (#6093)
      * admin: Use xxhash for etag (#6207)
      * modules: fix some typo in conments (#6206)
      * caddyhttp: Replace sensitive headers with REDACTED (close #5669)
      * caddyhttp: close quic connections when server closes (#6202)
      * reverseproxy: Use xxhash instead of fnv32 for LB (#6203)
      * caddyhttp: add http.request.local{,.host,.port} placeholder (#6182)
      * chore: remove repetitive word (#6193)
      * Added a null check to avoid segfault on rewrite query ops (#6191)
      * rewrite: `uri query` replace operation (#6165)
      * logging: support `ms` duration format and add docs (#6187)
      * replacer: use RWMutex to protect static provider (#6184)
      * caddyhttp: Allow `header` replacement with empty string (#6163)
      * vars: Make nil values act as empty string instead of `'<nil>'` (#6174)
      * chore: Update quic-go to v0.42.0 (#6176)
      * caddyhttp: Accept XFF header values with ports, when parsing client IP (#6183)
      * reverseproxy: configurable active health_passes and health_fails (#6154)
      * reverseproxy: Configurable forward proxy URL (#6114)
      * caddyhttp: upgrade to cel v0.20.0 (#6161)
      * chore: Bump Chroma to v2.13.0, includes new Caddyfile lexer (#6169)
      * caddyhttp: suppress flushing if the response is being buffered (#6150)
      * chore: encode: use FlushError instead of Flush (#6168)
      * encode: write status immediately when status code is informational (#6164)
      * httpcaddyfile: Keep deprecated `skip_log` in directive order (#6153)
      * httpcaddyfile: Add `RegisterDirectiveOrder` function for plugin authors (#5865)
      * rewrite: Implement `uri query` operations (#6120)
      * fix struct names (#6151)
      * fileserver: Preserve query during canonicalization redirect (#6109)
      * logging: Implement `log_append` handler (#6066)
      * httpcaddyfile: Allow nameless regexp placeholder shorthand (#6113)
      * logging: Implement `append` encoder, allow flatter filters config (#6069)
      * ci: fix the integration test `TestLeafCertLoaders` (#6149)
      * vars: Allow overriding `http.auth.user.id` in replacer as a special case (#6108)
      * caddytls: clientauth: leaf verifier: make trusted leaf certs source pluggable (#6050)
      * cmd: Adjust config load logs/errors (#6032)
      * reverseproxy: SRV dynamic upstream failover (#5832)
      * ci: bump golangci/golangci-lint-action from 3 to 4 (#6141)
      * core: OnExit hooks (#6128)
      * cmd: fix the output of the `Usage` section (#6138)
      * caddytls: verifier: caddyfile: re-add Caddyfile support (#6127)
      * acmeserver: add policy field to define allow/deny rules (#5796)
      * reverseproxy: cookie should be Secure and SameSite=None when TLS (#6115)
      * caddytest: Rename adapt tests to `*.caddyfiletest` extension (#6119)
      * tests: uses testing.TB interface for helper to be able to use test server in benchmarks. (#6103)
      * caddyfile: Assert having a space after heredoc marker to simply check (#6117)
      * chore: Update Chroma to get the new Caddyfile lexer (#6118)
      * reverseproxy: use context.WithoutCancel (#6116)
      * caddyfile: Reject directives in the place of site addresses (#6104)
      * caddyhttp: Register post-shutdown callbacks (#5948)
      * caddyhttp: Only attempt to enable full duplex for HTTP/1.x (#6102)
      * caddyauth: Drop support for `scrypt` (#6091)
      * Revert 'caddyfile: Reject long heredoc markers (#6098)' (#6100)
      * caddyauth: Rename `basicauth` to `basic_auth` (#6092)
      * logging: Inline Caddyfile syntax for `ip_mask` filter (#6094)
      * caddyfile: Reject long heredoc markers (#6098)
      * chore: Rename CI jobs, run on M1 mac (#6089)
      * fix: add back text/*
      * fix: add more media types to the compressed by default list
      * acmeserver: support specifying the allowed challenge types (#5794)
      * matchers: Drop `forwarded` option from `remote_ip` matcher (#6085)
      * caddyhttp: Test cases for `%2F` and `%252F` (#6084)
      * fileserver: Browse can show symlink target if enabled (#5973)
      * core: Support NO_COLOR env var to disable log coloring (#6078)
      * Update comment in setcap helper script
      * caddytls: Make on-demand 'ask' permission modular (#6055)
      * core: Add `ctx.Slogger()` which returns an `slog` logger (#5945)
      * chore: Update quic-go to v0.41.0, bump Go minimum to 1.21 (#6043)
      * chore: enabling a few more linters (#5961)
      * caddyfile: Correctly close the heredoc when the closing marker appears immediately (#6062)
      * caddyfile: Switch to slices.Equal for better performance (#6061)
      * tls: modularize trusted CA providers (#5784)
      * logging: Automatic `wrap` default for `filter` encoder (#5980)
      * caddyhttp: Fix panic when request missing ClientIPVarKey (#6040)
      * caddyfile: Normalize & flatten all unmarshalers (#6037)
      * cmd: reverseproxy: log: use caddy logger (#6042)
      * matchers: `query` now ANDs multiple keys (#6054)
      * caddyfile: Add heredoc support to `fmt` command (#6056)
      * refactor: move automaxprocs init in caddycmd.Main()
      * caddyfile: Allow heredoc blank lines (#6051)
      * httpcaddyfile: Add optional status code argument to `handle_errors` directive (#5965)
      * httpcaddyfile: Rewrite `root` and `rewrite` parsing to allow omitting matcher (#5844)
      * fileserver: Implement caddyfile.Unmarshaler interface (#5850)
      * reverseproxy: Add `tls_curves` option to HTTP transport (#5851)
      * caddyhttp: Security enhancements for client IP parsing (#5805)
      * replacer: Fix escaped closing braces (#5995)
      * filesystem: Globally declared filesystems, `fs` directive (#5833)
      * ci/cd: use the build tag `nobadger` to exclude badgerdb (#6031)
      * httpcaddyfile: Fix redir <to> html (#6001)
      * httpcaddyfile: Support client auth verifiers (#6022)
      * tls: add reuse_private_keys (#6025)
      * reverseproxy: Only change Content-Length when full request is buffered (#5830)
      * Switch Solaris-derivatives away from listen_unix (#6021)
      * chore: check against errors of `io/fs` instead of `os` (#6011)
      * caddyhttp: support unix sockets in `caddy respond` command (#6010)
      * fileserver: Add total file size to directory listing (#6003)
      * httpcaddyfile: Fix cert file decoding to load multiple PEM in one file (#5997)
      * cmd: use automaxprocs for better perf in containers (#5711)
      * logging: Add `zap.Option` support (#5944)
      * httpcaddyfile: Sort skip_hosts for deterministic JSON (#5990)
      * metrics: Record request metrics on HTTP errors (#5979)
      * go.mod: Updated quic-go to v0.40.1 (#5983)
      * fileserver: Enable compression for command by default (#5855)
      * fileserver: New --precompressed flag (#5880)
      * caddyhttp: Add `uuid` to access logs when used (#5859)
      * proxyprotocol: use github.com/pires/go-proxyproto (#5915)
      * cmd: Preserve LastModified date when exporting storage (#5968)
      * core: Always make AppDataDir for InstanceID (#5976)
      * chore: cross-build for AIX (#5971)
      * caddytls: Sync distributed storage cleaning (#5940)
      * caddytls: Context to DecisionFunc (#5923)
      * tls: accept placeholders in string values of certificate loaders (#5963)
      * templates: Offically make templates extensible (#5939)
      * http2 uses new round-robin scheduler (#5946)
      * panic when reading from backend failed to propagate stream error (#5952)
      * chore: Bump otel to v1.21.0. (#5949)
      * httpredirectlistener: Only set read limit for when request is HTTP (#5917)
      * fileserver: Add .m4v for browse template icon
      * Revert 'caddyhttp: Use sync.Pool to reduce lengthReader allocations (#5848)' (#5924)
      * go.mod: update quic-go version to v0.40.0 (#5922)
      * update quic-go to v0.39.3 (#5918)
      * chore: Fix usage pool comment (#5916)
      * test: acmeserver: add smoke test for the ACME server directory (#5914)
      *  Upgrade acmeserver to github.com/go-chi/chi/v5 (#5913)
      * caddyhttp: Adjust `scheme` placeholder docs (#5910)
      * go.mod: Upgrade quic-go to v0.39.1
      * go.mod: CVE-2023-45142 Update opentelemetry (#5908)
      * templates: Delete headers on `httpError` to reset to clean slate (#5905)
      * httpcaddyfile: Remove port from logger names (#5881)
      * core: Apply SO_REUSEPORT to UDP sockets (#5725)
      * caddyhttp: Use sync.Pool to reduce lengthReader allocations (#5848)
      * cmd: Add newline character to version string in CLI output (#5895)
      * core: quic listener will manage the underlying socket by itself (#5749)
      * templates: Clarify `include` args docs, add `.ClientIP` (#5898)
      * httpcaddyfile: Fix TLS automation policy merging with get_certificate (#5896)
      * cmd: upgrade: resolve symlink of the executable (#5891)
      * caddyfile: Fix variadic placeholder false positive when token contains `:` (#5883)

    - CVEs:
      * CVE-2024-22189 (boo#1222468)
      * CVE-2023-45142

    - Remove the manual user/group provides: the package uses
      sysusers.d; the auto-provides were not working due to the broken
      go_provides.

    - Provide user and group (due to RPM 4.19)
    - Update caddy.sysusers to also create a group

    - Update to version 2.7.6:

      * caddytls: Sync distributed storage cleaning (#5940)
      * caddytls: Context to DecisionFunc (#5923)
      * tls: accept placeholders in string values of certificate loaders (#5963)
      * templates: Offically make templates extensible (#5939)
      * http2 uses new round-robin scheduler (#5946)
      * panic when reading from backend failed to propagate stream error (#5952)
      * chore: Bump otel to v1.21.0. (#5949)
      * httpredirectlistener: Only set read limit for when request is HTTP (#5917)
      * fileserver: Add .m4v for browse template icon
      * Revert 'caddyhttp: Use sync.Pool to reduce lengthReader allocations (#5848)' (#5924)
      * go.mod: update quic-go version to v0.40.0 (#5922)
      * update quic-go to v0.39.3 (#5918)
      * chore: Fix usage pool comment (#5916)
      * test: acmeserver: add smoke test for the ACME server directory (#5914)
      * Upgrade acmeserver to github.com/go-chi/chi/v5 (#5913)
      * caddyhttp: Adjust `scheme` placeholder docs (#5910)
      * go.mod: Upgrade quic-go to v0.39.1
      * go.mod: CVE-2023-45142 Update opentelemetry (#5908)
      * templates: Delete headers on `httpError` to reset to clean slate (#5905)
      * httpcaddyfile: Remove port from logger names (#5881)
      * core: Apply SO_REUSEPORT to UDP sockets (#5725)
      * caddyhttp: Use sync.Pool to reduce lengthReader allocations (#5848)
      * cmd: Add newline character to version string in CLI output (#5895)
      * core: quic listener will manage the underlying socket by itself (#5749)
      * templates: Clarify `include` args docs, add `.ClientIP` (#5898)
      * httpcaddyfile: Fix TLS automation policy merging with get_certificate (#5896)
      * cmd: upgrade: resolve symlink of the executable (#5891)
      * caddyfile: Fix variadic placeholder false positive when token contains `:` (#5883)

    - Update to version 2.7.5:

      * admin: Respond with 4xx on non-existing config path (#5870)
      * ci: Force the Go version for govulncheck (#5879)
      * fileserver: Set canonical URL on browse template (#5867)
      * tls: Add X25519Kyber768Draft00 PQ 'curve' behind build tag (#5852)
      * reverseproxy: Add more debug logs (#5793)
      * reverseproxy: Fix `least_conn` policy regression (#5862)
      * reverseproxy: Add logging for dynamic A upstreams (#5857)
      * reverseproxy: Replace health header placeholders (#5861)
      * httpcaddyfile: Sort TLS SNI matcher for deterministic JSON output (#5860)
      * cmd: Fix exiting with custom status code, add `caddy -v` (#5874)
      * reverseproxy: fix parsing Caddyfile fails for unlimited request/response buffers (#5828)
      * reverseproxy: Fix retries on 'upstreams unavailable' error (#5841)
      * httpcaddyfile: Enable TLS for catch-all site if `tls` directive is specified (#5808)
      * encode: Add `application/wasm*` to the default content types (#5869)
      * fileserver: Add command shortcuts `-l` and `-a` (#5854)
      * go.mod: Upgrade dependencies incl. x/net/http
      * templates: Add dummy `RemoteAddr` to `httpInclude` request, proxy compatibility (#5845)
      * reverseproxy: Allow fallthrough for response handlers without routes (#5780)
      * fix: caddytest.AssertResponseCode error message (#5853)
      * caddyhttp: Use LimitedReader for HTTPRedirectListener
      * fileserver: browse template SVG icons and UI tweaks (#5812)
      * reverseproxy: fix nil pointer dereference in AUpstreams.GetUpstreams (#5811)
      * httpcaddyfile: fix placeholder shorthands in named routes (#5791)
      * cmd: Prevent overwriting existing env vars with `--envfile` (#5803)
      * ci: Run govulncheck (#5790)
      * logging: query filter for array of strings (#5779)
      * logging: Clone array on log filters, prevent side-effects (#5786)
      * fileserver: Export BrowseTemplate
      * ci: ensure short-sha is exported correctly on all platforms (#5781)
      * caddyfile: Fix case where heredoc marker is empty after newline (#5769)
      * go.mod: Update quic-go to v0.38.0 (#5772)
      * chore: Appease gosec linter (#5777)
      * replacer: change timezone to UTC for 'time.now.http' placeholders (#5774)
      * caddyfile: Adjust error formatting (#5765)
      * update quic-go to v0.37.6 (#5767)
      * httpcaddyfile: Stricter errors for site and upstream address schemes (#5757)
      * caddyfile: Loosen heredoc parsing (#5761)
      * fileserver: docs: clarify the ability to produce JSON array with `browse` (#5751)
      * fix package typo (#5764)

    - Switch to sysuser for user setup

    Update to version 2.7.4:

      * go.mod: Upgrade CertMagic and quic-go
      * reverseproxy: Always return new upstreams (fix #5736) (#5752)
      * ci: use gci linter (#5708)
      * fileserver: Slightly more fitting icons
      * cmd: Require config for caddy validate (fix #5612) (#5614)
      * caddytls: Update docs for on-demand config
      * fileserver: Don't repeat error for invalid method inside error context (#5705)
      * ci: Update to Go 1.21 (#5719)
      * ci: Add riscv64 (64-bit RISC-V) to goreleaser (#5720)
      * go.mod: Upgrade golang.org/x/net to 0.14.0 (#5718)
      * ci: Use gofumpt to format code (#5707)
      * templates: Fix httpInclude (fix #5698)

    Update to version 2.7.3:

      * go.mod: Upgrade to quic-go v0.37.3
      * cmd: Split unix sockets for admin endpoint addresses (#5696)
      * reverseproxy: do not parse upstream address too early if it contains replaceble parts (#5695)
      * caddyfile: check that matched key is not a substring of the replacement key (#5685)
      * chore: use `--clean` instead of `--rm-dist` for goreleaser (#5691)
      * go.mod: Upgrade quic-go to v0.37.2 (fix  #5680)
      * fileserver: browse: Render SVG images in grid

    - Update to version 2.7.2:
      * reverseproxy: Fix hijack ordering which broke websockets (#5679)
      * httpcaddyfile: Fix `string does not match ~[]E` error (#5675)
      * encode: Fix infinite recursion (#5672)
      * caddyhttp: Make use of `http.ResponseController` (#5654)
      * go.mod: Upgrade dependencies esp. smallstep/certificates
      * core: Allow loopback hosts for admin endpoint (fix #5650) (#5664)
      * httpcaddyfile: Allow `hostnames` & logger name overrides for log directive (#5643)
      * reverseproxy: Connection termination cleanup (#5663)
      * go.mod: Use quic-go 0.37.1
      * reverseproxy: Export ipVersions type (#5648)
      * go.mod: Use latest CertMagic (v0.19.1)
      * caddyhttp: Preserve original error (fix #5652)
      * fileserver: add lazy image loading (#5646)
      * go.mod: Update quic-go to v0.37.0, bump to Go 1.20 minimum (#5644)
      * core: Refine mutex during reloads (fix #5628) (#5645)
      * go.mod: update quic-go to v0.36.2 (#5636)
      * fileserver: Tweak grid view of browse template
      * fileserver: add `export-template` sub-command to `file-server` (#5630)
      * caddyfile: Fix comparing if two tokens are on the same line (#5626)
      * caddytls: Reuse certificate cache through reloads (#5623)
      * Minor tweaks to security.md
      * reverseproxy: Pointer receiver
      * caddyhttp: Trim dot/space only on Windows (fix #5613)
      * update quic-go to v0.36.1 (#5611)
      * caddyconfig: Specify config adapter for HTTP loader (close #5607)
      * core: Embed net.UDPConn to gain optimizations (#5606)
      * chore: remove deprecated property `rlcp` in goreleaser config (#5608)
      * core: Skip `chmod` for abstract unix sockets (#5596)
      * core: Add optional unix socket file permissions (#4741)
      * reverseproxy: Honor `tls_except_port` for active health checks (#5591)
      * Appease linter
      * Fix compile on Windows, hopefully
      * core: Properly preserve unix sockets (fix  #5568)
      * go.mod: Upgrade CertMagic for hotfix
      * go.mod: Upgrade some dependencies
      * chore: upgrade otel (#5586)
      * go.mod: Update quic-go to v0.36.0 (#5584)
      * reverseproxy: weighted_round_robin load balancing policy (#5579)
      * reverseproxy: Experimental streaming timeouts (#5567)
      * chore: remove refs of deprecated io/ioutil (#5576)
      * headers: Allow `>` to defer shortcut for replacements (#5574)
      * caddyhttp: Support custom network for HTTP/3 (#5573)
      * reverseproxy: Fix parsing of source IP in case it's an ipv6 address (#5569)
      * fileserver: browse: Better grid layout (#5564)
      * caddytls: Clarify some JSON config docs
      * cmd: Implement storage import/export (#5532)
      * go.mod: Upgrade quic-go to 0.35.1
      * update quic-go to v0.35.0 (#5560)
      * templates: Add `readFile` action that does not evaluate templates (#5553)
      * caddyfile: Track import name instead of modifying filename (#5540)
      * core: Use SO_REUSEPORT_LB on FreeBSD (#5554)
      * caddyfile: Do not replace import tokens if they are part of a snippet (#5539)
      * fileserver: Don't set Etag if mtime is 0 or 1 (close #5548) (#5550)
      * fileserver: browse: minor tweaks for grid view, dark mode (#5545)
      * fileserver: Only set Etag if not already set (fix #5546) (#5547)
      * fileserver: Fix file browser breadcrumb font (#5543)
      * caddyhttp: Fix h3 shutdown (#5541)
      * fileserver: More filetypes for browse icons
      * fileserver: Fix file browser footer in grid mode (#5536)
      * cmd: Avoid spammy log messages (fix #5538)
      * httpcaddyfile: Sort Caddyfile slice
      * caddyhttp: Implement named routes, `invoke` directive (#5107)
      * rewrite: use escaped path, fix #5278 (#5504)
      * headers: Add > Caddyfile shortcut for enabling defer (#5535)
      * go.mod: Upgrade several dependencies
      * reverseproxy: Expand port ranges to multiple upstreams in CLI + Caddyfile (#5494)
      * fileserver: Use EscapedPath for browse (#5534)
      * caddyhttp: Refactor cert Managers (fix #5415) (#5533)
      * Slightly more helpful error message
      * caddytls: Check for nil ALPN; close #5470 (#5473)
      * cmd: Reduce spammy logs from --watch
      * caddyhttp: Add a getter for Server.name (#5531)
      * caddytls: Configurable fallback SNI (#5527)
      * caddyhttp: Update quic's TLS configs after reload (#5517) (fix #4849)
      * Add doc comment about changing admin endpoint
      * feature: watch include directory (#5521)
      * chore: remove deprecated linters (#5525)
      * go.mod: Upgrade CertMagic again
      * go.mod: Upgrade CertMagic
      * reverseproxy: Optimize base case for least_conn and random_choose policies (#5487)
      * reverseproxy: Fix active health check header canonicalization, refactor (#5446)
      * reverseproxy: Add `fallback` for some policies, instead of always random (#5488)
      * logging: Actually honor the SoftStart parameter
      * logging: Soft start for net writer (close #5520)
      * fastcgi: Fix `capture_stderr` (#5515)
      * acmeserver: Configurable `resolvers`, fix smallstep deprecations (#5500)
      * go.mod: Update some dependencies
      * logging: Add traceID field to access logs when tracing is active (#5507)
      * caddyhttp: Impl `ResponseWriter.Unwrap()`, prep for Go 1.20's `ResponseController` (#5509)
      * reverseproxy: Fix reinitialize upstream healthy metrics (#5498)
      * fix some comments (#5508)
      * templates: Add `fileStat` function (#5497)
      * caddyfile: Stricter parsing, error for brace on new line (#5505)
      * core: Return default logger if no modules loaded
      * celmatcher: Implement `pkix.Name` conversion to string (#5492)
      * chore: Adjustments to CI caching (#5495)
      * reverseproxy: Remove deprecated `lookup_srv` (#5396)
      * cmd: Support `'` quotes in envfile parsing (#5437)
      * Update contributing guidelines (#5466)
      * caddyhttp: Serve http2 when listener wrapper doesn't return *tls.Conn (#4929)
      * reverseproxy: Add `query` and `client_ip_hash` lb policies (#5468)
      * cmd: Create pidfile before config load (close #5477)
      * fileserver: Add color-scheme meta tag (#5475)
      * proxyprotocol: Add PROXY protocol support to `reverse_proxy`, add HTTP listener wrapper (#5424)
      * reverseproxy: Add mention of which half a copyBuffer err comes from (#5472)
      * caddyhttp: Log request body bytes read (#5461)
      * log: Make sink logs encodable (#5441)
      * caddytls: Eval replacer on automation policy subjects (#5459)
      * headers: Support deleting all headers as first op (#5464)
      * replacer: Add HTTP time format (#5458)
      * reverseproxy: Header up/down support for CLI command (#5460)
      * caddyhttp: Determine real client IP if trusted proxies configured (#5104)
      * httpcaddyfile: Adjust path matcher sorting to solve for specificity (#5462)
      * caddytls: Zero out throttle window first (#5443)
      * ci: add `--yes` to cosign arguments (#5440)
      * reverseproxy: Reset Content-Length to prevent FastCGI from hanging (#5435)
      * caddytls: Allow on-demand w/o ask for internal-only
      * caddytls: Require 'ask' endpoint for on-demand TLS
      * fileserver: New file browse template (#5427)
      * go.mod: Upgrade dependencies
      * tracing: Support autoprop from OTEL_PROPAGATORS (#5147)
      * caddyhttp: Enable 0-RTT QUIC (#5425)
      * encode: flush status code when hijacked. (#5419)
      * fileserver: Remove trailing slash on fs filenames (#5417)
      * core: Eliminate unnecessary shutdown delay on Unix (#5413)
      * caddyhttp: Fix `vars_regexp` matcher with placeholders (#5408)
      * context: Rename func to `AppIfConfigured` (#5397)
      * reverseproxy: allow specifying ip version for dynamic `a` upstream (#5401)
      * caddyfile: Fix heredoc fuzz crasher, drop trailing newline (#5404)
      * caddyfile: Implement heredoc support (#5385)
      * cmd: Expand cobra support, add short flags (#5379)
      * ci: Update minimum Go version to 1.19
      * go.mod: Upgrade quic-go to v0.33.0 (Go 1.19 min)
      * reverseproxy: refactor HTTP transport layer (#5369)
      * caddytls: Relax the warning for on-demand (#5384)
      * cmd: Strict unmarshal for validate (#5383)
      * caddyfile: Implement variadics for import args placeholders (#5249)
      * cmd: make `caddy fmt` hints more clear (#5378)
      * cmd: Adjust documentation for commands (#5377)


    - Update to version 2.6.4:

      * reverseproxy: Don't buffer chunked requests (fix #5366) (#5367)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222468");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4POHOO6U2FW5XKZT7HPGZAJF7LQQW3W4/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2606b240");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45142");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-22189");
  script_set_attribute(attribute:"solution", value:
"Update the affected caddy, caddy-bash-completion, caddy-fish-completion and / or caddy-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45142");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caddy-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caddy-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:caddy-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'caddy-2.8.4-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'caddy-bash-completion-2.8.4-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'caddy-fish-completion-2.8.4-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'caddy-zsh-completion-2.8.4-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'caddy / caddy-bash-completion / caddy-fish-completion / etc');
}
