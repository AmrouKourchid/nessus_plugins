#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0003-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213540);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id(
    "CVE-2019-11254",
    "CVE-2020-15106",
    "CVE-2021-28235",
    "CVE-2023-47108",
    "CVE-2023-48795"
  );
  script_xref(name:"IAVA", value:"2024-A-0236");
  script_xref(name:"IAVA", value:"2024-A-0425-S");

  script_name(english:"openSUSE 15 Security Update : etcd (openSUSE-SU-2025:0003-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0003-1 advisory.

    Update to version 3.5.12:

      * Bump golang.org/x/crypto to v0.17+ to address CVE-2023-48795
      * test: fix TestHashKVWhenCompacting: ensure all goroutine finished
      * print error log when creating peer listener failed
      * mvcc: Printing etcd backend database related metrics inside scheduleCompaction function
      * dependency: update go version to 1.20.13
      * commit bbolt transaction if there is any pending deleting operations
      * add tests to test tx delete consistency.
      * Don't flock snapshot files
      * Backport adding digest for etcd base image.
      * Add a unit tests and missing flags in etcd help.
      * Add missing flag in etcd help.
      * Backport testutils.ExecuteUntil to 3.5 branch
      * member replace e2e test
      * Check if be is nil to avoid panic when be is overriden with nil by recoverSnapshotBackend on line 517
      * Don't redeclare err and snapshot variable, fixing validation of consistent index and closing database
    on defer
      * test: enable gofail in release e2e test.
      * [3.5] backport health check e2e tests.
      * tests: Extract e2e cluster setup to separate package

    - Update to version 3.5.11:

      * etcdserver: add linearizable_read check to readyz.
      * etcd: Update go version to 1.20.12
      * server: disable redirects in peer communication
      * etcdserver: add metric counters for livez/readyz health checks.
      * etcdserver: add livez and ready http endpoints for etcd.
      * http health check bug fixes
      * server: Split metrics and health code
      * server: Cover V3 health with tests
      * server: Refactor health checks
      * server: Run health check tests in subtests
      * server: Rename test case expect fields
      * server: Use named struct initialization in healthcheck test
      * Backport server: Don't follow redirects when checking peer urls.
      * Backport embed: Add tracing integration test.
      * Backport server: Have tracingExporter own resources it initialises.
      * Backport server: Add sampling rate to distributed tracing.
      * upgrade github.com/stretchr/testify,google.golang.org/genproto/googleapis/api,google.golang.org/grpc
    to make it consistent
      * CVE-2023-47108: Backport go.opentelemetry.io/otel@v1.20.0 and
    go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc@v0.46.0
      * github workflow: run arm64 tests on every push
      * etcd: upgrade go version from 1.20.10 to 1.20.11
      * bump bbolt to 1.3.8 for etcd 3.5
      * 3.5: upgrade gRPC-go to 1.58.3
      * Backport corrupt check test fix 'etcd server shouldn't wait for the ready notification infinitely on
    startup'
      * etcdserver: add cluster id check for hashKVHandler
      * [release-3.5]: upgrade gRPC-go to v1.52.0
      * backport #14125 to release-3.5: Update to grpc-1.47 (and fix the connection-string format)
      * Return to default write scheduler since golang.org/x/net@v0.11.0 started using round robin
      * Bump go to v1.20.10 Part of https://github.com/etcd-io/etcd/issues/16740
      * bump golang.org/x/net to 0.17.0 Part of https://github.com/etcd-io/etcd/issues/16740
      * etcd: upgrade go version to 1.20.9
      * Remove obsolete http 1.0 version.
      * fix:Ensure that go version is only defined in one file for release-3.5
      * Fix panic in etcd validate secure endpoints
      * dependency: bump golang to 1.20.8
      * Backport redirect metrics data into file to reduce output.
      * test.sh: increase timeout for grpcproxy test
      * test: add v3 curl test to cover maintenance hash/hashkv REST API
      * api: fix duplicate gateway url issue
      * pkg: add a verification on the pagebytes which must be > 0
      * tests: Backport deflake for TestWatchDelay
      * tests: Backport deflake for TestPageWriterRandom
      * Backport adding unit test for socket options.
      * Backport export reuse-port and reuse-address
      * Fix goword failure in rafthttp/transport.go.
      * Backport update to golang 1.20 minor release.
      * bump go version to 1.19.12
      * Update workflows to use makefile recipes for unit, integration & e2e-release.
      * Backport Makefile recipes for common test commands.
      * pkg/flags: fix UniqueURLs'Set to remove duplicates in UniqueURLs'uss
      * Backport fix to e2e release version identifcation.
      * Backport #14368 to v3.5
      * Follow up https://github.com/etcd-io/etcd/pull/16068#discussion_r1263667496
      * etcdserver: backport check scheduledCompactKeyName and finishedCompactKeyName before writing hash to
    release-3.5.
      * Backport #13577 Disable auth gracefully without impacting existing watchers.
      * bump go version to 1.19.11 to fix CVE GO-2023-1878
      * clientv3: create keepAliveCtxCloser goroutine only if ctx can be canceled
      * [3.5] etcdutl: fix db double closed
      * clientv3: remove v3.WithFirstKey() in Barrier.Wait()
      * update etcdctl flag description for snapshot restores
      * etcdutl: update description for --mark-compacted and --bump-revision flags in snapshot restore command
      * Adding optional revision bump and mark compacted to snapshot restore
      * Revert 'Merge pull request #16119 from natusameer/release-3.5'
      * Add e2e-arm64.yaml and tests-arm64.yaml to release-3.5 scheduled at 1.30
      * Backport .github/workflows: Read .go-version as a step and not separate workflow.
      * Add first unit test for authApplierV3
      * Early exit auth check on lease puts
      * remove stack log when etcdutl restore
      * etcdserver: fix corruption check when server has just been compacted
      * replace gobin with go install
      * [3.5] Backport updating go to latest patch release 1.19.10
      * add compact hash check to help
      * Fix test of clientv3/naming
      * clientv3/naming/endpoints: fix endpoints prefix bug fixes bug with multiple endpoints with same prefix
      * grpcproxy: fix memberlist results not update when proxy node down

    - Update to version 3.5.9:

      * Move go version to dedicated .go-version file
      * tests: e2e and integration test for timetolive
      * etcdserver: protect lease timetilive with auth
      * Backport go update to latest patch release 1.19.9.
      * Backport centralising go version for actions workflows.
      * server: backport 15743, improved description of --initial-cluster-state flag

    - Update to version 3.5.8:

      * etcdserver: Guarantee order of requested progress notifications
      * etcdserver: verify field 'username' and 'revision' present when decoding a JWT token
      * set zap logging to wsproxy
      * security: remove password after authenticating the user
      * test: add an e2e test to reproduce https://nvd.nist.gov/vuln/detail/CVE-2021-28235
      * bump golang to 1.19.8
      * server/auth: disallow creating empty permission ranges
      * chore: enable strict mode for test CI
      * Fixes: #15266 All docker images of Architecture show amd64
      * scripts: Add testing of etcd in local image in release workflow.
      * server: Fix defer function closure escape
      * tests: Test separate http port connection multiplexing
      * server: Add --listen-client-http-urls flag to allow running grpc server separate from http server
      * server: Pick one address that all grpc gateways connect to
      * server: Extract resolveUrl helper function
      * server: Separate client listener grouping from serving
      * refactor: Use proper variable names for urls
      * sever/auth: fix addUserWithNoOption of store_test
      * server/auth: fix auth panic bug when user changes password
      * Automated cherry-pick of #14860: Trigger release in current branch for github workflow case
      * server/embed: fix data race when start insecure grpc
      * server: Test watch restore
      * mvcc: update minRev when watcher stays synced
      * tests: Add v2 API to connection multiplexing test
      * tests: Add connection muiltiplexer testing
      * tests: Backport RunUtilCompletion
      * tests: Backport tls for etcdctl
      * tests: Extract e2e test utils
      * tests: Allow specifying http version in curl
      * tests: Refactor newClient args
      * tests: Refactor CURLPrefixArgs
      * Backport tls 1.3 support.
      * server: Switch back to random scheduler to improve resilience to watch starvation
      * test: Test etcd watch stream starvation under high read response load when sharing the same connection
      * tests: Allow configuring progress notify interval in e2e tests
      * Run go mod tidy
      * Updated go to 1.19.7.
      * Backport go_srcs_in_module changes and fix goword failures.
      * Formatted source code for go 1.19.6.
      *  Bump to go 1.19.6
      *  Bump golang.org/x/net to v0.7.0 to address CVE GO-2023-1571.
      * test:enhance the test case TestV3WatchProgressOnMemberRestart
      * clientv3: correct the nextRev on receving progress notification response
      * etcdserver: add failpoints walBeforeSync and walAfterSync
      * Fix regression in timestamp resolution
      * upgrade cockroachdb/datadriven to v1.0.2 to remove archived dependencies
      * bump github.com/stretchr/testify to v1.8.1
      * bump bbolt to v1.3.7 for release-3.5
      * netutil: consistently format ipv6 addresses
      * docker: remove nsswitch.conf

    - Update to version 3.5.7:

      * etcdserver: return membership.ErrIDNotFound when the memberID not found
      * etcdserver: process the scenaro of the last WAL record being partially synced to disk
      * update nsswitch.conf for 3.5
      * 3.5: remove the dependency on busybox
      * Remove dependency on gobin
      * resolve build error: parameter may not start with quote character '
      * remove .travis.yml
      * format the source code and tidy the dependencies using go 1.17.13
      * bump go version to 1.17.13
      * deps: bump golang.org/x/net to v0.4.0 to address CVEs
      * security: use distroless base image to address critical Vulnerabilities
      * cidc:  specify the correct branch name of release-3.5 in workflow for trivy nightly scan
      * Add trivy nightly scan for release-3.5
      * clientv3: revert the client side change in 14547
      * client/pkg/v3: fixes Solaris build of transport
      * etcdserver: fix nil pointer panic for readonly txn
      * Fix go fmt error
      * [3.5] Backport: non mutating requests pass through quotaKVServer when NOSPACE
      * etcdserver: intentionally set the memberID as 0 in corruption alarm

    - Update to version 3.5.6:

      * release: build with consistent paths
      * client/pkg/fileutil: add missing logger to {Create,Touch}DirAll
      * test: add test case to cover the CommonName based authentication
      * test: add certificate with root CommonName
      * clientv3: do not refresh token when using TLS CommonName based authentication
      * etcdserver: call the OnPreCommitUnsafe in unsafeCommit
      * add range flag for delete in etcdctl
      * server: add more context to panic message
      * fix:close conn
      * clientv3: fix the design & implementation of double barrier
      * test: added e2e test case for issue 14571: etcd doesn't load auth info when recovering from a snapshot
      * etcdserver: call refreshRangePermCache on Recover() in AuthStore. #14574
      * server: add a unit test case for authStore.Reocver() with empty rangePermCache
      * Backport #14591 to 3.5.
      * client/v3: Add backoff before retry when watch stream returns unavailable
      * etcdserver: added more debug log for the purgeFile goroutine
      * netutil: make a `raw` URL comparison part of the urlsEqual function
      * Apply suggestions from code review
      * netutil: add url comparison without resolver to URLStringsEqual
      * tests/Dockerfile: Switch to ubuntu 22.04 base
      * Makefile: Additional logic fix
      * *: avoid closing a watch with ID 0 incorrectly
      * tests: a test case for watch with auth token expiration
      * *: handle auth invalid token and old revision errors in watch
      * server/etcdmain: add configurable cipher list to gRPC proxy listener
      * Replace github.com/form3tech-oss/jwt-go with https://github.com/golang-jwt/jwt/v4

    - Update to version 3.5.5:

      * fix the flaky test fix_TestV3AuthRestartMember_20220913 for 3.5
      * etcdctl: fix move-leader for multiple endpoints
      * testing: fix TestOpenWithMaxIndex cleanup
      * server,test: refresh cache on each NewAuthStore
      * server/etcdmain: add build support for Apple M1
      * tests: Fix member id in CORRUPT alarm
      * server: Make corrtuption check optional and period configurable
      * server: Implement compaction hash checking
      * tests: Cover periodic check in tests
      * server: Refactor compaction checker
      * tests: Move CorruptBBolt to testutil
      * tests: Rename corruptHash to CorruptBBolt
      * tests: Unify TestCompactionHash and extend it to also Delete keys and Defrag
      * tests: Add tests for HashByRev HTTP API
      * tests: Add integration tests for compact hash
      * server: Cache compaction hash for HashByRev API
      * server: Extract hasher to separate interface
      * server: Remove duplicated compaction revision
      * server: Return revision range that hash was calcualted for
      * server: Store real rv range in hasher
      * server: Move adjusting revision to hasher
      * server: Pass revision as int
      * server: Calculate hash during compaction
      * server: Fix range in mock not returning same number of keys and values
      * server: Move reading KV index inside scheduleCompaction function
      * server: Return error from scheduleCompaction
      * server: Refactor hasher
      * server: Extract kvHash struct
      * server: Move unsafeHashByRev to new hash.go file
      * server: Extract unsafeHashByRev function
      * server: Test HashByRev values to make sure they don't change
      * server: Cover corruptionMonitor with tests
      * server: Extract corruption detection to dedicated struct
      * server: Extract triggerCorruptAlarm to function
      * move consistent_index forward when executing alarmList operation
      * fix the potential data loss for clusters with only one member
      * [backport 3.5] server: don't panic in readonly serializable txn
      * Backport of pull/14354 to 3.5.5
      * Refactor the keepAliveListener and keepAliveConn
      * clientv3: close streams after use in lessor keepAliveOnce method
      * Change default sampling rate from 100% to 0%
      * Fix the failure in TestEndpointSwitchResolvesViolation
      * update all related dependencies
      * move setupTracing into a separate file config_tracing.go
      * etcdserver: bump OpenTelemetry to 1.0.1
      * Change default sampling rate from 100% to 0%
      * server/auth: protect rangePermCache with a RW lock
      * Improve error message for incorrect values of ETCD_CLIENT_DEBUG
      * add e2e test cases to cover the maxConcurrentStreams
      * Add flag `--max-concurrent-streams` to set the max concurrent stream each client can open at a time
      * add the uint32Value data type
      * Client: fix check for WithPrefix op
      * client/v3: do not overwrite authTokenBundle on dial
      * restrict the max size of each WAL entry to the remaining size of the file
      * Add FileReader and FileBufReader utilities
      * Backport two lease related bug fixes to 3.5
      * scripts: Detect staged files before building release
      * scripts: Avoid additional repo clone
      * Make DRY_RUN explicit
      * scripts: Add tests for release scripts
      * server/auth: enable tokenProvider if recoved store enables auth
      * Update golang.org/x/crypto to latest

    - Update to version 3.5.4:

      * Update conssitent_index when applying fails
      * Add unit test for canonical SRV records
      * Revert 'trim the suffix dot from the srv.Target for etcd-client DNS lookup'

    - add variable ETCD_OPTIONS to both service unit and configuration file
      this allows the user to easily add things like '--enable-v2=true'

    - Update to version 3.5.3:

      https://github.com/etcd-io/etcd/compare/v3.5.2...v3.5.3
      * clientv3: disable mirror auth test with proxy
      * cv3/mirror: Fetch the most recent prefix revision
      * set backend to cindex before recovering the lessor in applySnapshot
      * support linearizable renew lease
      * clientv3: filter learners members during autosync
      * etcdserver: upgrade the golang.org/x/crypto dependency
      * fix the data inconsistency issue by adding a txPostLockHook into the backend
      * server: Save consistency index and term to backend even when they decrease
      * server: Add verification of whether lock was called within out outside of apply
      * go.mod: Upgrade to prometheus/client_golang v1.11.1
      * server: Use default logging configuration instead of zap production one
      * Fix offline defrag
      * backport 3.5: #13676 load all leases from backend
      * server/storage/backend: restore original bolt db options after defrag
      * always print raft term in decimal when displaying member list in json
      * enhance health check endpoint to support serializable request
      * trim the suffix dot from the srv.Target for etcd-client DNS lookup

    - Drop ETCD_UNSUPPORTED_ARCH=arm64 from sysconfig as ARM64 is now officially supported
    - Update etcd.conf variables
    - Add the new etcdutl into separate subpackage

    - Update to version 3.5.2:

      * Update dep: require gopkg.in/yaml.v2 v2.2.8 -> v2.4.0 due to: CVE-2019-11254.
      * fix runlock bug
      * server: Require either cluster version v3.6 or --experimental-enable-lease-checkpoint-persist to
    persist lease remainingTTL
      * etcdserver,integration: Store remaining TTL on checkpoint
      * lease,integration: add checkpoint scheduling after leader change
      * set the backend again after recovering v3 backend from snapshot
      * *: implement a retry logic for auth old revision in the client
      * client/v3: refresh the token when ErrUserEmpty is received while retrying
      * server/etcdserver/api/etcdhttp: exclude the same alarm type activated by multiple peers
      * storage/backend: Add a gauge to indicate if defrag is active (backport from 3.6)

    - Update to version 3.5.1:

      * version: 3.5.1
      * Dockerfile: bump debian bullseye-20210927
      * client: Use first endpoint as http2 authority header
      * tests: Add grpc authority e2e tests
      * client: Add grpc authority header integration tests
      * tests: Allow configuring integration tests to use TCP
      * test: Use unique number for grpc port
      * tests: Cleanup member interface by exposing Bridge directly
      * tests: Make using bridge optional
      * tests: Rename grpcAddr to grpcURL to imply that it includes schema
      * tests: Remove bridge dependency on unix
      * Decouple prefixArgs from os.Env dependency
      * server: Ensure that adding and removing members handle storev2 and backend out of sync
      * Stop using tip golang version in CI
      * fix self-signed-cert-validity parameter cannot be specified in the config file
      * fix health endpoint not usable when authentication is enabled
      * workflows: remove ARM64 job for maintenance

    - Update to version 3.5.0:

      * See link below, diff is too big
        https://github.com/etcd-io/etcd/compare/v3.4.16...v3.5.0

    - Added hardening to systemd service(s) (boo#1181400)

    - Change to sysuser-tools to create system user

    - Update to version 3.4.16:

      * Backport-3.4 exclude alarms from health check conditionally
      * etcdserver/mvcc: update trace.Step condition
      * Backport-3.4 etcdserver/util.go: reduce memory when logging range requests
      * .travis,Makefile,functional: Bump go 1.12 version to v1.12.17
      * integration: Fix 'go test --tags cluster_proxy --timeout=30m -v ./integration/...'
      * pkg/tlsutil: Adjust cipher suites for go 1.12
      * Fix pkg/tlsutil (test) to not fail on 386.
      * bill-of-materials.json: Update golang.org/x/sys
      * .travis,test: Turn race off in Travis for go version 1.15
      * integration : fix TestTLSClientCipherSuitesMismatch in go1.13
      * vendor: Run go mod vendor
      * go.mod,go.sum: Bump github.com/creack/pty that includes patch
      * go.mod,go.sum: Comply with go v1.15
      * etcdserver,wal: Convert int to string using rune()
      * integration,raft,tests: Comply with go v1.15 gofmt
      * .travis.yml: Test with go v1.15.11
      * pkpkg/testutil/leak.go: Allowlist created by testing.runTests.func1
      * vendor: Run go mod vendor
      * go.sum, go.mod: Run go mod tidy with go 1.12
      * go.mod: Pin go to 1.12 version
      * etcdserver: fix incorrect metrics generated when clients cancel watches
      * integration: relax leader timeout from 3s to 4s
      * etcdserver: when using --unsafe-no-fsync write data
      * server: Added config parameter experimental-warning-apply-duration
      * etcdserver: Fix PeerURL validation

    - update etcd.service: avoid args from commandline and environment
      as it leads to start failure (boo#1183703)

    - Update to version 3.4.15:

      * [Backport-3.4] etcdserver/api/etcdhttp: log successful etcd server side health check in debug level
      * etcdserver: Fix 64 KB websocket notification message limit
      * vendor: bump gorilla/websocket
      * pkg/fileutil: fix F_OFD_ constants

    - Update to version 3.4.14:

      * pkg/netutil: remove unused 'iptables' wrapper
      * tools/etcd-dump-metrics: validate exec cmd args
      * clientv3: get AuthToken automatically when clientConn is ready.
      * etcdserver: add ConfChangeAddLearnerNode to the list of config changes
      * integration: add flag WatchProgressNotifyInterval in integration test

    - Update to version 3.4.13:

      * pkg: file stat warning
      * Automated cherry pick of #12243 on release 3.4
      * version: 3.4.12
      * etcdserver: Avoid panics logging slow v2 requests in integration tests
      * version: 3.4.11
      * Revert 'etcdserver/api/v3rpc: 'MemberList' never return non-empty ClientURLs'
      * *: fix backport of PR12216
      * *: add experimental flag for watch notify interval
      * clientv3: remove excessive watch cancel logging
      * etcdserver: add OS level FD metrics
      * pkg/runtime: optimize FDUsage by removing sort
      * clientv3: log warning in case of error sending request
      * etcdserver/api/v3rpc: 'MemberList' never return non-empty ClientURLs

    - Update to version 3.4.10 [CVE-2020-15106][boo#1174951]:

      * Documentation: note on data encryption
      * etcdserver: change protobuf field type from int to int64 (#12000)
      * pkg: consider umask when use MkdirAll
      * etcdmain: let grpc proxy warn about insecure-skip-tls-verify
      * etcdmain: fix shadow error
      * pkg/fileutil: print desired file permission in error log
      * pkg: Fix dir permission check on Windows
      * auth: Customize simpleTokenTTL settings.
      * mvcc: chanLen 1024 is to biger,and it used more memory. 128 seems to be enough. Sometimes the
    consumption speed is more than the production speed.
      * auth: return incorrect result 'ErrUserNotFound' when client request without username or username was
    empty.
      * etcdmain: fix shadow error
      * doc: add TLS related warnings
      * etcdserver:FDUsage set ticker to 10 minute from 5 seconds. This ticker will check File Descriptor
    Requirements ,and count all fds in used. And recorded some logs when in used >= limit/5*4. Just recorded
    message. If fds was more than 10K,It's low performance due to FDUsage() works. So need to increase it.
      * clientv3: cancel watches proactively on client context cancellation
      * wal: check out of range slice in 'ReadAll', 'decoder'
      * etcdctl, etcdmain: warn about --insecure-skip-tls-verify options
      * Documentation: note on the policy of insecure by default
      * etcdserver: don't let InternalAuthenticateRequest have password
      * auth: a new error code for the case of password auth against no password user
      * Documentation: note on password strength
      * etcdmain: best effort detection of self pointing in tcp proxy
      * Discovery: do not allow passing negative cluster size
      * wal: fix panic when decoder not set
      * embed: fix compaction runtime err
      * pkg: check file stats
      * etcdserver, et al: add --unsafe-no-fsync flag
      * wal: add TestValidSnapshotEntriesAfterPurgeWal testcase
      * wal: fix crc mismatch crash bug
      * rafthttp: log snapshot download duration
      * rafthttp: improve snapshot send logging
      *  *: make sure snapshot save downloads SHA256 checksum
      * etcdserver/api/snap: exclude orphaned defragmentation files in snapNames
      * etcdserver: continue releasing snap db in case of error
      * etcdserver,wal: fix inconsistencies in WAL and snapshot
      * cherry pick of #11564 (#11880)
      * mvcc: fix deadlock bug
      * auth: optimize lock scope for CheckPassword
      * auth: ensure RoleGrantPermission is compatible with older versions
      * etcdserver: print warn log when failed to apply request
      * auth: cleanup saveConsistentIndex in NewAuthStore
      * auth: print warning log when error is ErrAuthOldRevision
      * auth: add new metric 'etcd_debugging_auth_revision'
      * tools/etcd-dump-db: add auth decoder, optimize print format
      * *: fix auth revision corruption bug
      * etcdserver: watch stream got closed once one request is not permitted (#11708)
      * version: 3.4.7
      * wal: add 'etcd_wal_writes_bytes_total'
      * pkg/ioutil: add 'FlushN'
      * test: auto detect branch when finding merge base
      * mvcc/kvstore:when the number key-value is greater than one million, compact take too long and blocks
    other requests
      * version: 3.4.6
      * lease: fix memory leak in LeaseGrant when node is follower
      * version: 3.4.5
      * words: whitelist 'racey'
      * Revert 'version: 3.4.5'
      * words: whitelist 'hasleader'
      * version: 3.4.5
      * etcdserver/api/v3rpc: handle api version metadata, add metrics
      * clientv3: embed api version in metadata
      * etcdserver/api/etcdhttp: log server-side /health checks
      * proxy/grpcproxy: add return on error for metrics handler
      * etcdctl: fix member add command
      * etcdserver: fix quorum calculation when promoting a learner member
      * etcdserver: corruption check via http
      * mvcc/backend: check for nil boltOpenOptions
      * mvcc/backend: Delete orphaned db.tmp files before defrag
      * auth: correct logging level
      * e2e: test curl auth on onoption user
      * auth: fix NoPassWord check when add user
      * auth: fix user.Options nil pointer
      * mvcc/kvstore:fixcompactbug
      * mvcc: update to 'etcd_debugging_mvcc_total_put_size_in_bytes'
      * mvcc: add 'etcd_mvcc_put_size_in_bytes' to monitor the throughput of put request.
      * clientv3: fix retry/streamer error message
      * etcdserver: wait purge file loop during shutdown
      * integration: disable TestV3AuthOldRevConcurrent
      * etcdserver: remove auth validation loop
      * scripts/release: list GPG key only when tagging is needed

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1174951");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1181400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1199031");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PE3D4WEFUCELLDKJUEM2KLPFMME7KTAI/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c40afae");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-11254");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-15106");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28235");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47108");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-48795");
  script_set_attribute(attribute:"solution", value:
"Update the affected etcd, etcdctl and / or etcdutl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15106");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28235");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etcd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etcdctl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:etcdutl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'etcd-3.5.12-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'etcdctl-3.5.12-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'etcdutl-3.5.12-bp156.4.3.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'etcd / etcdctl / etcdutl');
}
