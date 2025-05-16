#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0268-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206410);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/31");

  script_cve_id("CVE-2023-42363", "CVE-2024-6257", "CVE-2024-35192");
  script_xref(name:"IAVB", value:"2024-B-0065");

  script_name(english:"openSUSE 15 Security Update : trivy (openSUSE-SU-2024:0268-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0268-1 advisory.

    trivy was updated to fix the following issues:

    Update to version 0.54.1:

    * fix(flag): incorrect behavior for deprected flag `--clear-cache` [backport: release/v0.54] (#7285)
    * fix(java): Return error when trying to find a remote pom to avoid segfault [backport: release/v0.54]
    (#7283)
    * fix(plugin): do not call GitHub content API for releases and tags [backport: release/v0.54] (#7279)
    * docs: update ecosystem page reporting with plopsec.com app (#7262)
    * feat(vex): retrieve VEX attestations from OCI registries (#7249)
    * feat(sbom): add image labels into `SPDX` and `CycloneDX` reports (#7257)
    * refactor(flag): return error if both `--download-db-only` and `--download-java-db-only` are specified
    (#7259)
    * fix(nodejs): detect direct dependencies when using `latest` version for files `yarn.lock` +
    `package.json` (#7110)
    * chore: show VEX notice for OSS maintainers in CI environments (#7246)
    * feat(vuln): add `--pkg-relationships` (#7237)
    * docs: show VEX cli pages + update config file page for VEX flags (#7244)
    * fix(dotnet): show `nuget package dir not found` log only when checking `nuget` packages (#7194)
    * feat(vex): VEX Repository support (#7206)
    * fix(secret): skip regular strings contain secret patterns (#7182)
    * feat: share build-in rules (#7207)
    * fix(report): hide empty table when all secrets/license/misconfigs are ignored (#7171)
    * fix(cli): error on missing config file (#7154)
    * fix(secret): update length of `hugging-face-access-token` (#7216)
    * feat(sbom): add vulnerability support for SPDX formats (#7213)
    * fix(secret): trim excessively long lines (#7192)
    * chore(vex): update subcomponents for CVE-2023-42363/42364/42365/42366 (#7201)
    * fix(server): pass license categories to options (#7203)
    * feat(mariner): Add support for Azure Linux (#7186)
    * docs: updates config file (#7188)
    * refactor(fs): remove unused field for CompositeFS (#7195)
    * fix: add missing platform and type to spec (#7149)
    * feat(misconf): enabled China configuration for ACRs (#7156)
    * fix: close file when failed to open gzip (#7164)
    * docs: Fix PR documentation to use GitHub Discussions, not Issues (#7141)
    * docs(misconf): add info about limitations for terraform plan json (#7143)
    * chore: add VEX for Trivy images (#7140)
    * chore: add VEX document and generator for Trivy  (#7128)
    * fix(misconf): do not evaluate TF when a load error occurs (#7109)
    * feat(cli): rename `--vuln-type` flag to `--pkg-types` flag (#7104)
    * refactor(secret): move warning about file size after `IsBinary` check (#7123)
    * feat: add openSUSE tumbleweed detection and scanning (#6965)
    * test: add missing advisory details for integration tests database (#7122)
    * fix: Add dependencyManagement exclusions to the child exclusions (#6969)
    * fix: ignore nodes when listing permission is not allowed (#7107)
    * fix(java): use `go-mvn-version` to remove `Package` duplicates (#7088)
    * refactor(secret): add warning about large files (#7085)
    * feat(nodejs): add license parser to pnpm analyser (#7036)
    * refactor(sbom): add sbom prefix + filepaths for decode log messages (#7074)
    * feat: add `log.FilePath()` function for logger (#7080)
    * chore: bump golangci-lint from v1.58 to v1.59 (#7077)
    * perf(debian): use `bytes.Index` in `emptyLineSplit` to cut allocation (#7065)
    * refactor: pass DB dir to trivy-db (#7057)
    * docs: navigate to the release highlights and summary (#7072)

    Update to version 0.53.0 (bsc#1227022, CVE-2024-6257):

    * feat(conda): add licenses support for `environment.yml` files (#6953)
    * fix(sbom): fix panic when scanning SBOM file without root component into SBOM format (#7051)
    * feat: add memory cache backend (#7048)
    * fix(sbom): use package UIDs for uniqueness (#7042)
    * feat(php): add installed.json file support (#4865)
    * docs:  Updated ecosystem docs with reference to new community app (#7041)
    * fix: use embedded when command path not found (#7037)
    * refactor: use google/wire for cache (#7024)
    * fix(cli): show info message only when --scanners is available (#7032)
    * chore: enable float-compare rule from testifylint (#6967)
    * docs: Add sudo on commands, chmod before mv on install docs (#7009)
    * fix(plugin): respect `--insecure` (#7022)
    * feat(k8s)!: node-collector dynamic commands support (#6861)
    * fix(sbom): take pkg name from `purl` for maven pkgs (#7008)
    * feat!: add clean subcommand (#6993)
    * chore: use `!` for breaking changes (#6994)
    * feat(aws)!: Remove aws subcommand (#6995)
    * refactor: replace global cache directory with parameter passing (#6986)
    * fix(sbom): use `purl` for `bitnami` pkg names (#6982)
    * chore: bump Go toolchain version (#6984)
    * refactor: unify cache implementations (#6977)
    * docs: non-packaged and sbom clarifications (#6975)
    * BREAKING(aws): Deprecate `trivy aws` as subcmd in favour of a plugin (#6819)
    * docs: delete unknown URL (#6972)
    * refactor: use version-specific URLs for documentation references (#6966)
    * refactor: delete db mock (#6940)
    * refactor: add warning if severity not from vendor (or NVD or GH) is used (#6726)
    * feat: Add local ImageID to SARIF metadata (#6522)
    * fix(suse): Add SLES 15.6 and Leap 15.6 (#6964)
    * feat(java): add support for sbt projects using sbt-dependency-lock (#6882)
    * feat(java): add support for `maven-metadata.xml` files for remote snapshot repositories. (#6950)
    * fix(purl): add missed os types (#6955)
    * fix(cyclonedx): trim non-URL info for `advisory.url` (#6952)
    * fix(c): don't skip conan files from `file-patterns` and scan `.conan2` cache dir (#6949)
    * fix(image): parse `image.inspect.Created` field only for non-empty values (#6948)
    * fix(misconf): handle source prefix to ignore (#6945)
    * fix(misconf): fix parsing of engine links and frameworks (#6937)
    * feat(misconf): support of selectors for all providers for Rego (#6905)
    * fix(license): return license separation using separators  `,`, `or`, etc. (#6916)
    * feat(misconf): add support for AWS::EC2::SecurityGroupIngress/Egress (#6755)
    * BREAKING(misconf): flatten recursive types (#6862)
    * test: bump docker API to 1.45  (#6914)
    * feat(sbom): migrate to `CycloneDX v1.6` (#6903)
    * feat(image): Set User-Agent header for Trivy container registry requests (#6868)
    * fix(debian): take installed files from the origin layer (#6849)
    * fix(nodejs): fix infinite loop when package link from `package-lock.json` file is broken (#6858)
    * feat(misconf): API Gateway V1 support for CloudFormation (#6874)
    * feat(plugin): add support for nested archives (#6845)
    * fix(sbom): don't overwrite `srcEpoch` when decoding SBOM files (#6866)
    * fix(secret): `Asymmetric Private Key` shouldn't start with space (#6867)
    * chore: auto label discussions (#5259)
    * docs: explain how VEX is applied (#6864)
    * fix(python): compare pkg names from `poetry.lock` and `pyproject.toml` in lowercase (#6852)
    * fix(nodejs): fix infinity loops for `pnpm` with cyclic imports (#6857)
    * feat(dart): use first version of constraint for dependencies using SDK version (#6239)
    * fix(misconf): parsing numbers without fraction as int (#6834)
    * fix(misconf): fix caching of modules in subdirectories (#6814)
    * feat(misconf): add metadata to Cloud schema (#6831)
    * test: replace embedded Git repository with dynamically created repository (#6824)

    Update to version 0.52.2:

    * test: bump docker API to 1.45  [backport: release/v0.52] (#6922)
    * fix(debian): take installed files from the origin layer [backport: release/v0.52] (#6892)

    Update to version 0.52.1:

    * fix(nodejs): fix infinite loop when package link from `package-lock.json` file is broken [backport:
    release/v0.52] (#6888)
    * fix(sbom): don't overwrite `srcEpoch` when decoding SBOM files [backport: release/v0.52] (#6881)
    * fix(python): compare pkg names from `poetry.lock` and `pyproject.toml` in lowercase [backport:
    release/v0.52] (#6878)
    * docs: explain how VEX is applied (#6864)
    * fix(nodejs): fix infinity loops for `pnpm` with cyclic imports (#6857)

    Update to version 0.52.0 (bsc#1224781, CVE-2024-35192):

    * fix(plugin): initialize logger (#6836)
    * fix(cli): always output fatal errors to stderr (#6827)
    * fix: close testfile (#6830)
    * docs(julia): add scanner table (#6826)
    * feat(python): add license support for `requirement.txt` files (#6782)
    * docs: add more workarounds for out-of-disk (#6821)
    * chore: improve error message for image not found (#6822)
    * fix(sbom): fix panic for `convert` mode when scanning json file derived from sbom file (#6808)
    * fix: clean up golangci lint configuration (#6797)
    * fix(python): add package name and version validation for `requirements.txt` files. (#6804)
    * feat(vex): improve relationship support in CSAF VEX (#6735)
    * chore(alpine): add eol date for Alpine 3.20 (#6800)
    * docs(plugin): add missed `plugin` section (#6799)
    * fix: include packages unless it is not needed (#6765)
    * feat(misconf): support for VPC resources for inbound/outbound rules (#6779)
    * chore: replace interface{} with any (#6751)
    * fix: close settings.xml (#6768)
    * refactor(go): add priority for gobinary module versions from `ldflags` (#6745)
    * build: use main package instead of main.go (#6766)
    * feat(misconf): resolve tf module from OpenTofu compatible registry (#6743)
    * docs: add info on adding compliance checks (#6275)
    * docs: Add documentation for contributing additional checks to the trivy policies repo (#6234)
    * feat(nodejs): add v9 pnpm lock file support (#6617)
    * feat(vex): support non-root components for products in OpenVEX (#6728)
    * feat(python): add line number support for `requirement.txt` files (#6729)
    * chore: respect timeout value in .golangci.yaml (#6724)
    * fix: node-collector high and critical cves (#6707)
    * Merge pull request from GHSA-xcq4-m2r3-cmrj
    * chore: auto-bump golang patch versions (#6711)
    * fix(misconf): don't shift ignore rule related to code (#6708)
    * feat(plugin): specify plugin version (#6683)
    * chore: enforce golangci-lint version (#6700)
    * fix(go): include only `.version`|`.ver` (no prefixes) ldflags for `gobinaries` (#6705)
    * fix(go): add only non-empty root modules for `gobinaries` (#6710)
    * refactor: unify package addition and vulnerability scanning (#6579)
    * fix: Golang version parsing from binaries w/GOEXPERIMENT (#6696)
    * feat(misconf): Add support for deprecating a check (#6664)
    * feat: Add Julia language analyzer support (#5635)
    * feat(misconf): register builtin Rego funcs from trivy-checks (#6616)
    * fix(report): hide empty tables if all vulns has been filtered (#6352)
    * feat(report): Include licenses and secrets filtered by rego to ModifiedFindings (#6483)
    * feat: add support for plugin index (#6674)
    * docs: add support table for client server mode (#6498)
    * fix: close APKINDEX archive file (#6672)
    * fix(misconf): skip Rego errors with a nil location (#6666)
    * refactor: move artifact types under artifact package to avoid import cycles (#6652)
    * refactor(misconf): remove extrafs (#6656)
    * refactor: re-define module structs for serialization (#6655)
    * chore(misconf): Clean up iac logger (#6642)
    * feat(misconf): support symlinks inside of Helm archives (#6621)
    * feat(misconf): add Terraform 'removed' block to schema (#6640)
    * refactor: unify Library and Package structs (#6633)
    * fix: use of specified context to obtain cluster name (#6645)
    * perf(misconf): parse rego input once (#6615)
    * fix(misconf): skip Rego errors with a nil location (#6638)
    * docs: link warning to both timeout config options (#6620)
    * docs: fix usage of image-config-scanners (#6635)

    Update to version 0.51.1:

    * fix(fs): handle default skip dirs properly (#6628)
    * fix(misconf): load cached tf modules (#6607)
    * fix(misconf): do not use semver for parsing tf module versions (#6614)
    * refactor: move setting scanners when using compliance reports to flag parsing (#6619)
    * feat: introduce package UIDs for improved vulnerability mapping (#6583)
    * perf(misconf): Improve cause performance (#6586)
    * docs: trivy-k8s new experiance remove un-used section (#6608)
    * docs: remove mention of GitLab Gold because it doesn't exist anymore (#6609)
    * feat(misconf): Use updated terminology for misconfiguration checks (#6476)
    * docs: use `generic` link from `trivy-repo` (#6606)
    * docs: update trivy k8s with new experience (#6465)
    * feat: support `--skip-images` scanning flag (#6334)
    * BREAKING: add support for k8s `disable-node-collector` flag (#6311)
    * feat: add ubuntu 23.10 and 24.04 support (#6573)
    * docs(go): add stdlib (#6580)
    * feat(go): parse main mod version from build info settings (#6564)
    * feat: respect custom exit code from plugin (#6584)
    * docs: add asdf and mise installation method (#6063)
    * feat(vuln): Handle scanning conan v2.x lockfiles (#6357)
    * feat: add support `environment.yaml` files (#6569)
    * fix: close plugin.yaml (#6577)
    * fix: trivy k8s avoid deleting non-default node collector namespace  (#6559)
    * BREAKING: support exclude `kinds/namespaces` and include `kinds/namespaces` (#6323)
    * feat(go): add main module (#6574)
    * feat: add relationships (#6563)
    * docs: mention `--show-suppressed` is available in table (#6571)
    * chore: fix sqlite to support loong64 (#6511)
    * fix(debian): sort dpkg info before parsing due to exclude directories (#6551)
    * docs: update info about config file (#6547)
    * docs: remove RELEASE_VERSION from trivy.repo (#6546)
    * fix(sbom): change error to warning for multiple OSes (#6541)
    * fix(vuln): skip empty versions (#6542)
    * feat(c): add license support for conan lock files (#6329)
    * fix(terraform): Attribute and fileset fixes (#6544)
    * refactor: change warning if no vulnerability details are found (#6230)
    * refactor(misconf): improve error handling in the Rego scanner (#6527)
    * feat(go): parse main module of go binary files (#6530)
    * refactor(misconf): simplify the retrieval of module annotations (#6528)
    * docs(nodejs): add info about supported versions of pnpm lock files (#6510)
    * feat(misconf): loading embedded checks as a fallback (#6502)
    * fix(misconf): Parse JSON k8s manifests properly (#6490)
    * refactor: remove parallel walk (#5180)
    * fix: close pom.xml (#6507)
    * fix(secret): convert severity for custom rules (#6500)
    * fix(java): update logic to detect `pom.xml` file snapshot artifacts from remote repositories (#6412)
    * fix: typo (#6283)
    * docs(k8s,image): fix command-line syntax issues (#6403)
    * fix(misconf): avoid panic if the scheme is not valid (#6496)
    * feat(image): goversion as stdlib (#6277)
    * fix: add color for error inside of log message (#6493)
    * docs: fix links to OPA docs (#6480)
    * refactor: replace zap with slog (#6466)
    * docs: update links to IaC schemas (#6477)
    * chore: bump Go to 1.22 (#6075)
    * refactor(terraform): sync funcs with Terraform (#6415)
    * feat(misconf): add helm-api-version and helm-kube-version flag (#6332)
    * fix(terraform): eval submodules (#6411)
    * refactor(terraform): remove unused options (#6446)
    * refactor(terraform): remove unused file (#6445)
    * fix(misconf): Escape template value correctly (#6292)
    * feat(misconf): add support for wildcard ignores (#6414)
    * fix(cloudformation): resolve `DedicatedMasterEnabled` parsing issue (#6439)
    * refactor(terraform): remove metrics collection (#6444)
    * feat(cloudformation): add support for logging and endpoint access for EKS (#6440)
    * fix(db): check schema version for image name only (#6410)
    * feat(misconf): Support private registries for misconf check bundle (#6327)
    * feat(cloudformation): inline ignore support for YAML templates (#6358)
    * feat(terraform): ignore resources by nested attributes (#6302)
    * perf(helm): load in-memory files (#6383)
    * feat(aws): apply filter options to result (#6367)
    * feat(aws): quiet flag support (#6331)
    * fix(misconf): clear location URI for SARIF (#6405)
    * test(cloudformation): add CF tests (#6315)
    * fix(cloudformation): infer type after resolving a function (#6406)
    * fix(sbom): fix error when parent of SPDX Relationships is not a package. (#6399)
    * docs: add info about support for package license detection in `fs`/`repo` modes (#6381)
    * fix(nodejs): add support for parsing `workspaces` from `package.json` as an object (#6231)
    * fix: use `0600` perms for tmp files for post analyzers (#6386)
    * fix(helm): scan the subcharts once (#6382)
    * docs(terraform): add file patterns for Terraform Plan (#6393)
    * fix(terraform): hecking SSE encryption algorithm validity (#6341)
    * fix(java): parse modules from `pom.xml` files once (#6312)
    * fix(server): add Locations for `Packages` in client/server mode (#6366)
    * fix(sbom): add check for `CreationInfo` to nil when detecting SPDX created using Trivy (#6346)
    * fix(report): don't include empty strings in `.vulnerabilities[].identifiers[].url` when `gitlab.tpl` is
    used (#6348)
    * chore(ubuntu): Add Ubuntu 22.04 EOL date (#6371)
    * feat(java): add support licenses and graph for gradle lock files (#6140)
    * feat(vex): consider root component for relationships (#6313)
    * fix: increase the default buffer size for scanning dpkg status files by 2 times (#6298)
    * chore: updates wazero to v1.7.0 (#6301)
    * feat(sbom): Support license detection for SBOM scan (#6072)
    * refactor(sbom): use intermediate representation for SPDX (#6310)
    * docs(terraform): improve documentation for filtering by inline comments (#6284)
    * fix(terraform): fix policy document retrieval (#6276)
    * refactor(terraform): remove unused custom error (#6303)
    * refactor(sbom): add intermediate representation for BOM (#6240)
    * fix(amazon): check only major version of AL to find advisories (#6295)
    * fix(db): use schema version as tag only for `trivy-db` and `trivy-java-db` registries by default (#6219)
    * fix(nodejs): add name validation for package name from `package.json`  (#6268)
    * docs: Added install instructions for FreeBSD (#6293)
    * feat(image): customer podman host or socket option (#6256)
    * feat(java): mark dependencies from `maven-invoker-plugin` integration tests pom.xml files as `Dev`
    (#6213)
    * fix(license): reorder logic of how python package licenses are acquired (#6220)
    * test(terraform): skip cached modules (#6281)
    * feat(secret): Support for detecting Hugging Face Access Tokens (#6236)
    * fix(cloudformation): support of all SSE algorithms for s3 (#6270)
    * feat(terraform): Terraform Plan snapshot scanning support (#6176)
    * fix: typo function name and comment optimization (#6200)
    * fix(java): don't ignore runtime scope for pom.xml files (#6223)
    * fix(license): add FilePath to results to allow for license path filtering via trivyignore file (#6215)
    * test(k8s): use test-db for k8s integration tests (#6222)
    * fix(terraform): fix root module search (#6160)
    * test(parser): squash test data for yarn (#6203)
    * fix(terraform): do not re-expand dynamic blocks (#6151)
    * docs: update ecosystem page reporting with db app (#6201)
    * fix: k8s summary separate infra and user finding results (#6120)
    * fix: add context to target finding on k8s table view (#6099)
    * fix: Printf format err (#6198)
    * refactor: better integration of the parser into Trivy (#6183)
    * feat(terraform): Add hyphen and non-ASCII support for domain names in credential extraction (#6108)
    * fix(vex): CSAF filtering should consider relationships (#5923)
    * refactor(report): Replacing `source_location` in `github` report when scanning an image (#5999)
    * feat(vuln): ignore vulnerabilities by PURL (#6178)
    * feat(java): add support for fetching packages from repos mentioned in pom.xml (#6171)
    * feat(k8s): rancher rke2 version support (#5988)
    * docs: update kbom distribution for scanning (#6019)
    * chore: update CODEOWNERS (#6173)
    * fix(swift): try to use branch to resolve version (#6168)
    * fix(terraform): ensure consistent path handling across OS (#6161)
    * fix(java): add only valid libs from `pom.properties` files from `jars` (#6164)
    * fix(sbom): skip executable file analysis if Rekor isn't a specified SBOM source (#6163)
    * docs(report): add remark about `path` to filter licenses using `.trivyignore.yaml` file (#6145)
    * docs: update template path for gitlab-ci tutorial (#6144)
    * feat(report): support for filtering licenses and secrets via rego policy files (#6004)
    * fix(cyclonedx): move root component from scanned cyclonedx file to output cyclonedx file (#6113)
    * docs: add SecObserve in CI/CD and reporting (#6139)
    * fix(alpine): exclude empty licenses for apk packages (#6130)
    * docs: add docs tutorial on custom policies with rego (#6104)
    * fix(nodejs): use project dir when searching for workspaces for Yarn.lock files (#6102)
    * feat(vuln): show suppressed vulnerabilities in table (#6084)
    * docs: rename governance to principles (#6107)
    * docs: add governance (#6090)
    * feat(java): add dependency location support for `gradle` files (#6083)
    * fix(misconf): get `user` from `Config.User` (#6070)

    Update to version 0.49.1:

    * fix: check unescaped `BomRef` when matching `PkgIdentifier` (#6025)
    * docs: Fix broken link to 'pronunciation' (#6057)
    * fix: fix cursor usage in Redis Clear function (#6056)
    * fix(nodejs): add local packages support for `pnpm-lock.yaml` files (#6034)
    * test: fix flaky `TestDockerEngine` (#6054)
    * fix(java): recursive check all nested depManagements with import scope for pom.xml files (#5982)
    * fix(cli): inconsistent behavior across CLI flags, environment variables, and config files (#5843)
    * feat(rust): Support workspace.members parsing for Cargo.toml analysis (#5285)
    * docs: add note about Bun (#6001)
    * fix(report): use `AWS_REGION` env for secrets in `asff` template (#6011)
    * fix: check returned error before deferring f.Close() (#6007)
    * feat(misconf): add support of buildkit instructions when building dockerfile from image config (#5990)
    * feat(vuln): enable `--vex` for all targets (#5992)
    * docs: update link to data sources (#6000)
    * feat(java): add support for line numbers for pom.xml files (#5991)
    * refactor(sbom): use new `metadata.tools` struct for CycloneDX (#5981)
    * docs: Update troubleshooting guide with image not found error (#5983)
    * style: update band logos (#5968)
    * docs: update cosign tutorial and commands, update kyverno policy (#5929)
    * docs: update command to scan go binary (#5969)
    * fix: handle non-parsable images names (#5965)
    * fix(amazon): save system files for pkgs containing `amzn` in src (#5951)
    * fix(alpine): Add EOL support for alpine 3.19. (#5938)
    * feat: allow end-users to adjust K8S client QPS and burst (#5910)
    * fix(nodejs): find licenses for packages with slash (#5836)
    * fix(sbom): use `group` field for pom.xml and nodejs files for CycloneDX reports (#5922)
    * fix: ignore no init containers (#5939)
    * docs: Fix documentation of ecosystem (#5940)
    * docs(misconf): multiple ignores in comment (#5926)
    * fix(secret): find aws secrets ending with a comma or dot (#5921)
    * docs:  Updated ecosystem docs with reference to new community app (#5918)
    * fix(java): check if a version exists when determining GAV by file name for `jar` files (#5630)
    * feat(vex): add PURL matching for CSAF VEX (#5890)
    * fix(secret): `AWS Secret Access Key` must include only secrets with `aws` text. (#5901)
    * revert(report): don't escape new line characters for sarif format (#5897)
    * docs: improve filter by rego (#5402)
    * docs: add_scan2html_to_trivy_ecosystem (#5875)
    * fix(vm): update ext4-filesystem fix reading groupdescriptor in 32bit mode (#5888)
    * feat(vex): Add support for CSAF format (#5535)
    * feat(python): parse licenses from dist-info folder (#4724)
    * feat(nodejs): add yarn alias support (#5818)
    * refactor: propagate time through context values (#5858)
    * refactor: move PkgRef under PkgIdentifier (#5831)
    * fix(cyclonedx): fix unmarshal for licenses (#5828)
    * feat(vuln): include pkg identifier on detected vulnerabilities (#5439)

    Update to version 0.48.1:

    * fix(bitnami): use a different comparer for detecting vulnerabilities (#5633)
    * refactor(sbom): disable html escaping for CycloneDX (#5764)
    * refactor(purl): use `pub` from `package-url` (#5784)
    * docs(python): add note to using `pip freeze` for `compatible releases` (#5760)
    * fix(report): use OS information for OS packages purl in `github` template (#5783)
    * fix(report): fix error if miconfigs are empty (#5782)
    * refactor(vuln): don't remove VendorSeverity in JSON report (#5761)
    * fix(report): don't mark misconfig passed tests as failed in junit.tpl (#5767)
    * docs(k8s): replace --scanners config with --scanners misconfig in docs (#5746)
    * fix(report): update Gitlab template (#5721)
    * feat(secret): add support of GitHub fine-grained tokens (#5740)
    * fix(misconf): add an image misconf to result (#5731)
    * feat(secret): added support of Docker registry credentials (#5720)

    Update to version 0.48.0:

    * feat: filter k8s core components vuln results (#5713)
    * feat(vuln): remove duplicates in Fixed Version (#5596)
    * feat(report): output plugin (#4863)
    * docs: typo in modules.md (#5712)
    * feat: Add flag to configure node-collector image ref (#5710)
    * feat(misconf): Add `--misconfig-scanners` option (#5670)
    * chore: bump Go to 1.21 (#5662)
    * feat: Packagesprops support (#5605)
    * docs: update adopters discussion template (#5632)
    * docs: terraform tutorial links updated to point to correct loc (#5661)
    * fix(secret): add `sec` and space to secret prefix for `aws-secret-access-key` (#5647)
    * fix(nodejs): support protocols for dependency section in yarn.lock files (#5612)
    * fix(secret): exclude upper case before secret for `alibaba-access-key-id` (#5618)
    * docs: Update Arch Linux package URL in installation.md (#5619)
    * chore: add prefix to image errors (#5601)
    * docs(vuln): fix link anchor (#5606)
    * docs: Add Dagger integration section and cleanup Ecosystem CICD docs page (#5608)
    * fix: k8s friendly error messages kbom non cluster scans (#5594)
    * feat: set InstalledFiles for DEB and RPM packages (#5488)
    * fix(report): use time.Time for CreatedAt (#5598)
    * test: retry containerd initialization (#5597)
    * feat(misconf): Expose misconf engine debug logs with `--debug` option (#5550)
    * test: mock VM walker (#5589)
    * chore: bump node-collector v0.0.9 (#5591)
    * feat(misconf): Add support for `--cf-params` for CFT (#5507)
    * feat(flag): replace '--slow' with '--parallel' (#5572)
    * fix(report): add escaping for Sarif format (#5568)
    * chore: show a deprecation notice for `--scanners config` (#5587)
    * feat(report): Add CreatedAt to the JSON report. (#5542) (#5549)
    * test: mock RPM DB (#5567)
    * feat: add aliases to '--scanners' (#5558)
    * refactor: reintroduce output writer (#5564)
    * chore: not load plugins for auto-generating docs (#5569)
    * chore: sort supported AWS services (#5570)
    * fix: no schedule toleration (#5562)
    * fix(cli): set correct `scanners` for `k8s` target (#5561)
    * fix(sbom): add `FilesAnalyzed` and `PackageVerificationCode` fields for SPDX (#5533)
    * refactor(misconf): Update refactored dependencies (#5245)
    * feat(secret): add built-in rule for JWT tokens (#5480)
    * fix: trivy k8s parse ecr image with arn (#5537)
    * fix: fail k8s resource scanning (#5529)
    * refactor(misconf): don't remove Highlighted in json format (#5531)
    * docs(k8s): fix link in kubernetes.md (#5524)
    * docs(k8s): fix whitespace in list syntax (#5525)

    Update to version 0.47.0:

    * docs: add info that license scanning supports file-patterns flag (#5484)
    * docs: add Zora integration into Ecosystem session (#5490)
    * fix(sbom): Use UUID as BomRef for packages with empty purl (#5448)
    * fix: correct error mismatch causing race in fast walks (#5516)
    * docs: k8s vulnerability scanning (#5515)
    * docs: remove glad for java datasources (#5508)
    * chore: remove unused logger attribute in amazon detector (#5476)
    * fix: correct error mismatch causing race in fast walks (#5482)
    * fix(server): add licenses to `BlobInfo` message (#5382)
    * feat: scan vulns on k8s core component apps (#5418)
    * fix(java): fix infinite loop when `relativePath` field points to `pom.xml` being scanned (#5470)
    * fix(sbom): save digests for package/application when scanning SBOM files (#5432)
    * docs: fix the broken link (#5454)
    * docs: fix error when installing `PyYAML` for gh pages (#5462)
    * fix(java): download java-db once (#5442)
    * docs(misconf): Update `--tf-exclude-downloaded-modules` description (#5419)
    * feat(misconf): Support `--ignore-policy` in config scans (#5359)
    * docs(misconf): fix broken table for `Use container image` section (#5425)
    * feat(dart): add graph support (#5374)
    * refactor: define a new struct for scan targets (#5397)
    * fix(sbom): add missed `primaryURL` and `source severity` for CycloneDX (#5399)
    * fix: correct invalid MD5 hashes for rpms ending with one or more zero bytes (#5393)
    * docs: remove --scanners none (#5384)
    * docs: Update container_image.md #5182 (#5193)
    * feat(report): Add `InstalledFiles` field to Package (#4706)
    * feat(k8s): add support for vulnerability detection (#5268)
    * fix(python): override BOM in `requirements.txt` files (#5375)
    * docs: add kbom documentation (#5363)
    * test: use maximize build space for VM tests (#5362)
    * fix(report): add escaping quotes in misconfig Title for asff template (#5351)
    * fix: Report error when os.CreateTemp fails (to be consistent with other uses) (#5342)
    * fix: add config files to FS for post-analyzers (#5333)
    * fix: fix MIME warnings after updating to Go 1.20 (#5336)
    * build: fix a compile error with Go 1.21 (#5339)
    * feat: added `Metadata` into the k8s resource's scan report (#5322)
    * chore: update adopters template (#5330)
    * fix(sbom): use PURL or Group and Name in case of Java  (#5154)
    * docs: add buildkite repository to ecosystem page (#5316)
    * chore: enable go-critic (#5302)
    * close java-db client (#5273)
    * fix(report): removes git::http from uri in sarif (#5244)
    * Improve the meaning of  sentence (#5301)
    * add app nil check (#5274)
    * typo: in secret.md (#5281)
    * docs: add info about `github` format (#5265)
    * feat(dotnet): add license support for NuGet (#5217)
    * docs: correctly export variables (#5260)
    * chore: Add line numbers for lint output (#5247)
    * chore(cli): disable java-db flags in server mode (#5263)
    * feat(db): allow passing registry options (#5226)
    * refactor(purl): use TypeApk from purl (#5232)
    * chore: enable more linters (#5228)
    * Fix typo on ide.md (#5239)
    * refactor: use defined types (#5225)
    * fix(purl): skip local Go packages (#5190)
    * docs: update info about license scanning in Yarn projects (#5207)
    * fix link (#5203)
    * fix(purl): handle rust types (#5186)
    * chore: auto-close issues (#5177)
    * fix(k8s): kbom support addons labels (#5178)
    * test: validate SPDX with the JSON schema (#5124)
    * chore: bump trivy-kubernetes-latest (#5161)
    * docs: add 'Signature Verification' guide (#4731)
    * docs: add image-scanner-with-trivy for ecosystem (#5159)
    * fix(fs): assign the absolute path to be inspected to ROOTPATH when filesystem (#5158)
    * Update filtering.md (#5131)
    * chaging adopters discussion tempalte (#5091)
    * docs: add Bitnami (#5078)
    * feat(docker): add support for scanning Bitnami components (#5062)
    * feat: add support for .trivyignore.yaml (#5070)
    * fix(terraform): improve detection of terraform files (#4984)
    * feat: filter artifacts on --exclude-owned flag (#5059)
    * fix(sbom): cyclonedx advisory should omit `null` value (#5041)
    * build: maximize build space for build tests (#5072)
    * feat: improve kbom component name (#5058)
    * fix(pom): add licenses for pom artifacts (#5071)
    * chore: bump Go to `1.20` (#5067)
    * feat: PURL matching with qualifiers in OpenVEX (#5061)
    * feat(java): add graph support for pom.xml (#4902)
    * feat(swift): add vulns for cocoapods (#5037)
    * fix: support image pull secret for additional workloads (#5052)
    * fix: #5033 Superfluous double quote in html.tpl (#5036)
    * docs(repo): update trivy repo usage and example (#5049)
    * perf: Optimize Dockerfile for reduced layers and size (#5038)
    * feat: scan K8s Resources Kind with --all-namespaces (#5043)
    * fix: vulnerability typo (#5044)
    * docs: adding a terraform tutorial to the docs (#3708)
    * feat(report): add licenses to sarif format (#4866)
    * feat(misconf): show the resource name in the report (#4806)
    * chore: update alpine base images (#5015)
    * feat: add Package.resolved swift files support (#4932)
    * feat(nodejs): parse licenses in yarn projects (#4652)
    * fix: k8s private registries support (#5021)
    * bump github.com/testcontainers/testcontainers-go from 0.21.0 to 0.23.0 (#5018)
    * feat(vuln): support last_affected field from osv (#4944)
    * feat(server): add version endpoint (#4869)
    * feat: k8s private registries support (#4987)
    * fix(server): add indirect prop to package (#4974)
    * docs: add coverage (#4954)
    * feat(c): add location for lock file dependencies. (#4994)
    * docs: adding blog post on ec2 (#4813)
    * revert 32bit bins (#4977)

    Update to version 0.44.1:

    * fix(report): return severity colors in table format (#4969)
    * build: maximize available disk space for release (#4937)
    * test(cli): Fix assertion helptext (#4966)
    * test: validate CycloneDX with the JSON schema (#4956)
    * fix(server): add licenses to the Result message (#4955)
    * fix(aws): resolve endpoint if endpoint is passed (#4925)
    * fix(sbom): move licenses to `name` field in Cyclonedx format (#4941)
    * use testify instead of gotest.tools (#4946)
    * fix(nodejs): do not detect lock file in node_modules as an app (#4949)
    * bump go-dep-parser (#4936)
    * test(aws): move part of unit tests to integration (#4884)
    * docs(cli): update help string for file and dir skipping (#4872)
    * docs: update the discussion template (#4928)

     Update to version 0.44.0:

    * feat(repo): support local repositories (#4890)
    * bump go-dep-parser (#4893)
    * fix(misconf): add missing fields to proto (#4861)
    * fix: remove trivy-db package replacement (#4877)
    * chore(test): bump the integration test timeout to 15m (#4880)
    * chore: update CODEOWNERS (#4871)
    * feat(vuln): support vulnerability status (#4867)
    * feat(misconf): Support custom URLs for policy bundle (#4834)
    * refactor: replace with sortable packages (#4858)
    * docs: correct license scanning sample command (#4855)
    * fix(report): close the file (#4842)
    * feat(misconf): Add support for independently enabling libraries (#4070)
    * feat(secret): add secret config file for cache calculation (#4837)
    * Fix a link in gitlab-ci.md (#4850)
    * fix(flag): use globalstar to skip directories (#4854)
    * fix(license): using common way for splitting licenses (#4434)
    * fix(containerd): Use img platform in exporter instead of strict host platform (#4477)
    * remove govulndb (#4783)
    * fix(java): inherit licenses from parents (#4817)
    * refactor: add allowed values for CLI flags (#4800)
    * add example regex to allow rules (#4827)
    * feat(misconf): Support custom data for rego policies for cloud (#4745)
    * docs: correcting the trivy k8s tutorial (#4815)
    * feat(cli): add --tf-exclude-downloaded-modules flag (#4810)
    * fix(sbom): cyclonedx recommendations should include fixed versions for each package (#4794)
    * feat(misconf): enable --policy flag to accept directory and files both (#4777)
    * feat(python): add license fields (#4722)
    * fix: support trivy k8s-version on k8s sub-command (#4786)

    Update to version 0.43.1:

    * docs(image): fix the comment on the soft/hard link (#4740)
    * check Type when filling pkgs in vulns (#4776)
    * feat: add support of linux/ppc64le and linux/s390x architectures for Install.sh script (#4770)
    * fix(rocky): add architectures support for advisories (#4691)
    * fix: documentation about reseting trivy image (#4733)
    * fix(suse): Add openSUSE Leap 15.5 eol date as well (#4744)
    * fix: update Amazon Linux 1 EOL (#4761)

    Update to version 0.43.0:

    * feat(nodejs): support yarn workspaces (#4664)
    * fix(image): pass the secret scanner option to scan the img config (#4735)
    * fix: scan job pod it not found on k8s-1.27.x (#4729)
    * feat(docker): add support for mTLS authentication when connecting to registry (#4649)
    * fix: skip scanning the gpg-pubkey package (#4720)
    * Fix http registry oci pull (#4701)
    * feat(misconf): Support skipping services (#4686)
    * docs: fix supported modes for pubspec.lock files (#4713)
    * fix(misconf): disable the terraform plan analyzer for other scanners (#4714)
    * clarifying a dir path is required for custom policies (#4716)
    * chore: update alpine base images (#4715)
    * fix last-history-created (#4697)
    * feat: kbom and cyclonedx v1.5 spec support (#4708)
    * docs: add information about Aqua (#4590)
    * fix: k8s escape resource filename on windows os (#4693)
    * feat: cyclondx sbom custom property support (#4688)
    * add SUSE Linux Enterprise Server 15 SP5 and update SP4 eol date (#4690)
    * use group field for jar in cyclonedx (#4674)
    * feat(java): capture licenses from pom.xml (#4681)
    * feat(helm): make sessionAffinity configurable (#4623)
    * fix: Show the correct URL of the secret scanning (#4682)
    * document expected file pattern definition format (#4654)
    * fix: format arg error (#4642)
    * feat(k8s): cyclonedx kbom support (#4557)
    * fix(nodejs): remove unused fields for the pnpm lockfile (#4630)
    * fix(vm): update ext4-filesystem parser for parse multi block extents (#4616)
    * fix(debian): update EOL for Debian 12 (#4647)
    * chore: unnecessary use of fmt.Sprintf (S1039) (#4637)
    * fix(db): change argument order in Exists query for JavaDB (#4595)
    * feat(aws): Add support to see successes in results (#4427)
    * feat: trivy k8s private registry support (#4567)
    * docs: add general coverage page (#3859)
    * chore: create SECURITY.md (#4601)

    Update to version 0.42.1:

    * fix(misconf): deduplicate misconf results (#4588)
    * fix(vm): support sector size of 4096 (#4564)
    * fix(misconf): terraform relative paths (#4571)
    * fix(purl): skip unsupported library type (#4577)
    * fix(terraform): recursively detect all Root Modules (#4457)
    * fix(vm): support post analyzer for vm command (#4544)
    * fix(nodejs): change the type of the devDependencies field (#4560)
    * fix(sbom): export empty dependencies in CycloneDX (#4568)
    * refactor: add composite fs for post-analyzers (#4556)
    * feat: add SBOM analyzer (#4210)
    * fix(sbom): update logic for work with files in spdx format (#4513)
    * feat: azure workload identity support (#4489)
    * feat(ubuntu): add eol date for 18.04 ESM (#4524)
    * fix(misconf): Update required extensions for terraformplan (#4523)
    * refactor(cyclonedx): add intermediate representation (#4490)
    * fix(misconf): Remove debug print while scanning (#4521)
    * fix(java): remove duplicates of jar libs (#4515)
    * fix(java): fix overwriting project props in pom.xml (#4498)
    * docs: Update compilation instructions (#4512)
    * fix(nodejs): update logic for parsing pnpm lock files (#4502)
    *  fix(secret): remove aws-account-id rule (#4494)
    * feat(oci): add support for referencing an input image by digest (#4470)
    * docs: fixed the format (#4503)
    * fix(java): add support of * for exclusions for pom.xml files (#4501)
    * feat: adding issue template for documentation (#4453)
    * docs: switch glad to ghsa for Go (#4493)
    * feat(misconf): Add terraformplan support (#4342)
    * feat(debian): add digests for dpkg (#4445)
    * feat(k8s): exclude node scanning by node labels (#4459)
    * docs: add info about multi-line mode for regexp from custom secret rules (#4159)
    * feat(cli): convert JSON reports into a different format (#4452)
    * feat(image): add logic to guess base layer for docker-cis scan (#4344)
    * fix(cyclonedx): set original names for packages (#4306)
    * feat: group subcommands (#4449)
    * feat(cli): add retry to cache operations (#4189)
    * fix(vuln): report architecture for `apk` packages (#4247)
    * refactor: enable cases where return values are not needed in pipeline (#4443)
    * fix(image): resolve scan deadlock when error occurs in slow mode (#4336)
    * docs(misconf): Update docs for kubernetes file patterns (#4435)
    * test: k8s integration tests (#4423)
    * feat(redhat): add package digest for rpm (#4410)
    * feat(misconf): Add `--reset-policy-bundle` for policy bundle (#4167)
    * fix: typo (#4431)
    * add user instruction to imgconf (#4429)
    * fix(k8s): add image sources (#4411)
    * docs(scanning): Add versioning banner (#4415)
    * feat(cli): add mage command to update golden integration test files (#4380)
    * feat: node-collector custom namespace support (#4407)
    * refactor(sbom): use multiline json for spdx-json format (#4404)
    * fix(ubuntu): add EOL date for Ubuntu 23.04 (#4347)
    * refactor: code-optimization (#4214)
    * feat(image): Add image-src flag to specify which runtime(s) to use (#4047)
    *  test: skip wrong update of test golden files (#4379)
    * refactor: don't return error for package.json without version/name (#4377)
    * docs: cmd  error (#4376)
    * test(cli): add test for config file and env combination (#2666)
    * fix(report): set a correct file location for license scan output (#4326)
    * chore(alpine): Update Alpine to 3.18 (#4351)
    * fix(alpine): add EOL date for Alpine 3.18 (#4308)
    * feat: allow root break for mapfs (#4094)
    * docs(misconf): Remove examples.md (#4256)
    * fix(ubuntu): update eol dates for Ubuntu (#4258)
    * feat(alpine): add digests for apk packages (#4168)
    * chore: add discussion templates (#4190)
    * fix(terraform): Support tfvars (#4123)
    * chore: separate docs:generate (#4242)
    * refactor: define vulnerability scanner interfaces (#4117)
    * feat: unified k8s scan resources (#4188)
    * chore: trivy bin ignore (#4212)
    * feat(image): enforce image platform (#4083)
    * fix(ubuntu): fix version selection logic for ubuntu esm (#4171)
    * chore: install.sh support for windows (#4155)
    * docs: moving skipping files out of others (#4154)

    Update to version 0.41.0:

    * fix(spdx): add workaround for no src packages (#4118)
    * test(golang): rename broken go.mod (#4129)
    * feat(sbom): add supplier field (#4122)
    * test(misconf): skip downloading of policies for tests #4126
    * refactor: use debug message for post-analyze errors (#4037)
    * feat(sbom): add VEX support (#4053)
    * feat(sbom): add primary package purpose field for SPDX (#4119)
    * fix(k8s): fix quiet flag (#4120)
    * fix(python): parse of pip extras (#4103)
    * feat(java): use full path for nested jars (#3992)
    * feat(license): add new flag for classifier confidence level (#4073)
    * feat: config and fs compliance support (#4097)
    * feat(spdx): add support for SPDX 2.3 (#4058)
    * fix: k8s all-namespaces support (#4096)
    * perf(misconf): replace with post-analyzers (#4090)
    * fix(helm): update networking API version detection (#4106)
    * feat(image): custom docker host option (#3599)
    * style: debug flag is incorrect and needs extra - (#4087)
    * docs(vuln): Document inline vulnerability filtering comments (#4024)
    * feat(fs): customize error callback during fs walk (#4038)
    * fix(ubuntu): skip copyright files from subfolders (#4076)
    * docs: restructure scanners (#3977)
    * fix: fix `file does not exist` error for post-analyzers (#4061)

    Update to version 0.40.0:

    * feat(flag): Support globstar for `--skip-files` and `--skip-directories` (#4026)
    * fix: return insecure option to download javadb (#4064)
    * fix(nodejs): don't stop parsing when unsupported yarn.lock protocols are found (#4052)
    * fix(k8s): current context title (#4055)
    * fix(k8s): quit support on k8s progress bar (#4021)
    * chore: add a note about Dockerfile.canary (#4050)
    * fix(vuln): report architecture for debian packages (#4032)
    * feat: add support for Chainguard's commercial distro (#3641)
    * fix(vuln): fix error message for remote scanners (#4031)
    * feat(report): add image metadata to SARIF (#4020)
    * docs: fix broken cache link on Installation page (#3999)
    * fix: lock downloading policies and database (#4017)
    * fix: avoid concurrent access to the global map (#4014)
    * feat(rust): add Cargo.lock v3 support (#4012)
    * feat: auth support oci download server subcommand (#4008)
    * chore: install.sh support for armv7 (#3985)

    Update to version 0.39.1:

    * fix(rust): fix panic when 'dependencies' field is not used in cargo.toml (#3997)
    * fix(sbom): fix infinite loop for cyclonedx (#3998)
    * fix: use warning for errors from enrichment files for post-analyzers (#3972)
    * fix(helm): added annotation to psp configurable from values (#3893)
    * fix(secret): update built-in rule `tests`  (#3855)
    * test: rewrite scripts in Go (#3968)
    * docs(cli): Improve glob documentation (#3945)

    Update to version 0.39.0:

    * docs(cli): added makefile and go file to create docs (#3930)
    * feat(cyclonedx): support dependency graph (#3177)
    * feat(server): redis with public TLS certs support (#3783)
    * feat(flag): Add glob support to `--skip-dirs` and `--skip-files`  (#3866)
    * chore: replace make with mage (#3932)
    * fix(sbom): add checksum to files (#3888)
    * chore: remove unused mount volumes (#3927)
    * feat: add auth support for downloading OCI artifacts (#3915)
    * refactor(purl): use epoch in qualifier (#3913)
    * feat(image): add registry options (#3906)
    * feat(rust): dependency tree and line numbers support for cargo lock file (#3746)
    * feat(php): add support for location, licenses and graph for composer.lock files (#3873)
    * feat(image): discover SBOM in OCI referrers (#3768)
    * docs: change cache-dir key in config file (#3897)
    * fix(sbom): use release and epoch for SPDX package version (#3896)
    * docs: Update incorrect comment for skip-update flag (#3878)
    * refactor(misconf): simplify policy filesystem (#3875)
    * feat(nodejs): parse package.json alongside yarn.lock (#3757)
    * fix(spdx): add PkgDownloadLocation field (#3879)
    * chore(amazon): update EOL (#3876)
    * fix(nodejs): improvement logic for package-lock.json v2-v3 (#3877)
    * feat(amazon): add al2023 support (#3854)
    * docs(misconf): Add information about selectors (#3703)
    * docs(cli): update CLI docs with cobra (#3815)
    * feat: k8s parallel processing (#3693)
    * docs: add DefectDojo in the Security Management section (#3871)
    * refactor: add pipeline (#3868)
    * feat(cli): add javadb metadata to version info (#3835)
    * feat(sbom): add support for CycloneDX JSON Attestation of the correct specification (#3849)
    * feat: add node toleration option (#3823)
    * fix: allow mapfs to open dirs (#3867)
    * fix(report): update uri only for os class targets (#3846)
    * feat(nodejs): Add v3 npm lock file support (#3826)
    * feat(nodejs): parse package.json files alongside package-lock.json (#2916)
    * docs(misconf): Fix links to built in policies (#3841)

    Update to version 0.38.3:

      from 1.86.1 to 1.89.1
    * fix(java): skip empty files for jar post analyzer
    * fix(docker): build healthcheck command for line without
      /bin/sh prefix
    * refactor(license): use goyacc for license parser (#3824)
      23.0.0-rc.1+incompatible to 23.0.1+incompatible
    * fix: populate timeout context to node-collector
    * fix: exclude node collector scanning (#3771)
    * fix: display correct flag in error message when skipping
      java db update #3808
    * fix: disable jar analyzer for scanners other than vuln (#3810)
    * fix(sbom): fix incompliant license format for spdx (#3335)
    * fix(java): the project props take precedence over the
      parent's props (#3320)
    * docs: add canary build info to README.md (#3799)
    * docs: adding link to gh token generation (#3784)
    * docs: changing docs in accordance with #3460 (#3787)

    Update to version 0.38.2:

    * fix(license): disable jar analyzer for licence scan only (#3780)
    * bump trivy-issue-action to v0.0.0; skip `pkg` dir (#3781)
    * fix: skip checking dirs for required post-analyzers (#3773)
    * docs: add information about plugin format (#3749)
    * fix(sbom): add trivy version to spdx creators tool field (#3756)

    Update to version 0.38.1:

    * feat(misconf): Add support to show policy bundle version (#3743)
    * fix(python): fix error with optional dependencies in pyproject.toml (#3741)
    * add id for package.json files (#3750)

    Update to version 0.38.0:

    * fix(cli): pass integer to exit-on-eol (#3716)
    * feat: add kubernetes pss compliance (#3498)
    * feat: Adding --module-dir and --enable-modules (#3677)
    * feat: add special IDs for filtering secrets (#3702)
    * docs(misconf): Add guide on input schema (#3692)
    * feat(go): support dependency graph and show only direct dependencies in the tree (#3691)
    * feat: docker multi credential support (#3631)
    * feat: summarize vulnerabilities in compliance reports (#3651)
    * feat(python): parse pyproject.toml alongside poetry.lock (#3695)
    * feat(python): add dependency tree for poetry lock file (#3665)
    * fix(cyclonedx): incompliant affect ref (#3679)
    * chore(helm): update skip-db-update environment variable (#3657)
    * fix(spdx): change CreationInfo timestamp format RFC3336Nano to RFC3336 (#3675)
    * fix(sbom): export empty dependencies in CycloneDX (#3664)
    * docs: java-db air-gap doc tweaks (#3561)
    * feat(go): license support (#3683)
    * feat(ruby): add dependency tree/location support for Gemfile.lock (#3669)
    * fix(k8s): k8s label size (#3678)
    * fix(cyclondx): fix array empty value, null to [] (#3676)
    * refactor: rewrite gomod analyzer as post-analyzer (#3674)
    * feat: config outdated-api result filtered by k8s version (#3578)
    * fix: Update to Alpine 3.17.2 (#3655)
    * feat: add support for virtual files (#3654)
    * feat: add post-analyzers (#3640)
    * feat(python): add dependency locations for Pipfile.lock (#3614)
    * fix(java): fix groupID selection by ArtifactID for jar files. (#3644)
    * fix(aws): Adding a fix for update-cache flag that is not applied on AWS scans. (#3619)
    * feat(cli): add command completion (#3061)
    * docs(misconf): update dockerfile link (#3627)
    * feat(flag): add exit-on-eosl option (#3423)
    * fix(cli): make java db repository configurable (#3595)
    * chore: bump trivy-kubernetes (#3613)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224781");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227022");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6XAQOEGAUMX4BBTNYDJHKA4H3VD5H2PQ/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?586ccb8a");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-42363");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-35192");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-6257");
  script_set_attribute(attribute:"solution", value:
"Update the affected trivy package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42363");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trivy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    {'reference':'trivy-0.54.1-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'trivy');
}
