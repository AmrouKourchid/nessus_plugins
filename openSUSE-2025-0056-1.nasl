#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0056-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(215185);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/10");

  script_cve_id(
    "CVE-2024-3817",
    "CVE-2024-34155",
    "CVE-2024-34156",
    "CVE-2024-34158",
    "CVE-2024-45337",
    "CVE-2024-45338",
    "CVE-2025-21613",
    "CVE-2025-21614"
  );

  script_name(english:"openSUSE 15 Security Update : trivy (openSUSE-SU-2025:0056-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2025:0056-1 advisory.

    Update to version 0.58.2 (

          boo#1234512, CVE-2024-45337,
          boo#1235265, CVE-2024-45338):

      * fix(misconf): allow null values only for tf variables [backport: release/v0.58] (#8238)
      * fix(suse): SUSE - update OSType constants and references for compatility [backport: release/v0.58]
    (#8237)
      * fix: CVE-2025-21613 and CVE-2025-21614 : go-git: argument injection via the URL field [backport:
    release/v0.58] (#8215)
      * fix(sbom): attach nested packages to Application [backport: release/v0.58] (#8168)
      * fix(python): skip dev group's deps for poetry [backport: release/v0.58] (#8158)
      * fix(sbom): use root package for `unknown` dependencies (if exists) [backport: release/v0.58] (#8156)
      * chore(deps): bump `golang.org/x/net` from `v0.32.0` to `v0.33.0` [backport: release/v0.58] (#8142)
      * chore(deps): bump `github.com/CycloneDX/cyclonedx-go` from `v0.9.1` to `v0.9.2` [backport:
    release/v0.58] (#8136)
      * fix(redhat): correct rewriting of recommendations for the same vulnerability [backport: release/v0.58]
    (#8135)
      * fix(oracle): add architectures support for advisories [backport: release/v0.58] (#8125)
      * fix(sbom): fix wrong overwriting of applications obtained from different sbom files but having same
    app type [backport: release/v0.58] (#8124)
      * chore(deps): bump golang.org/x/crypto from 0.30.0 to 0.31.0 [backport: release/v0.58] (#8122)
      * fix: handle `BLOW_UNKNOWN` error to download DBs [backport: release/v0.58] (#8121)
      * fix(java): correctly overwrite version from depManagement if dependency uses `project.*` props
    [backport: release/v0.58] (#8119)
      * release: v0.58.0 [main] (#7874)
      * fix(misconf): wrap AWS EnvVar to iac types (#7407)
      * chore(deps): Upgrade trivy-checks (#8018)
      * refactor(misconf): Remove unused options (#7896)
      * docs: add terminology page to explain Trivy concepts (#7996)
      * feat: add `workspaceRelationship` (#7889)
      * refactor(sbom): simplify relationship generation (#7985)
      * docs: improve databases documentation (#7732)
      * refactor: remove support for custom Terraform checks (#7901)
      * docs: drop AWS account scanning (#7997)
      * fix(aws): change CPU and Memory type of ContainerDefinition to a string (#7995)
      * fix(cli): Handle empty ignore files more gracefully (#7962)
      * fix(misconf): load full Terraform module (#7925)
      * fix(misconf): properly resolve local Terraform cache (#7983)
      * refactor(k8s): add v prefix for Go packages (#7839)
      * test: replace Go checks with Rego (#7867)
      * feat(misconf): log causes of HCL file parsing errors (#7634)
      * chore(deps): bump the aws group across 1 directory with 7 updates (#7991)
      * chore(deps): bump github.com/moby/buildkit from 0.17.0 to 0.17.2 in the docker group across 1
    directory (#7990)
      * chore(deps): update csaf module dependency from csaf-poc to gocsaf (#7992)
      * chore: downgrade the failed block expand message to debug (#7964)
      * fix(misconf): do not erase variable type for child modules (#7941)
      * feat(go): construct dependencies of `go.mod` main module in the parser (#7977)
      * feat(go): construct dependencies in the parser (#7973)
      * feat: add cvss v4 score and vector in scan response (#7968)
      * docs: add `overview` page for `others` (#7972)
      * fix(sbom): Fixes for Programming Language Vulnerabilities and SBOM Package Maintainer Details (#7871)
      * feat(suse): Align SUSE/OpenSUSE OS Identifiers (#7965)
      * chore(deps): bump the common group with 4 updates (#7949)
      * feat(oracle): add `flavors` support (#7858)
      * fix(misconf): Update trivy-checks default repo to `mirror.gcr.io` (#7953)
      * chore(deps): Bump up trivy-checks to v1.3.0 (#7959)
      * fix(k8s): check all results for vulnerabilities (#7946)
      * ci(helm): bump Trivy version to 0.57.1 for Trivy Helm Chart 0.9.0 (#7945)
      * feat(secret): Add built-in secrets rules for Private Packagist (#7826)
      * docs: Fix broken links (#7900)
      * docs: fix mistakes/typos (#7942)
      * feat: Update registry fallbacks (#7679)
      * fix(alpine): add `UID` for removed packages (#7887)
      * chore(deps): bump the aws group with 6 updates (#7902)
      * chore(deps): bump the common group with 6 updates (#7904)
      * fix(debian): infinite loop (#7928)
      * fix(redhat): don't return error if `root/buildinfo/content_manifests/` contains files that are not
    `contentSets` files (#7912)
      * docs: add note about temporary podman socket (#7921)
      * docs: combine trivy.dev into trivy docs (#7884)
      * test: change branch in spdx schema link to check in integration tests (#7935)
      * docs: add Headlamp to the Trivy Ecosystem page (#7916)
      * fix(report): handle `git@github.com` schema for misconfigs in `sarif` report (#7898)
      * chore(k8s): enhance k8s scan log (#6997)
      * fix(terraform): set null value as fallback for missing variables (#7669)
      * fix(misconf): handle null properties in CloudFormation templates (#7813)
      * fix(fs): add missing defered Cleanup() call to post analyzer fs (#7882)
      * chore(deps): bump the common group across 1 directory with 20 updates (#7876)
      * chore: bump containerd to v2.0.0 (#7875)
      * fix: Improve version comparisons when build identifiers are present (#7873)
      * feat(k8s): add default commands for unknown platform (#7863)
      * chore(deps): bump github.com/golang-jwt/jwt/v4 from 4.5.0 to 4.5.1 (#7868)
      * refactor(secret): optimize performance by moving ToLower operation outside loop (#7862)
      * test: save `containerd` image into archive and use in tests (#7816)
      * chore(deps): bump the github-actions group across 1 directory with 2 updates (#7854)
      * chore: bump golangci-lint to v1.61.0 (#7853)

    - Update to version 0.57.1:
      * release: v0.57.1 [release/v0.57] (#7943)
      * feat: Update registry fallbacks [backport: release/v0.57] (#7944)
      * fix(redhat): don't return error if `root/buildinfo/content_manifests/` contains files that are not
    `contentSets` files [backport: release/v0.57] (#7939)
      * test: change branch in spdx schema link to check in integration tests [backport: release/v0.57]
    (#7940)
      * release: v0.57.0 [main] (#7710)
      * chore: lint `errors.Join` (#7845)
      * feat(db): append errors (#7843)
      * docs(java): add info about supported scopes (#7842)
      * docs: add example of creating whitelist of checks (#7821)
      * chore(deps): Bump trivy-checks (#7819)
      * fix(go): Do not trim v prefix from versions in Go Mod Analyzer (#7733)
      * fix(k8s): skip resources without misconfigs (#7797)
      * fix(sbom):  use `Annotation` instead of `AttributionTexts` for `SPDX` formats (#7811)
      * fix(cli): add config name to skip-policy-update alias (#7820)
      * fix(helm): properly handle multiple archived dependencies (#7782)
      * refactor(misconf): Deprecate `EXCEPTIONS` for misconfiguration scanning (#7776)
      * fix(k8s)!: support k8s multi container (#7444)
      * fix(k8s): support kubernetes v1.31 (#7810)
      * docs: add Windows install instructions (#7800)
      * ci(helm): auto public Helm chart after PR merged (#7526)
      * feat: add end of life date for Ubuntu 24.10 (#7787)
      * feat(report): update gitlab template to populate operating_system value (#7735)
      * feat(misconf): Show misconfig ID in output (#7762)
      * feat(misconf): export unresolvable field of IaC types to Rego (#7765)
      * refactor(k8s): scan config files as a folder (#7690)
      * fix(license): fix license normalization for Universal Permissive License (#7766)
      * fix: enable usestdlibvars linter (#7770)
      * fix(misconf): properly expand dynamic blocks (#7612)
      * feat(cyclonedx): add file checksums to `CycloneDX` reports (#7507)
      * fix(misconf): fix for Azure Storage Account network acls adaptation (#7602)
      * refactor(misconf): simplify k8s scanner (#7717)
      * feat(parser): ignore white space in pom.xml files (#7747)
      * test: use forked images (#7755)
      * fix(java): correctly inherit `version` and `scope` from upper/root `depManagement` and `dependencies`
    into parents (#7541)
      * fix(misconf): check if property is not nil before conversion (#7578)
      * fix(misconf): change default ACL of digitalocean_spaces_bucket to private (#7577)
      * feat(misconf): ssl_mode support for GCP SQL DB instance (#7564)
      * test: define constants for test images (#7739)
      * docs: add note about disabled DS016 check (#7724)
      * feat(misconf): public network support for Azure Storage Account (#7601)
      * feat(cli): rename `trivy auth` to `trivy registry` (#7727)
      * docs: apt-transport-https is a transitional package (#7678)
      * refactor(misconf): introduce generic scanner (#7515)
      * fix(cli): `clean --all` deletes only relevant dirs (#7704)
      * feat(cli): add `trivy auth` (#7664)
      * fix(sbom): add options for DBs in private registries (#7660)
      * docs(report): fix reporting doc format (#7671)
      * fix(repo): `git clone` output to Stderr (#7561)
      * fix(redhat): include arch in PURL qualifiers (#7654)
      * fix(report): Fix invalid URI in SARIF report (#7645)
      * docs(report): Improve SARIF reporting doc (#7655)
      * fix(db): fix javadb downloading error handling (#7642)
      * feat(cli): error out when ignore file cannot be found (#7624)

    - Update to version 0.56.2:
      * release: v0.56.2 [release/v0.56] (#7694)
      * fix(redhat): include arch in PURL qualifiers [backport: release/v0.56] (#7702)
      * fix(sbom): add options for DBs in private registries [backport: release/v0.56] (#7691)

    - Update to version 0.56.1:
      * release: v0.56.1 [release/v0.56] (#7648)
      * fix(db): fix javadb downloading error handling [backport: release/v0.56] (#7646)
      * release: v0.56.0 [main] (#7447)
      * fix(misconf): not to warn about missing selectors of libraries (#7638)
      * feat: support RPM archives (#7628)
      * fix(secret): change grafana token regex to find them without unquoted (#7627)
      * fix(misconf): Disable deprecated checks by default (#7632)
      * chore: add prefixes to log messages (#7625)
      * feat(misconf): Support `--skip-*` for all included modules  (#7579)
      * feat: support multiple DB repositories for vulnerability and Java DB (#7605)
      * ci: don't use cache for `setup-go` (#7622)
      * test: use loaded image names (#7617)
      * feat(java): add empty versions if `pom.xml` dependency versions can't be detected (#7520)
      * feat(secret): enhance secret scanning for python binary files (#7223)
      * refactor: fix auth error handling (#7615)
      * ci: split `save` and `restore` cache actions (#7614)
      * fix(misconf): disable DS016 check for image history analyzer (#7540)
      * feat(suse): added SUSE Linux Enterprise Micro support (#7294)
      * feat(misconf): add ability to disable checks by ID (#7536)
      * fix(misconf): escape all special sequences (#7558)
      * test: use a local registry for remote scanning (#7607)
      * fix: allow access to '..' in mapfs (#7575)
      * fix(db): check `DownloadedAt` for `trivy-java-db` (#7592)
      * chore(deps): bump the common group across 1 directory with 20 updates (#7604)
      * ci: add `workflow_dispatch` trigger for test workflow. (#7606)
      * ci: cache test images for `integration`, `VM` and `module` tests (#7599)
      * chore(deps): remove broken replaces for opa and discovery (#7600)
      * docs(misconf): Add more info on how to use arbitrary JSON/YAML scan feat (#7458)
      * fix(misconf): Fixed scope for China Cloud (#7560)
      * perf(misconf): use port ranges instead of enumeration (#7549)
      * fix(sbom): export bom-ref when converting a package to a component (#7340)
      * refactor(misconf): pass options to Rego scanner as is (#7529)
      * fix(sbom): parse type `framework` as `library` when unmarshalling `CycloneDX` files (#7527)
      * chore(deps): bump go-ebs-file (#7513)
      * fix(misconf): Fix logging typo (#7473)
      * feat(misconf): Register checks only when needed (#7435)
      * refactor: split `.egg` and `packaging` analyzers (#7514)
      * fix(java): use `dependencyManagement` from root/child pom's for dependencies from parents (#7497)
      * chore(vex): add `CVE-2024-34155`, `CVE-2024-34156` and `CVE-2024-34158` in `trivy.openvex.json`
    (#7510)
      * chore(deps): bump alpine from 3.20.0 to 3.20.3 (#7508)
      * chore(vex): suppress openssl vulnerabilities (#7500)
      * revert(java): stop supporting of `test` scope for `pom.xml` files (#7488)
      * docs(db): add a manifest example (#7485)
      * feat(license): improve license normalization (#7131)
      * docs(oci): Add a note About the expected Media Type for the Trivy-DB OCI Artifact (#7449)
      * fix(report): fix error with unmarshal of `ExperimentalModifiedFindings` (#7463)
      * fix(report): change a receiver of MarshalJSON (#7483)
      * fix(oracle): Update EOL date for Oracle 7 (#7480)
      * chore(deps): bump the aws group with 6 updates (#7468)
      * chore(deps): bump the common group across 1 directory with 19 updates (#7436)
      * chore(helm): bump up Trivy Helm chart (#7441)
      * refactor(java): add error/statusCode for logs when we can't get pom.xml/maven-metadata.xml from remote
    repo (#7451)
      * fix(license): stop spliting a long license text (#7336)
      * release: v0.55.0 [main] (#7271)
      * feat(go): use `toolchain` as `stdlib` version for `go.mod` files (#7163)
      * fix(license): add license handling to JUnit template (#7409)
      * feat(java): add `test` scope support for `pom.xml` files (#7414)
      * chore(deps): Bump trivy-checks and pin OPA (#7427)
      * fix(helm): explicitly define `kind` and `apiVersion` of `volumeClaimTemplate` element (#7362)
      * feat(sbom): set User-Agent header on requests to Rekor (#7396)
      * test: add integration plugin tests (#7299)
      * fix(nodejs): check all `importers` to detect dev deps from pnpm-lock.yaml file (#7387)
      * fix: logger initialization before flags parsing (#7372)
      * fix(aws): handle ECR repositories in different regions (#6217)
      * fix(misconf): fix infer type for null value (#7424)
      * fix(secret): use `.eyJ` keyword for JWT secret (#7410)
      * fix(misconf): do not recreate filesystem map (#7416)
      * chore(deps): Bump trivy-checks (#7417)
      * fix(misconf): do not register Rego libs in checks registry (#7420)
      * fix(sbom): use `NOASSERTION` for licenses fields in SPDX formats (#7403)
      * feat(report): export modified findings in JSON (#7383)
      * feat(server): Make Trivy Server Multiplexer Exported (#7389)
      * chore: update CODEOWNERS (#7398)
      * fix(secret): use only line with secret for long secret lines (#7412)
      * chore: fix allow rule of ignoring test files to make it case insensitive (#7415)
      * feat(misconf): port and protocol support for EC2 networks (#7146)
      * fix(misconf): do not filter Terraform plan JSON by name (#7406)
      * feat(misconf): support for ignore by nested attributes (#7205)
      * fix(misconf): use module to log when metadata retrieval fails (#7405)
      * fix(report): escape `Message` field in `asff.tpl` template (#7401)
      * feat(misconf): Add support for using spec from on-disk bundle (#7179)
      * docs: add pkg flags to config file page (#7370)
      * feat(python): use minimum version for pip packages (#7348)
      * fix(misconf): support deprecating for Go checks (#7377)
      * fix(misconf): init frameworks before updating them (#7376)
      * feat(misconf): ignore duplicate checks (#7317)
      * refactor(misconf): use slog (#7295)
      * chore(deps): bump trivy-checks (#7350)
      * feat(server): add internal `--path-prefix` flag for client/server mode (#7321)
      * chore(deps): bump the aws group across 1 directory with 7 updates (#7358)
      * fix: safely check if the directory exists (#7353)
      * feat(misconf): variable support for Terraform Plan (#7228)
      * feat(misconf): scanning support for YAML and JSON (#7311)
      * fix(misconf): wrap Azure PortRange in iac types (#7357)
      * refactor(misconf): highlight only affected rows (#7310)
      * fix(misconf): change default TLS values for the Azure storage account (#7345)
      * chore(deps): bump the common group with 9 updates (#7333)
      * docs(misconf): Update callsites to use correct naming (#7335)
      * docs: update air-gapped docs (#7160)
      * refactor: replace ftypes.Gradle with packageurl.TypeGradle (#7323)
      * perf(misconf): optimize work with context (#6968)
      * docs: update links to packaging.python.org (#7318)
      * docs: update client/server docs for misconf and license scanning (#7277)
      * chore(deps): bump the common group across 1 directory with 7 updates (#7305)
      * feat(misconf): iterator argument support for dynamic blocks (#7236)
      * fix(misconf): do not set default value for default_cache_behavior (#7234)
      * feat(misconf): support for policy and bucket grants (#7284)
      * fix(misconf): load only submodule if it is specified in source (#7112)
      * perf(misconf): use json.Valid to check validity of JSON (#7308)
      * refactor(misconf): remove unused universal scanner (#7293)
      * perf(misconf): do not convert contents of a YAML file to string (#7292)
      * fix(terraform): add aws_region name to presets (#7184)
      * docs: add auto-generated config (#7261)
      * feat(vuln): Add `--detection-priority` flag for accuracy tuning (#7288)
      * refactor(misconf): remove file filtering from parsers (#7289)
      * fix(flag): incorrect behavior for deprected flag `--clear-cache` (#7281)
      * fix(java): Return error when trying to find a remote pom to avoid segfault (#7275)
      * fix(plugin): do not call GitHub content API for releases and tags (#7274)
      * feat(vm): support the Ext2/Ext3 filesystems (#6983)
      * feat(cli)!: delete deprecated SBOM flags (#7266)
      * feat(vm): Support direct filesystem (#7058)

    - Update to version 0.51.1 (boo#1227010, CVE-2024-3817):

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1235265");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DUNHR7ATZWEF5LQKUNEXKL22CUQAND3A/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6d4d16c");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34155");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34156");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-34158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3817");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45337");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21614");
  script_set_attribute(attribute:"solution", value:
"Update the affected trivy package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/U:Clear");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21613");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:trivy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'reference':'trivy-0.58.2-bp156.2.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'trivy');
}
