#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3151-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(206758);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/07");

  script_cve_id(
    "CVE-2024-1753",
    "CVE-2024-3727",
    "CVE-2024-24786",
    "CVE-2024-28180"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3151-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : buildah (SUSE-SU-2024:3151-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has a package installed that is affected by multiple
vulnerabilities as referenced in the SUSE-SU-2024:3151-1 advisory.

    Update to version 1.35.4:

    * Bump to Buildah v1.35.4
    * CVE-2024-3727 updates (bsc#1224117)
    * integration test: handle new labels in 'bud and test --unsetlabel'
    * Bump go-jose CVE-2024-28180
    * Bump ocicrypt and go-jose CVE-2024-28180

    Update to version 1.35.3:

    * correctly configure /etc/hosts and resolv.conf
    * buildah: refactor resolv/hosts setup.
    * CVE-2024-24786 protobuf to 1.33


    Update to version 1.35.1:

    * CVE-2024-1753 container escape fix (bsc#1221677)

    - Buildah dropped cni support, require netavark instead (bsc#1221243)

    - Remove obsolete requires libcontainers-image & libcontainers-storage

    - Require passt for rootless networking (poo#156955)
      Buildah moved to passt/pasta for rootless networking from slirp4netns
      (https://github.com/containers/common/pull/1846)

    Update to version 1.35.0:

    * Bump c/common v0.58.0, c/image v5.30.0, c/storage v1.53.0
    * conformance tests: don't break on trailing zeroes in layer blobs
    * Add a conformance test for copying to a mounted prior stage
    * cgroups: reuse version check from c/common
    * Update vendor of containers/(common,image)
    * manifest add: complain if we get artifact flags without --artifact
    * Use retry logic from containers/common
    * Vendor in containers/(storage,image,common)
    * Update module golang.org/x/crypto to v0.20.0
    * Add comment re: Total Success task name
    * tests: skip_if_no_unshare(): check for --setuid
    * Properly handle build --pull=false
    * [skip-ci] Update tim-actions/get-pr-commits action to v1.3.1
    * Update module go.etcd.io/bbolt to v1.3.9
    * Revert 'Reduce official image size'
    * Update module github.com/opencontainers/image-spec to v1.1.0
    * Reduce official image size
    * Build with CNI support on FreeBSD
    * build --all-platforms: skip some base 'image' platforms
    * Bump main to v1.35.0-dev
    * Vendor in latest containers/(storage,image,common)
    * Split up error messages for missing --sbom related flags
    * `buildah manifest`: add artifact-related options
    * cmd/buildah/manifest.go: lock lists before adding/annotating/pushing
    * cmd/buildah/manifest.go: don't make struct declarations aliases
    * Use golang.org/x/exp/slices.Contains
    * Disable loong64 again
    * Fix a couple of typos in one-line comments
    * egrep is obsolescent; use grep -E
    * Try Cirrus with a newer VM version
    * Set CONTAINERS_CONF in the chroot-mount-flags integration test
    * Update to match dependency API update
    * Update github.com/openshift/imagebuilder and containers/common
    * docs: correct default authfile path
    * tests: retrofit test for heredoc summary
    * build, heredoc: show heredoc summary in build output
    * manifest, push: add support for --retry and --retry-delay
    * imagebuildah: fix crash with empty RUN
    * Make buildah match podman for handling of ulimits
    * docs: move footnotes to where they're applicable
    * Allow users to specify no-dereference
    * docs: use reversed logo for dark theme in README
    * build,commit: add --sbom to scan and produce SBOMs when committing
    * commit: force omitHistory if the parent has layers but no history
    * docs: fix a couple of typos
    * internal/mkcw.Archive(): handle extra image content
    * stage_executor,heredoc: honor interpreter in heredoc
    * stage_executor,layers: burst cache if heredoc content is changed
    * Replace map[K]bool with map[K]struct{} where it makes sense
    * Replace strings.SplitN with strings.Cut
    * Document use of containers-transports values in buildah
    * manifest: addCompression use default from containers.conf
    * commit: add a --add-file flag
    * mkcw: populate the rootfs using an overlay
    * Ignore errors if label.Relabel returns ENOSUP

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221677");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224117");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036812.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3bea6aa9");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-1753");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-28180");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3727");
  script_set_attribute(attribute:"solution", value:
"Update the affected buildah package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-28180");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1753");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:buildah");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'buildah-1.35.4-150500.3.10.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'buildah-1.35.4-150500.3.10.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'buildah-1.35.4-150500.3.10.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'buildah-1.35.4-150500.3.10.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-containers-release-15.6', 'sles-release-15.6']},
    {'reference':'buildah-1.35.4-150500.3.10.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'buildah-1.35.4-150500.3.10.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah');
}
