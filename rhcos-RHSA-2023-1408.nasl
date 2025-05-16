#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1408. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189411);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id("CVE-2022-46149");
  script_xref(name:"RHSA", value:"2023:1408");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.12.9 (RHSA-2023:1408)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing a security update for OpenShift Container Platform 4.12.9.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has a package installed that is affected by a vulnerability as
referenced in the RHSA-2023:1408 advisory.

  - Cap'n Proto is a data interchange format and remote procedure call (RPC) system. Cap'n Proro prior to
    versions 0.7.1, 0.8.1, 0.9.2, and 0.10.3, as well as versions of Cap'n Proto's Rust implementation prior
    to 0.13.7, 0.14.11, and 0.15.2 are vulnerable to out-of-bounds read due to logic error handling list-of-
    list. This issue may lead someone to remotely segfault a peer by sending it a malicious message, if the
    victim performs certain actions on a list-of-pointer type. Exfiltration of memory is possible if the
    victim performs additional certain actions on a list-of-pointer type. To be vulnerable, an application
    must perform a specific sequence of actions, described in the GitHub Security Advisory. The bug is present
    in inlined code, therefore the fix will require rebuilding dependent applications. Cap'n Proto has C++
    fixes available in versions 0.7.1, 0.8.1, 0.9.2, and 0.10.3. The `capnp` Rust crate has fixes available in
    versions 0.13.7, 0.14.11, and 0.15.2. (CVE-2022-46149)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-46149");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1408");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.12.9 packages based on the guidance in RHSA-2023:1408.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46149");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conmon-rs");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat CoreOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.12')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.12', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'conmon-rs-0.5.1-3.rhaos4.12.git.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'conmon-rs-0.5.1-3.rhaos4.12.git.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'RHCOS' + package_array['release'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (reference &&
      _release &&
      (!exists_check || rpm_exists(release:_release, rpm:exists_check)) &&
      rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'conmon-rs');
}
