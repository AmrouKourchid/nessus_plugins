#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:1802. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190168);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id(
    "CVE-2023-0547",
    "CVE-2023-1945",
    "CVE-2023-1999",
    "CVE-2023-28427",
    "CVE-2023-29479",
    "CVE-2023-29533",
    "CVE-2023-29535",
    "CVE-2023-29536",
    "CVE-2023-29539",
    "CVE-2023-29541",
    "CVE-2023-29548",
    "CVE-2023-29550"
  );
  script_xref(name:"IAVA", value:"2023-A-0166-S");
  script_xref(name:"IAVA", value:"2023-A-0199-S");
  script_xref(name:"RHSA", value:"2023:1802");

  script_name(english:"CentOS 8 : thunderbird (CESA-2023:1802)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
CESA-2023:1802 advisory.

  - OCSP revocation status of recipient certificates was not checked when sending S/Mime encrypted email, and
    revoked certificates would be accepted. Thunderbird versions from 68 to 102.9.1 were affected by this bug.
    This vulnerability affects Thunderbird < 102.10. (CVE-2023-0547)

  - Unexpected data returned from the Safe Browsing API could have led to memory corruption and a potentially
    exploitable crash. This vulnerability affects Thunderbird < 102.10 and Firefox ESR < 102.10.
    (CVE-2023-1945)

  - There exists a use after free/double free in libwebp. An attacker can use the ApplyFiltersAndEncode()
    function and loop through to free best.bw and assign best = trial pointer. The second loop will then
    return 0 because of an Out of memory error in VP8 encoder, the pointer is still assigned to trial and the
    AddressSanitizer will attempt a double free. (CVE-2023-1999)

  - matrix-js-sdk is a Matrix messaging protocol Client-Server SDK for JavaScript. In versions prior to 24.0.0
    events sent with special strings in key places can temporarily disrupt or impede the matrix-js-sdk from
    functioning properly, potentially impacting the consumer's ability to process data safely. Note that the
    matrix-js-sdk can appear to be operating normally but be excluding or corrupting runtime data presented to
    the consumer. This vulnerability is distinct from GHSA-rfv9-x7hh-xc32 which covers a similar issue. The
    issue has been patched in matrix-js-sdk 24.0.0 and users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-28427)

  - Ribose RNP before 0.16.3 may hang when the input is malformed. (CVE-2023-29479)

  - A website could have obscured the fullscreen notification by using a combination of
    <code>window.open</code>, fullscreen requests, <code>window.name</code> assignments, and
    <code>setInterval</code> calls. This could have led to user confusion and possible spoofing attacks. This
    vulnerability affects Firefox < 112, Focus for Android < 112, Firefox ESR < 102.10, Firefox for Android <
    112, and Thunderbird < 102.10. (CVE-2023-29533)

  - Following a Garbage Collector compaction, weak maps may have been accessed before they were correctly
    traced. This resulted in memory corruption and a potentially exploitable crash. This vulnerability affects
    Firefox < 112, Focus for Android < 112, Firefox ESR < 102.10, Firefox for Android < 112, and Thunderbird <
    102.10. (CVE-2023-29535)

  - An attacker could cause the memory manager to incorrectly free a pointer that addresses attacker-
    controlled memory, resulting in an assertion, memory corruption, or a potentially exploitable crash. This
    vulnerability affects Firefox < 112, Focus for Android < 112, Firefox ESR < 102.10, Firefox for Android <
    112, and Thunderbird < 102.10. (CVE-2023-29536)

  - When handling the filename directive in the Content-Disposition header, the filename would be truncated if
    the filename contained a NULL character. This could have led to reflected file download attacks
    potentially tricking users to install malware. This vulnerability affects Firefox < 112, Focus for Android
    < 112, Firefox ESR < 102.10, Firefox for Android < 112, and Thunderbird < 102.10. (CVE-2023-29539)

  - Firefox did not properly handle downloads of files ending in <code>.desktop</code>, which can be
    interpreted to run attacker-controlled commands. <br>*This bug only affects Firefox for Linux on certain
    Distributions. Other operating systems are unaffected, and Mozilla is unable to enumerate all affected
    Linux Distributions.*. This vulnerability affects Firefox < 112, Focus for Android < 112, Firefox ESR <
    102.10, Firefox for Android < 112, and Thunderbird < 102.10. (CVE-2023-29541)

  - A wrong lowering instruction in the ARM64 Ion compiler resulted in a wrong optimization result. This
    vulnerability affects Firefox < 112, Focus for Android < 112, Firefox ESR < 102.10, Firefox for Android <
    112, and Thunderbird < 102.10. (CVE-2023-29548)

  - Memory safety bugs present in Firefox 111 and Firefox ESR 102.9. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort some of these could have been exploited to run
    arbitrary code. This vulnerability affects Firefox < 112, Focus for Android < 112, Firefox ESR < 102.10,
    Firefox for Android < 112, and Thunderbird < 102.10. (CVE-2023-29550)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1802");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29550");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'thunderbird-102.10.0-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-102.10.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird');
}
