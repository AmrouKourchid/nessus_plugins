#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:0003.
##

include('compat.inc');

if (description)
{
  script_id(187643);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id(
    "CVE-2023-6856",
    "CVE-2023-6857",
    "CVE-2023-6858",
    "CVE-2023-6859",
    "CVE-2023-6860",
    "CVE-2023-6861",
    "CVE-2023-6862",
    "CVE-2023-6863",
    "CVE-2023-6864",
    "CVE-2023-50761",
    "CVE-2023-50762"
  );
  script_xref(name:"ALSA", value:"2024:0003");
  script_xref(name:"IAVA", value:"2023-A-0702-S");

  script_name(english:"AlmaLinux 8 : thunderbird (ALSA-2024:0003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ALSA-2024:0003 advisory.

  - The signature of a digitally signed S/MIME email message may optionally specify the signature creation
    date and time. If present, Thunderbird did not compare the signature creation date with the message date
    and time, and displayed a valid signature despite a date or time mismatch. This could be used to give
    recipients the impression that a message was sent at a different date or time. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50761)

  - When processing a PGP/MIME payload that contains digitally signed text, the first paragraph of the text
    was never shown to the user. This is because the text was interpreted as a MIME message and the first
    paragraph was always treated as an email header section. A digitally signed text from a different context,
    such as a signed GIT commit, could be used to spoof an email message. This vulnerability affects
    Thunderbird < 115.6. (CVE-2023-50762)

  - The WebGL `DrawElementsInstanced` method was susceptible to a heap buffer overflow when used on systems
    with the Mesa VM driver. This issue could allow an attacker to perform remote code execution and sandbox
    escape. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6856)

  - When resolving a symlink, a race may occur where the buffer passed to `readlink` may actually be smaller
    than necessary. *This bug only affects Firefox on Unix-based operating systems (Android, Linux, MacOS).
    Windows is unaffected.* This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox <
    121. (CVE-2023-6857)

  - Firefox was susceptible to a heap buffer overflow in `nsTextFragment` due to insufficient OOM handling.
    This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6858)

  - A use-after-free condition affected TLS socket creation when under memory pressure. This vulnerability
    affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121. (CVE-2023-6859)

  - The `VideoBridge` allowed any content process to use textures produced by remote decoders. This could be
    abused to escape the sandbox. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6860)

  - The `nsWindow::PickerOpen(void)` method was susceptible to a heap buffer overflow when running in headless
    mode. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and Firefox < 121.
    (CVE-2023-6861)

  - A use-after-free was identified in the `nsDNSService::Init`. This issue appears to manifest rarely during
    start-up. This vulnerability affects Firefox ESR < 115.6 and Thunderbird < 115.6. (CVE-2023-6862)

  - The `ShutdownObserver()` was susceptible to potentially undefined behavior due to its reliance on a
    dynamic type that lacked a virtual destructor. This vulnerability affects Firefox ESR < 115.6, Thunderbird
    < 115.6, and Firefox < 121. (CVE-2023-6863)

  - Memory safety bugs present in Firefox 120, Firefox ESR 115.5, and Thunderbird 115.5. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox ESR < 115.6, Thunderbird < 115.6, and
    Firefox < 121. (CVE-2023-6864)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2024-0003.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6864");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 122, 20, 347, 363, 416);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::powertools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'thunderbird-115.6.0-1.el8_9.alma', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-115.6.0-1.el8_9.alma', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
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
