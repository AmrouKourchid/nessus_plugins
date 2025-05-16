#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2023:4954.
##

include('compat.inc');

if (description)
{
  script_id(182724);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2023-4051",
    "CVE-2023-4053",
    "CVE-2023-4573",
    "CVE-2023-4574",
    "CVE-2023-4575",
    "CVE-2023-4577",
    "CVE-2023-4578",
    "CVE-2023-4580",
    "CVE-2023-4581",
    "CVE-2023-4583",
    "CVE-2023-4584",
    "CVE-2023-4585"
  );
  script_xref(name:"IAVA", value:"2023-A-0449-S");
  script_xref(name:"RLSA", value:"2023:4954");

  script_name(english:"Rocky Linux 8 : thunderbird (RLSA-2023:4954)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2023:4954 advisory.

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks. This vulnerability affects Firefox < 116, Firefox ESR
    < 115.2, and Thunderbird < 115.2. (CVE-2023-4051)

  - A website could have obscured the full screen notification by using a URL with a scheme handled by an
    external program, such as a mailto URL. This could have led to user confusion and possible spoofing
    attacks. This vulnerability affects Firefox < 116, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4053)

  - When receiving rendering data over IPC `mStream` could have been destroyed when initialized, which could
    have led to a use-after-free causing a potentially exploitable crash. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4573)

  - When creating a callback over IPC for showing the Color Picker window, multiple of the same callbacks
    could have been created at a time and eventually all simultaneously destroyed as soon as one of the
    callbacks finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and
    Thunderbird < 115.2. (CVE-2023-4574)

  - When creating a callback over IPC for showing the File Picker window, multiple of the same callbacks could
    have been created at a time and eventually all simultaneously destroyed as soon as one of the callbacks
    finished. This could have led to a use-after-free causing a potentially exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and
    Thunderbird < 115.2. (CVE-2023-4575)

  - When `UpdateRegExpStatics` attempted to access `initialStringHeap` it could already have been garbage
    collected prior to entering the function, which could potentially have led to an exploitable crash. This
    vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2. (CVE-2023-4577)

  - When calling `JS::CheckRegExpSyntax` a Syntax Error could have been set which would end in calling
    `convertToRuntimeErrorAndClear`. A path in the function could attempt to allocate memory when none is
    available which would have caused a newly created Out of Memory exception to be mishandled as a Syntax
    Error. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and Thunderbird < 115.2.
    (CVE-2023-4578)

  - Push notifications stored on disk in private browsing mode were not being encrypted potentially allowing
    the leak of sensitive information. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4580)

  - Excel `.xll` add-in files did not have a blocklist entry in Firefox's executable blocklist which allowed
    them to be downloaded without any warning of their potential harm. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4581)

  - When checking if the Browsing Context had been discarded in `HttpBaseChannel`, if the load group was not
    available then it was assumed to have already been discarded which was not always the case for private
    channels after the private session had ended. This vulnerability affects Firefox < 117, Firefox ESR <
    115.2, and Thunderbird < 115.2. (CVE-2023-4583)

  - Memory safety bugs present in Firefox 116, Firefox ESR 102.14, Firefox ESR 115.1, Thunderbird 102.14, and
    Thunderbird 115.1. Some of these bugs showed evidence of memory corruption and we presume that with enough
    effort some of these could have been exploited to run arbitrary code. This vulnerability affects Firefox <
    117, Firefox ESR < 102.15, Firefox ESR < 115.2, Thunderbird < 102.15, and Thunderbird < 115.2.
    (CVE-2023-4584)

  - Memory safety bugs present in Firefox 116, Firefox ESR 115.1, and Thunderbird 115.1. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. This vulnerability affects Firefox < 117, Firefox ESR < 115.2, and
    Thunderbird < 115.2. (CVE-2023-4585)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2023:4954");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236071");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236072");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236073");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236077");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236078");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236079");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236080");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236084");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236086");
  script_set_attribute(attribute:"solution", value:
"Update the affected thunderbird, thunderbird-debuginfo and / or thunderbird-debugsource packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4585");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:thunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'thunderbird-102.15.0-1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-102.15.0-1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.15.0-1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debuginfo-102.15.0-1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-102.15.0-1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'thunderbird-debugsource-102.15.0-1.el8_8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'thunderbird / thunderbird-debuginfo / thunderbird-debugsource');
}
