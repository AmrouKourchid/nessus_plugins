#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2024:0141.
##

include('compat.inc');

if (description)
{
  script_id(187981);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/21");

  script_cve_id("CVE-2023-5455");
  script_xref(name:"ALSA", value:"2024:0141");

  script_name(english:"AlmaLinux 9 : ipa (ALSA-2024:0141)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2024:0141 advisory.

  - A Cross-site request forgery vulnerability exists in ipa/session/login_password in all supported versions
    of IPA. This flaw allows an attacker to trick the user into submitting a request that could perform
    actions as the user, resulting in a loss of confidentiality and system integrity. During community
    penetration testing it was found that for certain HTTP end-points FreeIPA does not ensure CSRF protection.
    Due to implementation details one cannot use this flaw for reflection of a cookie representing already
    logged-in user. An attacker would always have to go through a new authentication attempt. (CVE-2023-5455)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2024-0141.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:python3-ipatests");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'ipa-client-4.10.2-5.el9_3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.10.2-5.el9_3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.10.2-5.el9_3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.10.2-5.el9_3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.10.2-5.el9_3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.10.2-5.el9_3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-selinux-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.10.2-5.el9_3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.10.2-5.el9_3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.10.2-5.el9_3.alma.1', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.10.2-5.el9_3.alma.1', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaclient-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipalib-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaserver-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipatests-4.10.2-5.el9_3.alma.1', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa-client / ipa-client-common / ipa-client-epn / ipa-client-samba / etc');
}
