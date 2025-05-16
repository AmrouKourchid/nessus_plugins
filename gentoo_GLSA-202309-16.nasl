#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202309-16.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(182401);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/30");

  script_cve_id("CVE-2021-30004", "CVE-2022-23303", "CVE-2022-23304");

  script_name(english:"GLSA-202309-16 : wpa_supplicant, hostapd: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202309-16 (wpa_supplicant, hostapd: Multiple
Vulnerabilities)

  - In wpa_supplicant and hostapd 2.9, forging attacks may occur because AlgorithmIdentifier parameters are
    mishandled in tls/pkcs1.c and tls/x509v3.c. (CVE-2021-30004)

  - The implementations of SAE in hostapd before 2.10 and wpa_supplicant before 2.10 are vulnerable to side
    channel attacks as a result of cache access patterns. NOTE: this issue exists because of an incomplete fix
    for CVE-2019-9494. (CVE-2022-23303)

  - The implementations of EAP-pwd in hostapd before 2.10 and wpa_supplicant before 2.10 are vulnerable to
    side-channel attacks as a result of cache access patterns. NOTE: this issue exists because of an
    incomplete fix for CVE-2019-9495. (CVE-2022-23304)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202309-16");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=768759");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=780135");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=780138");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=831332");
  script_set_attribute(attribute:"solution", value:
"All wpa_supplicant users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-wireless/wpa_supplicant-2.10
        
All hostapd users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-wireless/hostapd-2.10");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23304");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-wireless/hostapd',
    'unaffected' : make_list("ge 2.10"),
    'vulnerable' : make_list("lt 2.10")
  },
  {
    'name' : 'net-wireless/wpa_supplicant',
    'unaffected' : make_list("ge 2.10"),
    'vulnerable' : make_list("lt 2.10")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'wpa_supplicant / hostapd');
}
