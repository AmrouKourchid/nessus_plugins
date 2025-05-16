#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202405-28.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(195168);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/08");

  script_cve_id("CVE-2023-25515", "CVE-2023-25516", "CVE-2023-31022");

  script_name(english:"GLSA-202405-28 : NVIDIA Drivers: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202405-28 (NVIDIA Drivers: Multiple Vulnerabilities)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability where unexpected untrusted data
    is parsed, which may lead to code execution, denial of service, escalation of privileges, data tampering,
    or information disclosure. (CVE-2023-25515)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an
    unprivileged user can cause an integer overflow, which may lead to information disclosure and denial of
    service. (CVE-2023-25516)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a
    NULL-pointer dereference may lead to denial of service. (CVE-2023-31022)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202405-28");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=909226");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916583");
  script_set_attribute(attribute:"solution", value:
"All NVIDIA Drivers 470 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-470.223.02:0/470
        
All NVIDIA Drivers 525 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-525.147.05:0/525
        
All NVIDIA Drivers 535 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-535.129.03:0/535");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nvidia-drivers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 470.223.02", "lt 470.0.0"),
    'vulnerable' : make_list("lt 470.223.02")
  },
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 525.147.05", "lt 525.0.0"),
    'vulnerable' : make_list("lt 525.147.05")
  },
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 535.129.03", "lt 535.0.0"),
    'vulnerable' : make_list("lt 535.129.03")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'NVIDIA Drivers');
}
