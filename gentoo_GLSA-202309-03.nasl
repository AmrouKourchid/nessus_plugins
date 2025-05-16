#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202309-03.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(181507);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/17");

  script_cve_id("CVE-2022-2085", "CVE-2023-28879", "CVE-2023-36664");

  script_name(english:"GLSA-202309-03 : GPL Ghostscript: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202309-03 (GPL Ghostscript: Multiple Vulnerabilities)

  - A NULL pointer dereference vulnerability was found in Ghostscript, which occurs when it tries to render a
    large number of bits in memory. When allocating a buffer device, it relies on an init_device_procs defined
    for the device that uses it as a prototype that depends upon the number of bits per pixel. For bpp > 64,
    mem_x_device is used and does not have an init_device_procs defined. This flaw allows an attacker to parse
    a large number of bits (more than 64 bits per pixel), which triggers a NULL pointer dereference flaw,
    causing an application to crash. (CVE-2022-2085)

  - In Artifex Ghostscript through 10.01.0, there is a buffer overflow leading to potential corruption of data
    internal to the PostScript interpreter, in base/sbcp.c. This affects BCPEncode, BCPDecode, TBCPEncode, and
    TBCPDecode. If the write buffer is filled to one byte less than full, and one then tries to write an
    escaped character, two bytes are written. (CVE-2023-28879)

  - Artifex Ghostscript through 10.01.2 mishandles permission validation for pipe devices (with the %pipe%
    prefix or the | pipe character prefix). (CVE-2023-36664)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202309-03");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=904245");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=910294");
  script_set_attribute(attribute:"solution", value:
"All GPL Ghostscript users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-text/ghostscript-gpl-10.01.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2085");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:ghostscript-gpl");
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
    'name' : 'app-text/ghostscript-gpl',
    'unaffected' : make_list("ge 10.01.2"),
    'vulnerable' : make_list("lt 10.01.2")
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'GPL Ghostscript');
}
