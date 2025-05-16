#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(192596);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_name(english:"FreeBSD : phpmyfaq -- multiple vulnerabilities (8b3be705-eba7-11ee-99b3-589cfc0f81b0)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 8b3be705-eba7-11ee-99b3-589cfc0f81b0 advisory.

  - phpMyFAQ team reports: The phpMyFAQ Team has learned of multiple security issues that'd             been
    discovered in phpMyFAQ 3.2.5 and earlier. phpMyFAQ contains             cross-site scripting (XSS), SQL
    injection and bypass             vulnerabilities. (8b3be705-eba7-11ee-99b3-589cfc0f81b0)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-2grw-mc9r-822r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bce7ab99");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-48vw-jpf8-hwqh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e928e812");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-6p68-36m6-392r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a08527c7");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-hm8r-95g3-5hj9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?11732122");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-mmh6-5cpf-2c72
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38d40b10");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-pwh2-fpfr-x5gf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b99d8d71");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-q7g6-xfh2-vhpx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?538f6d04");
  # https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-qgxx-4xv5-6hcw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c4640c7");
  # https://vuxml.freebsd.org/freebsd/8b3be705-eba7-11ee-99b3-589cfc0f81b0.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80180535");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq-php81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq-php82");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:phpmyfaq-php83");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'phpmyfaq-php81<3.2.6',
    'phpmyfaq-php82<3.2.6',
    'phpmyfaq-php83<3.2.6'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
