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
  script_id(190374);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/19");

  script_cve_id("CVE-2024-24821");

  script_name(english:"FreeBSD : Composer -- Code execution and possible privilege escalation (33ba2241-c68e-11ee-9ef3-001999f8d30b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 33ba2241-c68e-11ee-9ef3-001999f8d30b advisory.

  - Composer is a dependency Manager for the PHP language. In affected versions several files within the local
    working directory are included during the invocation of Composer and in the context of the executing user.
    As such, under certain conditions arbitrary code execution may lead to local privilege escalation, provide
    lateral user movement or malicious code execution when Composer is invoked within a directory with
    tampered files. All Composer CLI commands are affected, including composer.phar's self-update. The
    following scenarios are of high risk: Composer being run with sudo, Pipelines which may execute Composer
    on untrusted projects, Shared environments with developers who run Composer individually on the same
    project. This vulnerability has been addressed in versions 2.7.0 and 2.2.23. It is advised that the
    patched versions are applied at the earliest convenience. Where not possible, the following should be
    addressed: Remove all sudo composer privileges for all users to mitigate root privilege escalation, and
    avoid running Composer within an untrusted directory, or if needed, verify that the contents of
    `vendor/composer/InstalledVersions.php` and `vendor/composer/installed.php` do not include untrusted code.
    A reset can also be done on these files by the following:```sh rm vendor/composer/installed.php
    vendor/composer/InstalledVersions.php composer install --no-scripts --no-plugins ``` (CVE-2024-24821)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/composer/composer/security/advisories/GHSA-7c6p-848j-wh5h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6591e7ff");
  # https://vuxml.freebsd.org/freebsd/33ba2241-c68e-11ee-9ef3-001999f8d30b.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45edb731");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24821");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php81-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php82-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php83-composer");
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
    'php81-composer<2.7.0',
    'php82-composer<2.7.0',
    'php83-composer<2.7.0'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
