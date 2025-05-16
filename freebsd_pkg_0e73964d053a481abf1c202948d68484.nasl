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
  script_id(201163);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-5157",
    "CVE-2024-5158",
    "CVE-2024-5159",
    "CVE-2024-5160",
    "CVE-2024-5493",
    "CVE-2024-5494",
    "CVE-2024-5495",
    "CVE-2024-5496",
    "CVE-2024-5499",
    "CVE-2024-5831",
    "CVE-2024-5832",
    "CVE-2024-6100",
    "CVE-2024-6101",
    "CVE-2024-6103"
  );

  script_name(english:"FreeBSD : electron29 -- multiple vulnerabilities (0e73964d-053a-481a-bf1c-202948d68484)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 0e73964d-053a-481a-bf1c-202948d68484 advisory.

    Electron developers report:
    This update fixes the following vulnerabilities:

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-4433-jwm9-48r5");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-8xgv-q88p-ghq4");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-9pmm-wf44-xjqc");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-c24q-2hx9-mjpc");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-f6rr-qfxh-hcf9");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-fv2x-w8xf-gxpq");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-g779-vpj7-v6c4");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-hqfv-mf6j-g3j6");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-ph5m-227m-fc5g");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-qmp7-vwf7-6g2g");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-rg42-f9ww-x3w7");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-rw9q-cwc5-qqp5");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-w7g4-69hj-jcrq");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-wrxh-8wc3-33rm");
  # https://vuxml.freebsd.org/freebsd/0e73964d-053a-481a-bf1c-202948d68484.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ad5436e");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:electron29");
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
    'electron29<29.4.3'
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
