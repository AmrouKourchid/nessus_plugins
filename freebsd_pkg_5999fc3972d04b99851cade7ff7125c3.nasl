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
  script_id(180107);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2023-4068",
    "CVE-2023-4070",
    "CVE-2023-4071",
    "CVE-2023-4072",
    "CVE-2023-4073",
    "CVE-2023-4074",
    "CVE-2023-4075",
    "CVE-2023-4076",
    "CVE-2023-4351",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355"
  );

  script_name(english:"FreeBSD : electron25 -- multiple vulnerabilities (5999fc39-72d0-4b99-851c-ade7ff7125c3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 5999fc39-72d0-4b99-851c-ade7ff7125c3 advisory.

  - Type Confusion in V8 in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to perform
    arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4068,
    CVE-2023-4070)

  - Heap buffer overflow in Visuals in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4071)

  - Out of bounds read and write in WebGL in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4072)

  - Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 115.0.5790.170 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4073)

  - Use after free in Blink Task Scheduling in Google Chrome prior to 115.0.5790.170 allowed a remote attacker
    to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4074)

  - Use after free in Cast in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4075)

  - Use after free in WebRTC in Google Chrome prior to 115.0.5790.170 allowed a remote attacker to potentially
    exploit heap corruption via a crafted WebRTC session. (Chromium security severity: High) (CVE-2023-4076)

  - Use after free in Network in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    elicited a browser shutdown to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4351)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4353)

  - Heap buffer overflow in Skia in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4354)

  - Out of bounds memory access in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4355)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-6j3m-7hm6-qjrx");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-7332-j628-x48x");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-7rfc-cwhj-x2qv");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-9j4r-qr47-rcxp");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-9xxv-mx64-rx27");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-g9wf-6ppg-937x");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-mh2g-52mr-mr5v");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-mjq9-8vf6-qh49");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-qc3g-vp59-7vwh");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-rq4v-7hxq-wpm5");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-wh89-h5f7-hhcr");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-xrw8-8992-37w4");
  # https://vuxml.freebsd.org/freebsd/5999fc39-72d0-4b99-851c-ade7ff7125c3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2c347dd");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4355");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:electron25");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'electron25<25.7.0'
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
