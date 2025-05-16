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
  script_id(197096);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2024-2625",
    "CVE-2024-2626",
    "CVE-2024-2885",
    "CVE-2024-2887",
    "CVE-2024-3157",
    "CVE-2024-3159",
    "CVE-2024-3516",
    "CVE-2024-3837",
    "CVE-2024-3839",
    "CVE-2024-3840",
    "CVE-2024-3914",
    "CVE-2024-4058",
    "CVE-2024-4060",
    "CVE-2024-4331",
    "CVE-2024-4368",
    "CVE-2024-4671"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/06/03");

  script_name(english:"FreeBSD : qt6-webengine -- Multiple vulnerabilities (c6f03ea6-12de-11ef-83d8-4ccc6adda413)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the c6f03ea6-12de-11ef-83d8-4ccc6adda413 advisory.

  - Object lifecycle issue in V8 in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-2625)

  - Out of bounds read in Swiftshader in Google Chrome prior to 123.0.6312.58 allowed a remote attacker to
    perform out of bounds memory access via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-2626)

  - Use after free in Dawn in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2885)

  - Type Confusion in WebAssembly in Google Chrome prior to 123.0.6312.86 allowed a remote attacker to execute
    arbitrary code via a crafted HTML page. (Chromium security severity: High) (CVE-2024-2887)

  - Out of bounds memory access in Compositing in Google Chrome prior to 123.0.6312.122 allowed a remote
    attacker who had compromised the GPU process to potentially perform a sandbox escape via specific UI
    gestures. (Chromium security severity: High) (CVE-2024-3157)

  - Out of bounds memory access in V8 in Google Chrome prior to 123.0.6312.105 allowed a remote attacker to
    perform arbitrary read/write via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3159)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 123.0.6312.122 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3516)

  - Use after free in QUIC in Google Chrome prior to 124.0.6367.60 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-3837)

  - Out of bounds read in Fonts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-3839)

  - Insufficient policy enforcement in Site Isolation in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3840)

  - Use after free in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3914)

  - Type confusion in ANGLE in Google Chrome prior to 124.0.6367.78 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Critical) (CVE-2024-4058)

  - Use after free in Dawn in Google Chrome prior to 124.0.6367.78 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4060)

  - Use after free in Picture In Picture in Google Chrome prior to 124.0.6367.118 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-4331)

  - Use after free in Dawn in Google Chrome prior to 124.0.6367.118 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-4368)

  - Use after free in Visuals in Google Chrome prior to 124.0.6367.201 allowed a remote attacker who had
    compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page.
    (Chromium security severity: High) (CVE-2024-4671)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://code.qt.io/cgit/qt/qtwebengine-chromium.git/log/?h=118-based");
  # https://vuxml.freebsd.org/freebsd/c6f03ea6-12de-11ef-83d8-4ccc6adda413.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b67d397a");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-4671");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qt6-webengine");
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
    'qt6-webengine<6.7.0'
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
