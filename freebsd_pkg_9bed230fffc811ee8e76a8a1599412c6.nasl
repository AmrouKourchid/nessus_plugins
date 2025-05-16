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
  script_id(193692);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2024-3832",
    "CVE-2024-3833",
    "CVE-2024-3834",
    "CVE-2024-3837",
    "CVE-2024-3838",
    "CVE-2024-3839",
    "CVE-2024-3840",
    "CVE-2024-3841",
    "CVE-2024-3843",
    "CVE-2024-3844",
    "CVE-2024-3845",
    "CVE-2024-3846",
    "CVE-2024-3847",
    "CVE-2024-3914"
  );

  script_name(english:"FreeBSD : chromium -- multiple security fixes (9bed230f-ffc8-11ee-8e76-a8a1599412c6)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 9bed230f-ffc8-11ee-8e76-a8a1599412c6 advisory.

  - Object corruption in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit object corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3832)

  - Object corruption in WebAssembly in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit object corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3833)

  - Use after free in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2024-3834)

  - Use after free in QUIC in Google Chrome prior to 124.0.6367.60 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2024-3837)

  - Inappropriate implementation in Autofill in Google Chrome prior to 124.0.6367.60 allowed an attacker who
    convinced a user to install a malicious app to perform UI spoofing via a crafted app. (Chromium security
    severity: Medium) (CVE-2024-3838)

  - Out of bounds read in Fonts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to obtain
    potentially sensitive information from process memory via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2024-3839)

  - Insufficient policy enforcement in Site Isolation in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to bypass navigation restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3840)

  - Insufficient data validation in Browser Switcher in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to inject scripts or HTML into a privileged page via a malicious file. (Chromium security
    severity: Medium) (CVE-2024-3841)

  - Insufficient data validation in Downloads in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2024-3843)

  - Inappropriate implementation in Extensions in Google Chrome prior to 124.0.6367.60 allowed a remote
    attacker to perform UI spoofing via a crafted Chrome Extension. (Chromium security severity: Low)
    (CVE-2024-3844)

  - Inappropriate implementation in Networks in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass mixed content policy via a crafted HTML page. (Chromium security severity: Low) (CVE-2024-3845)

  - Inappropriate implementation in Prompts in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    who convinced a user to engage in specific UI gestures to perform UI spoofing via a crafted HTML page.
    (Chromium security severity: Low) (CVE-2024-3846)

  - Insufficient policy enforcement in WebUI in Google Chrome prior to 124.0.6367.60 allowed a remote attacker
    to bypass content security policy via a crafted HTML page. (Chromium security severity: Low)
    (CVE-2024-3847)

  - Use after free in V8 in Google Chrome prior to 124.0.6367.60 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2024-3914)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2024/04/stable-channel-update-for-desktop_16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?843c08d5");
  # https://vuxml.freebsd.org/freebsd/9bed230f-ffc8-11ee-8e76-a8a1599412c6.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43e73900");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3837");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ungoogled-chromium");
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
    'chromium<124.0.6367.60',
    'ungoogled-chromium<124.0.6367.60'
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
