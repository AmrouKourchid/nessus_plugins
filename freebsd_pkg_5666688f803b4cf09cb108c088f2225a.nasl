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
  script_id(179942);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/18");

  script_cve_id(
    "CVE-2023-2312",
    "CVE-2023-4349",
    "CVE-2023-4350",
    "CVE-2023-4351",
    "CVE-2023-4352",
    "CVE-2023-4353",
    "CVE-2023-4354",
    "CVE-2023-4355",
    "CVE-2023-4356",
    "CVE-2023-4357",
    "CVE-2023-4358",
    "CVE-2023-4359",
    "CVE-2023-4360",
    "CVE-2023-4361",
    "CVE-2023-4362",
    "CVE-2023-4363",
    "CVE-2023-4364",
    "CVE-2023-4365",
    "CVE-2023-4366",
    "CVE-2023-4367",
    "CVE-2023-4368"
  );
  script_xref(name:"IAVA", value:"2023-A-0428-S");

  script_name(english:"FreeBSD : chromium -- multiple vulnerabilities (5666688f-803b-4cf0-9cb1-08c088f2225a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 5666688f-803b-4cf0-9cb1-08c088f2225a advisory.

  - Use after free in Offline in Google Chrome on Android prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-2312)

  - Use after free in Device Trust Connectors in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity:
    High) (CVE-2023-4349)

  - Inappropriate implementation in Fullscreen in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof the contents of the Omnibox (URL bar) via a crafted HTML page.
    (Chromium security severity: High) (CVE-2023-4350)

  - Use after free in Network in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    elicited a browser shutdown to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4351)

  - Type confusion in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: High) (CVE-2023-4352)

  - Heap buffer overflow in ANGLE in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4353)

  - Heap buffer overflow in Skia in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who had
    compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. (Chromium
    security severity: High) (CVE-2023-4354)

  - Out of bounds memory access in V8 in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)
    (CVE-2023-4355)

  - Use after free in Audio in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who has
    convinced a user to engage in specific UI interaction to potentially exploit heap corruption via a crafted
    HTML page. (Chromium security severity: Medium) (CVE-2023-4356)

  - Insufficient validation of untrusted input in XML in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to bypass file access restrictions via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4357)

  - Use after free in DNS in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to potentially
    exploit heap corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4358)

  - Inappropriate implementation in App Launcher in Google Chrome on iOS prior to 116.0.5845.96 allowed a
    remote attacker to potentially spoof elements of the security UI via a crafted HTML page. (Chromium
    security severity: Medium) (CVE-2023-4359)

  - Inappropriate implementation in Color in Google Chrome prior to 116.0.5845.96 allowed a remote attacker to
    obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4360)

  - Inappropriate implementation in Autofill in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to bypass Autofill restrictions via a crafted HTML page. (Chromium security severity:
    Medium) (CVE-2023-4361)

  - Heap buffer overflow in Mojom IDL in Google Chrome prior to 116.0.5845.96 allowed a remote attacker who
    had compromised the renderer process and gained control of a WebUI process to potentially exploit heap
    corruption via a crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4362)

  - Inappropriate implementation in WebShare in Google Chrome on Android prior to 116.0.5845.96 allowed a
    remote attacker to spoof the contents of a dialog URL via a crafted HTML page. (Chromium security
    severity: Medium) (CVE-2023-4363)

  - Inappropriate implementation in Permission Prompts in Google Chrome prior to 116.0.5845.96 allowed a
    remote attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4364)

  - Inappropriate implementation in Fullscreen in Google Chrome prior to 116.0.5845.96 allowed a remote
    attacker to obfuscate security UI via a crafted HTML page. (Chromium security severity: Medium)
    (CVE-2023-4365)

  - Use after free in Extensions in Google Chrome prior to 116.0.5845.96 allowed an attacker who convinced a
    user to install a malicious extension to potentially exploit heap corruption via a crafted HTML page.
    (Chromium security severity: Medium) (CVE-2023-4366)

  - Insufficient policy enforcement in Extensions API in Google Chrome prior to 116.0.5845.96 allowed an
    attacker who convinced a user to install a malicious extension to bypass an enterprise policy via a
    crafted HTML page. (Chromium security severity: Medium) (CVE-2023-4367, CVE-2023-4368)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://chromereleases.googleblog.com/2023/08/stable-channel-update-for-desktop_15.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?404ab584");
  # https://vuxml.freebsd.org/freebsd/5666688f-803b-4cf0-9cb1-08c088f2225a.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77b914f7");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4368");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ungoogled-chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'chromium<116.0.5845.96',
    'ungoogled-chromium<116.0.5845.96'
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
