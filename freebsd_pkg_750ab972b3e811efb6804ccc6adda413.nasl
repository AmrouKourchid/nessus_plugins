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
  script_id(212149);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/05");

  script_cve_id(
    "CVE-2024-47537",
    "CVE-2024-47539",
    "CVE-2024-47540",
    "CVE-2024-47543",
    "CVE-2024-47544",
    "CVE-2024-47545",
    "CVE-2024-47546",
    "CVE-2024-47596",
    "CVE-2024-47597",
    "CVE-2024-47598",
    "CVE-2024-47601",
    "CVE-2024-47602",
    "CVE-2024-47603",
    "CVE-2024-47606",
    "CVE-2024-47775",
    "CVE-2024-47776",
    "CVE-2024-47777",
    "CVE-2024-47778",
    "CVE-2024-47834",
    "CVE-2024-47835"
  );
  script_xref(name:"IAVA", value:"2024-A-0832-S");

  script_name(english:"FreeBSD : gstreamer1-plugins-good -- multiple vulnerabilities (750ab972-b3e8-11ef-b680-4ccc6adda413)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 750ab972-b3e8-11ef-b680-4ccc6adda413 advisory.

    The GStreamer Security Center reports:
    20 security bugs.

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0005.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0006.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0007.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0010.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0011.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0012.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0013.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0014.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0015.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0017.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0019.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0020.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0021.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0027.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0027.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0027.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0027.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0028.html");
  script_set_attribute(attribute:"see_also", value:"https://gstreamer.freedesktop.org/security/sa-2024-0030.html");
  # https://vuxml.freebsd.org/freebsd/750ab972-b3e8-11ef-b680-4ccc6adda413.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d11c4108");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gstreamer1-plugins-good");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'gstreamer1-plugins-good<1.24.10'
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
