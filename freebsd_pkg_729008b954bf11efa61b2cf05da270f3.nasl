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
  script_id(205158);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/30");

  script_cve_id(
    "CVE-2024-2800",
    "CVE-2024-3035",
    "CVE-2024-3114",
    "CVE-2024-3958",
    "CVE-2024-4207",
    "CVE-2024-4210",
    "CVE-2024-4784",
    "CVE-2024-5423",
    "CVE-2024-6329",
    "CVE-2024-6356",
    "CVE-2024-7586"
  );
  script_xref(name:"IAVA", value:"2024-A-0473-S");

  script_name(english:"FreeBSD : Gitlab -- Vulnerabilities (729008b9-54bf-11ef-a61b-2cf05da270f3)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 729008b9-54bf-11ef-a61b-2cf05da270f3 advisory.

    Gitlab reports:
    Privilege Escalation via LFS Tokens Granting Unrestricted Repository Access
    Cross project access of Security policy bot
    Advanced search ReDOS in highlight for code results
    Denial of Service via banzai pipeline
    Denial of service using adoc files
    ReDoS in RefMatcher when matching branch names using wildcards
    Path encoding can cause the Web interface to not render diffs correctly
    XSS while viewing raw XHTML files through API
    Ambiguous tag name exploitation
    Logs disclosings potentially sensitive data in query params
    Password bypass on approvals using policy projects
    ReDoS when parsing git push
    Webhook deletion audit log can preserve auth credentials

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2024/08/07/patch-release-gitlab-17-2-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85077af6");
  # https://vuxml.freebsd.org/freebsd/729008b9-54bf-11ef-a61b-2cf05da270f3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4995a4c4");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3035");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ee");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'gitlab-ce>=12.0.0<17.0.6',
    'gitlab-ce>=17.1.0<17.1.4',
    'gitlab-ce>=17.2.0<17.2.2',
    'gitlab-ee>=12.0.0<17.0.6',
    'gitlab-ee>=17.1.0<17.1.4',
    'gitlab-ee>=17.2.0<17.2.2'
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
