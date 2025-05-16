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
  script_id(179202);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/08");

  script_cve_id(
    "CVE-2023-0632",
    "CVE-2023-1210",
    "CVE-2023-2022",
    "CVE-2023-2164",
    "CVE-2023-3364",
    "CVE-2023-3385",
    "CVE-2023-3401",
    "CVE-2023-3500",
    "CVE-2023-3900",
    "CVE-2023-3993",
    "CVE-2023-3994",
    "CVE-2023-4002",
    "CVE-2023-4008",
    "CVE-2023-4011"
  );
  script_xref(name:"IAVA", value:"2023-A-0389-S");

  script_name(english:"FreeBSD : Gitlab -- Vulnerabilities (fa239535-30f6-11ee-aef9-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the fa239535-30f6-11ee-aef9-001b217b3468 advisory.

  - An issue has been discovered in GitLab affecting all versions starting from 15.2 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. A Regular
    Expression Denial of Service was possible by using crafted payloads to search Harbor Registry.
    (CVE-2023-0632)

  - An issue has been discovered in GitLab affecting all versions starting from 12.9 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. It was possible
    to leak a user's email via an error message for groups that restrict membership by email domain.
    (CVE-2023-1210)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting before 16.0.8, all versions
    starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2, which leads to developers
    being able to create pipeline schedules on protected branches even if they don't have access to merge
    (CVE-2023-2022)

  - An issue has been discovered in GitLab affecting all versions starting from 15.9 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. It was possible
    for an attacker to trigger a stored XSS vulnerability via user interaction with a crafted URL in the
    WebIDE beta. (CVE-2023-2164)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 8.14 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. A Regular
    Expression Denial of Service was possible via sending crafted payloads which use AutolinkFilter to the
    preview_markdown endpoint. (CVE-2023-3364)

  - An issue has been discovered in GitLab affecting all versions starting from 8.10 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. Under specific
    circumstances, a user importing a project 'from export' could access and read unrelated files via
    uploading a specially crafted file. This was due to a bug in `tar`, fixed in
    [`tar-1.35`](https://lists.gnu.org/archive/html/info-gnu/2023-07/msg00005.html). (CVE-2023-3385)

  - An issue has been discovered in GitLab affecting all versions before 16.0.8, all versions starting from
    16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. The main branch of a repository with a
    specially designed name allows an attacker to create repositories with malicious code. (CVE-2023-3401)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.0 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. A reflected XSS
    was possible when creating specific PlantUML diagrams that allowed the attacker to perform arbitrary
    actions on behalf of victims. (CVE-2023-3500)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 16.1 before 16.1.3, all
    versions starting from 16.2 before 16.2.2. An invalid 'start_sha' value on merge requests page may lead to
    Denial of Service as Changes tab would not load. (CVE-2023-3900)

  - An issue has been discovered in GitLab EE affecting all versions starting from 14.3 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. Access tokens
    may have been logged when a query was made to a specific endpoint. (CVE-2023-3993)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 9.3 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. A Regular
    Expression Denial of Service was possible via sending crafted payloads which use ProjectReferenceFilter to
    the preview_markdown endpoint. (CVE-2023-3994)

  - An issue has been discovered in GitLab EE affecting all versions from 15.11 prior to 16.2.2 which allows
    an attacker to spike the resource consumption resulting in DoS. (CVE-2023-4011)

  - Gitlab reports: ReDoS via ProjectReferenceFilter in any Markdown fields ReDoS via AutolinkFilter in any
    Markdown fields Regex DoS in Harbor Registry search Arbitrary read of files owned by the git user via
    malicious tar.gz file upload using GitLab export functionality Stored XSS in Web IDE Beta via crafted URL
    securityPolicyProjectAssign mutation does not authorize security policy project ID An attacker can run
    pipeline jobs as arbitrary user Possible Pages Unique Domain Overwrite Access tokens may have been logged
    when a query was made to an endpoint Reflected XSS via PlantUML diagram The main branch of a repository
    with a specially designed name may allow an attacker to create repositories with malicious code Invalid
    'start_sha' value on merge requests page may lead to Denial of Service Developers can create pipeline
    schedules on protected branches even if they don't have access to merge Potential DOS due to lack of
    pagination while loading license data Leaking emails of newly created users (CVE-2023-4002)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.9 before 16.0.8, all
    versions starting from 16.1 before 16.1.3, all versions starting from 16.2 before 16.2.2. It was possible
    to takeover GitLab Pages with unique domain URLs if the random string added was known. (CVE-2023-4008)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/08/01/security-release-gitlab-16-2-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?728ca7c5");
  # https://vuxml.freebsd.org/freebsd/fa239535-30f6-11ee-aef9-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5a5fa92");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4008");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
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
    'gitlab-ce>=16.1.0<16.1.3',
    'gitlab-ce>=16.2.0<16.2.2',
    'gitlab-ce>=9.3.0<16.0.8'
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
