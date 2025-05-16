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
  script_id(182168);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/09");

  script_cve_id(
    "CVE-2023-0989",
    "CVE-2023-2233",
    "CVE-2023-3115",
    "CVE-2023-3413",
    "CVE-2023-3906",
    "CVE-2023-3914",
    "CVE-2023-3917",
    "CVE-2023-3920",
    "CVE-2023-3922",
    "CVE-2023-3979",
    "CVE-2023-4379",
    "CVE-2023-4532",
    "CVE-2023-4658",
    "CVE-2023-5198",
    "CVE-2023-5207"
  );
  script_xref(name:"IAVA", value:"2023-A-0518-S");

  script_name(english:"FreeBSD : Gitlab -- vulnerabilities (6e0ebb4a-5e75-11ee-a365-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 6e0ebb4a-5e75-11ee-a365-001b217b3468 advisory.

  - An information disclosure issue in GitLab CE/EE affecting all versions prior to 16.2.8, 16.3 prior to
    16.3.5, and 16.4 prior to 16.4.1 allows an attacker to extract non-protected CI/CD variables by tricking a
    user to visit a fork with a malicious CI/CD configuration. (CVE-2023-0989)

  - An improper authorization issue has been discovered in GitLab CE/EE affecting all versions starting from
    11.8 before 16.2.x8, all versions starting from 16.3 before 16.3.5 and all versions starting from 16.4.0
    before 16.4.1. It allows a project reporter can leak the owner's Sentry instance projects. (CVE-2023-2233)

  - An issue has been discovered in GitLab EE affecting all versions affecting all versions from 11.11 prior
    to 16.2.8, 16.3 prior to 16.3.5, and 16.4 prior to 16.4.1. Single Sign On restrictions were not correctly
    enforced for indirect project members accessing public members-only project repositories. (CVE-2023-3115)

  - An issue has been discovered in GitLab affecting all versions starting from 16.2 before 16.2.8, all
    versions starting from 16.3 before 16.3.5, all versions starting from 16.4 before 16.4.1. It was possible
    that an unauthorised user to fork a public project. (CVE-2023-3413)

  - An input validation issue in the asset proxy in GitLab EE, affecting all versions from 12.3 prior to
    16.2.8, 16.3 prior to 16.3.5, and 16.4 prior to 16.4.1, allowed an authenticated attacker to craft image
    urls which bypass the asset proxy. (CVE-2023-3906)

  - A business logic error in GitLab EE affecting all versions prior to 16.2.8, 16.3 prior to 16.3.5, and 16.4
    prior to 16.4.1 allows access to internal projects. A service account is not deleted when a namespace is
    deleted, allowing access to internal projects. (CVE-2023-3914)

  - Denial of Service in pipelines affecting all versions of Gitlab EE and CE prior to 16.2.8, 16.3 prior to
    16.3.5, and 16.4 prior to 16.4.1 allows attacker to cause pipelines to fail. (CVE-2023-3917)

  - An issue has been discovered in GitLab affecting all versions starting from 11.2 before 16.2.8, all
    versions starting from 16.3 before 16.3.5, all versions starting from 16.4 before 16.4.1. It was possible
    that a maintainer to create a fork relationship between existing projects contrary to the documentation.
    (CVE-2023-3920)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 8.15 before 16.2.8, all
    versions starting from 16.3 before 16.3.5, all versions starting from 16.4 before 16.4.1. It was possible
    to hijack some links and buttons on the GitLab UI to a malicious page. (CVE-2023-3922)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.6 before 16.2.8, all
    versions starting from 16.3 before 16.3.5, all versions starting from 16.4 before 16.4.1. It was possible
    that upstream members to collaborate with you on your branch get permission to write to the merge
    request's source branch. . (CVE-2023-3979)

  - An issue has been discovered in GitLab EE affecting all versions starting 15.3 prior to prior to 16.2.8,
    16.3 prior to 16.3.5, and 16.4 prior to 16.4.1. Code owner approval was not removed from merge requests
    when the target branch was updated. (CVE-2023-4379)

  - An issue has been discovered in GitLab affecting all versions starting from 16.2 before 16.2.8, all
    versions starting from 16.3 before 16.3.5, all versions starting from 16.4 before 16.4.1. Users were
    capable of linking CI/CD jobs of private projects which they are not a member of. (CVE-2023-4532)

  - An issue has been discovered in GitLab EE affecting all versions starting from X.Y before 16.X, all
    versions starting from 16.X before 16.X. It was possible for an attacker to abuse the Allowed to merge
    permission as a guest user, when granted the permission through a group. (CVE-2023-4658)

  - An issue has been discovered in GitLab affecting all versions prior to 16.2.7, all versions starting from
    16.3 before 16.3.5, and all versions starting from 16.4 before 16.4.1. It was possible for a removed
    project member to write to protected branches using deploy keys. (CVE-2023-5198)

  - Two issues have been discovered in Ultimate-licensed GitLab EE affecting all versions starting 13.12 prior
    to 16.2.8, 16.3.0 prior to 16.3.5, and 16.4.0 prior to 16.4.1 that could allow an attacker to impersonate
    users in CI pipelines through direct transfer group imports. These are a high severity issues
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N, 8.2). They are now mitigated in the latest release and are
    assigned CVE-2023-5207. These issues have been discovered internally by GitLab team member Joern
    Schneeweisz. (CVE-2023-5207)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/09/28/security-release-gitlab-16-4-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12bd985a");
  # https://vuxml.freebsd.org/freebsd/6e0ebb4a-5e75-11ee-a365-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b069fb84");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5207");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/29");

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
    'gitlab-ce>=16.3.0<16.3.5',
    'gitlab-ce>=16.4.0<16.4.1',
    'gitlab-ce>=8.15<16.2.8'
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
