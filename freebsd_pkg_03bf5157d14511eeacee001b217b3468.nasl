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
  script_id(190909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id(
    "CVE-2023-3509",
    "CVE-2023-4895",
    "CVE-2023-6477",
    "CVE-2023-6736",
    "CVE-2024-0410",
    "CVE-2024-0861",
    "CVE-2024-1451",
    "CVE-2024-1525"
  );
  script_xref(name:"IAVA", value:"2024-A-0113-S");

  script_name(english:"FreeBSD : Gitlab -- Vulnerabilities (03bf5157-d145-11ee-acee-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 03bf5157-d145-11ee-acee-001b217b3468 advisory.

  - An issue has been discovered in GitLab affecting all versions before 16.7.6, all versions starting from
    16.8 before 16.8.3, all versions starting from 16.9 before 16.9.1. It was possible for group members with
    sub-maintainer role to change the title of privately accessible deploy keys associated with projects in
    the group. (CVE-2023-3509)

  - An issue has been discovered in GitLab EE affecting all versions starting from 12.0 to 16.7.6, all
    versions starting from 16.8 before 16.8.3, all versions starting from 16.9 before 16.9.1. This
    vulnerability allows for bypassing the 'group ip restriction' settings to access environment details of
    projects (CVE-2023-4895)

  - An issue has been discovered in GitLab EE affecting all versions starting from 16.5 before 16.7.6, all
    versions starting from 16.8 before 16.8.3, all versions starting from 16.9 before 16.9.1. When a user is
    assigned a custom role with admin_group_member permission, they may be able to make a group, other members
    or themselves Owners of that group, which may lead to privilege escalation. (CVE-2023-6477)

  - An issue has been discovered in GitLab EE affecting all versions starting from 11.3 before 16.6.7, all
    versions starting from 16.7 before 16.7.5, all versions starting from 16.8 before 16.8.2. It was possible
    for an attacker to cause a client-side denial of service using malicious crafted content in the CODEOWNERS
    file. (CVE-2023-6736)

  - An authorization bypass vulnerability was discovered in GitLab affecting versions 15.1 prior to 16.7.6,
    16.8 prior to 16.8.3, and 16.9 prior to 16.9.1. A developer could bypass CODEOWNERS approvals by creating
    a merge conflict. (CVE-2024-0410)

  - An issue has been discovered in GitLab EE affecting all versions starting from 16.4 before 16.7.6, all
    versions starting from 16.8 before 16.8.3, all versions starting from 16.9 before 16.9.1. Users with the
    `Guest` role can change `Custom dashboard projects` settings contrary to permissions. (CVE-2024-0861)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 16.9 before 16.9.1. A
    crafted payload added to the user profile page could lead to a stored XSS on the client side, allowing
    attackers to perform arbitrary actions on behalf of victims. (CVE-2024-1451)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 16.1 before 16.7.6, all
    versions starting from 16.8 before 16.8.3, all versions starting from 16.9 before 16.9.1. Under some
    specialized conditions, an LDAP user may be able to reset their password using their verified secondary
    email address and sign-in using direct authentication with the reset password, bypassing LDAP.
    (CVE-2024-1525)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2024/02/21/security-release-gitlab-16-9-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ef605f4");
  # https://vuxml.freebsd.org/freebsd/03bf5157-d145-11ee-acee-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f63de2b");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
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
    'gitlab-ce>=11.3.0<16.7.6',
    'gitlab-ce>=16.8.0<16.8.3',
    'gitlab-ce>=16.9.0<16.9.1'
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
