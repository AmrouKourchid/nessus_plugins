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
  script_id(180454);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2022-4343",
    "CVE-2023-0120",
    "CVE-2023-1279",
    "CVE-2023-1555",
    "CVE-2023-3205",
    "CVE-2023-3915",
    "CVE-2023-3950",
    "CVE-2023-4018",
    "CVE-2023-4378",
    "CVE-2023-4630",
    "CVE-2023-4638",
    "CVE-2023-4647"
  );
  script_xref(name:"IAVA", value:"2023-A-0452-S");

  script_name(english:"FreeBSD : Gitlab -- Vulnerabilities (aaea7b7c-4887-11ee-b164-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the aaea7b7c-4887-11ee-b164-001b217b3468 advisory.

  - An issue has been discovered in GitLab EE affecting all versions starting from 13.12 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1 in which a
    project member can leak credentials stored in site profile. (CVE-2022-4343)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.0 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1. Due to improper
    permission validation it was possible to edit labels description by an unauthorised user. (CVE-2023-0120)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 4.1 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1 where it was
    possible to create a URL that would redirect to a different project. (CVE-2023-1279)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.2 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1. A namespace-
    level banned user can access the API. (CVE-2023-1555)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.11 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1. An authenticated
    user could trigger a denial of service when importing or cloning malicious content. (CVE-2023-3205)

  - An issue has been discovered in GitLab EE affecting all versions starting from 16.1 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1. If an external
    user is given an owner role on any group, that external user may escalate their privileges on the instance
    by creating a service account in that group. This service account is not classified as external and may be
    used to access internal projects. (CVE-2023-3915)

  - Gitlab reports: Privilege escalation of external user to internal access through group service account
    Maintainer can leak sentry token by changing the configured URL (fix bypass) Google Cloud Logging private
    key showed in plain text in GitLab UI leaking to other group owners Information disclosure via project
    import endpoint Developer can leak DAST scanners Site Profile request headers and auth password Project
    forking outside current group User is capable of creating Model experiment and updating existing run's
    status in public project ReDoS in bulk import API Pagination for Branches and Tags can be skipped leading
    to DoS Internal Open Redirection Due to Improper handling of ../ characters Subgroup Member With
    Reporter Role Can Edit Group Labels Banned user can delete package registries (CVE-2023-3950,
    CVE-2023-4378)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 16.2 before 16.2.5, all
    versions starting from 16.3 before 16.3.1. Due to improper permission validation it was possible to create
    model experiments in public projects. (CVE-2023-4018)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 10.6 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1 in which any user
    can read limited information about any project's imports. (CVE-2023-4630)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 13.3 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1. Due to improper
    permission validation it was possible to fork a project outside of current group by an unauthorised user.
    (CVE-2023-4638)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 15.3 before 16.1.5, all
    versions starting from 16.2 before 16.2.5, all versions starting from 16.3 before 16.3.1 in which the
    projects API pagination can be skipped, potentially leading to DoS on certain instances. (CVE-2023-4647)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/08/31/security-release-gitlab-16-3-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f755f06");
  # https://vuxml.freebsd.org/freebsd/aaea7b7c-4887-11ee-b164-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5d2af4d");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3915");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/01");

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
    'gitlab-ce>=16.2.0<16.2.5',
    'gitlab-ce>=16.3.0<16.3.1',
    'gitlab-ce>=4.1.0<16.1.5'
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
