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
  script_id(187103);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2023-49933",
    "CVE-2023-49934",
    "CVE-2023-49935",
    "CVE-2023-49936",
    "CVE-2023-49937",
    "CVE-2023-49938"
  );

  script_name(english:"FreeBSD : slurm-wlm -- Several security issues (76c2110b-9e97-11ee-ae23-a0f3c100ae18)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 76c2110b-9e97-11ee-ae23-a0f3c100ae18 advisory.

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. There is Improper Enforcement of
    Message Integrity During Transmission in a Communication Channel. This allows attackers to modify RPC
    traffic in a way that bypasses message hash checks. The fixed versions are 22.05.11, 23.02.7, and 23.11.1.
    (CVE-2023-49933)

  - An issue was discovered in SchedMD Slurm 23.11.x. There is SQL Injection against the SlurmDBD database.
    The fixed version is 23.11.1. (CVE-2023-49934)

  - An issue was discovered in SchedMD Slurm 23.02.x and 23.11.x. There is Incorrect Access Control because of
    a slurmd Message Integrity Bypass. An attacker can reuse root-level authentication tokens during
    interaction with the slurmd process. This bypasses the RPC message hashes that protect against undesired
    MUNGE credential reuse. The fixed versions are 23.02.7 and 23.11.1. (CVE-2023-49935)

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. A NULL pointer dereference leads
    to denial of service. The fixed versions are 22.05.11, 23.02.7, and 23.11.1. (CVE-2023-49936)

  - An issue was discovered in SchedMD Slurm 22.05.x, 23.02.x, and 23.11.x. Because of a double free,
    attackers can cause a denial of service or possibly execute arbitrary code. The fixed versions are
    22.05.11, 23.02.7, and 23.11.1. (CVE-2023-49937)

  - An issue was discovered in SchedMD Slurm 22.05.x and 23.02.x. There is Incorrect Access Control: an
    attacker can modified their extended group list that is used with the sbcast subsystem, and open files
    with an unauthorized set of extended groups. The fixed versions are 22.05.11 and 23.02.7. (CVE-2023-49938)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://vuxml.freebsd.org/freebsd/76c2110b-9e97-11ee-ae23-a0f3c100ae18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cc515e0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:slurm-wlm");
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
    'slurm-wlm<23.11.1'
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
