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
  script_id(192184);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id(
    "CVE-2023-30451",
    "CVE-2024-22188",
    "CVE-2024-25118",
    "CVE-2024-25119",
    "CVE-2024-25120",
    "CVE-2024-25121"
  );

  script_name(english:"FreeBSD : typo3-{11,12} -- multiple vulnerabilities (1ad3d264-e36b-11ee-9c27-40b034429ecf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 1ad3d264-e36b-11ee-9c27-40b034429ecf advisory.

  - In TYPO3 11.5.24, the filelist component allows attackers (who have access to the administrator panel) to
    read arbitrary files via directory traversal in the baseuri field, as demonstrated by POST
    /typo3/record/edit with ../../../ in data[sys_file_storage]*[data][sDEF][lDEF][basePath][vDEF].
    (CVE-2023-30451)

  - TYPO3 before 13.0.1 allows an authenticated admin user (with system maintainer privileges) to execute
    arbitrary shell commands (with the privileges of the web server) via a command injection vulnerability in
    form fields of the Install Tool. The fixed versions are 8.7.57 ELTS, 9.5.46 ELTS, 10.4.43 ELTS, 11.5.35
    LTS, 12.4.11 LTS, and 13.0.1. (CVE-2024-22188)

  - TYPO3 is an open source PHP based web content management system released under the GNU GPL. Password
    hashes were being reflected in the editing forms of the TYPO3 backend user interface. This allowed
    attackers to crack the plaintext password using brute force techniques. Exploiting this vulnerability
    requires a valid backend user account. Users are advised to update to TYPO3 versions 8.7.57 ELTS, 9.5.46
    ELTS, 10.4.43 ELTS, 11.5.35 LTS, 12.4.11 LTS, 13.0.1 that fix the problem described. There are no known
    workarounds for this issue. (CVE-2024-25118)

  - TYPO3 is an open source PHP based web content management system released under the GNU GPL. The plaintext
    value of `$GLOBALS['SYS']['encryptionKey']` was displayed in the editing forms of the TYPO3 Install Tool
    user interface. This allowed attackers to utilize the value to generate cryptographic hashes used for
    verifying the authenticity of HTTP request parameters. Exploiting this vulnerability requires an
    administrator-level backend user account with system maintainer permissions. Users are advised to update
    to TYPO3 versions 8.7.57 ELTS, 9.5.46 ELTS, 10.4.43 ELTS, 11.5.35 LTS, 12.4.11 LTS, 13.0.1 that fix the
    problem described. There are no known workarounds for this vulnerability. (CVE-2024-25119)

  - TYPO3 is an open source PHP based web content management system released under the GNU GPL. The
    TYPO3-specific `t3://` URI scheme could be used to access resources outside of the users' permission
    scope. This encompassed files, folders, pages, and records (although only if a valid link-handling
    configuration was provided). Exploiting this vulnerability requires a valid backend user account. Users
    are advised to update to TYPO3 versions 8.7.57 ELTS, 9.5.46 ELTS, 10.4.43 ELTS, 11.5.35 LTS, 12.4.11 LTS,
    13.0.1 that fix the problem described. There are no known workarounds for this issue. (CVE-2024-25120)

  - TYPO3 is an open source PHP based web content management system released under the GNU GPL. In affected
    versions of TYPO3 entities of the File Abstraction Layer (FAL) could be persisted directly via
    `DataHandler`. This allowed attackers to reference files in the fallback storage directly and retrieve
    their file names and contents. The fallback storage (zero-storage) is used as a backward compatibility
    layer for files located outside properly configured file storages and within the public web root
    directory. Exploiting this vulnerability requires a valid backend user account. Users are advised to
    update to TYPO3 version 8.7.57 ELTS, 9.5.46 ELTS, 10.4.43 ELTS, 11.5.35 LTS, 12.4.11 LTS, or 13.0.1 which
    fix the problem described. When persisting entities of the File Abstraction Layer directly via
    DataHandler, `sys_file` entities are now denied by default, and `sys_file_reference` & `sys_file_metadata`
    entities are not permitted to reference files in the fallback storage anymore. When importing data from
    secure origins, this must be explicitly enabled in the corresponding DataHandler instance by using
    `$dataHandler->isImporting = true;`. (CVE-2024-25121)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://typo3.org/article/typo3-1301-12411-and-11535-security-releases-published
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54fbb469");
  # https://vuxml.freebsd.org/freebsd/1ad3d264-e36b-11ee-9c27-40b034429ecf.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0f75444");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25121");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-12");
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
    'typo3-11<11.5.35',
    'typo3-12<12.4.11'
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
