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
  script_id(191471);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/03");

  script_cve_id(
    "CVE-2023-46809",
    "CVE-2024-21890",
    "CVE-2024-21891",
    "CVE-2024-21892",
    "CVE-2024-21896",
    "CVE-2024-22017",
    "CVE-2024-22019",
    "CVE-2024-22025"
  );
  script_xref(name:"IAVB", value:"2024-B-0016-S");

  script_name(english:"FreeBSD : NodeJS -- Vulnerabilities (77a6f1c9-d7d2-11ee-bb12-001b217b3468)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 77a6f1c9-d7d2-11ee-bb12-001b217b3468 advisory.

  - The Node.js Permission Model does not clarify in the documentation that wildcards should be only used as
    the last character of a file path. For example: ``` --allow-fs-read=/home/node/.ssh/*.pub ``` will ignore
    `pub` and give access to everything after `.ssh/`. This misleading documentation affects all users using
    the experimental permission model in Node.js 20 and Node.js 21. Please note that at the time this CVE was
    issued, the permission model is an experimental feature of Node.js. (CVE-2024-21890)

  - Node.js depends on multiple built-in utility functions to normalize paths provided to node:fs functions,
    which can be overwitten with user-defined implementations leading to filesystem permission model bypass
    through path traversal attack. This vulnerability affects all users using the experimental permission
    model in Node.js 20 and Node.js 21. Please note that at the time this CVE was issued, the permission model
    is an experimental feature of Node.js. (CVE-2024-21891)

  - On Linux, Node.js ignores certain environment variables if those may have been set by an unprivileged user
    while the process is running with elevated privileges with the only exception of CAP_NET_BIND_SERVICE. Due
    to a bug in the implementation of this exception, Node.js incorrectly applies this exception even when
    certain other capabilities have been set. This allows unprivileged users to inject code that inherits the
    process's elevated privileges. (CVE-2024-21892)

  - The permission model protects itself against path traversal attacks by calling path.resolve() on any paths
    given by the user. If the path is to be treated as a Buffer, the implementation uses Buffer.from() to
    obtain a Buffer from the result of path.resolve(). By monkey-patching Buffer internals, namely,
    Buffer.prototype.utf8Write, the application can modify the result of path.resolve(), which leads to a path
    traversal vulnerability. This vulnerability affects all users using the experimental permission model in
    Node.js 20 and Node.js 21. Please note that at the time this CVE was issued, the permission model is an
    experimental feature of Node.js. (CVE-2024-21896)

  - A vulnerability in Node.js HTTP servers allows an attacker to send a specially crafted HTTP request with
    chunked encoding, leading to resource exhaustion and denial of service (DoS). The server reads an
    unbounded number of bytes from a single connection, exploiting the lack of limitations on chunk extension
    bytes. The issue can cause CPU and network bandwidth exhaustion, bypassing standard safeguards like
    timeouts and body size limits. (CVE-2024-22019)

  - A vulnerability in the privateDecrypt() API of the crypto library, allowed a covert timing side-channel
    during PKCS#1 v1.5 padding error handling. The vulnerability revealed significant timing differences in
    decryption for valid and invalid ciphertexts. This poses a serious threat as attackers could remotely
    exploit the vulnerability to decrypt captured RSA ciphertexts or forge signatures, especially in scenarios
    involving API endpoints processing Json Web Encryption messages. Impacts: Thank you, to hkario for
    reporting this vulnerability and thank you Michael Dawson for fixing it. (CVE-2023-46809)

  - setuid() does not affect libuv's internal io_uring operations if initialized before the call to setuid().
    This allows the process to perform privileged operations despite presumably having dropped such privileges
    through a call to setuid(). Impacts: Thank you, to valette for reporting this vulnerability and thank you
    Tobias Nieen for fixing it. (CVE-2024-22017)

  -  Denial of Service by resource exhaustion in fetch() brotli decoding. (CVE-2024-22025)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V20.md#2024-02-14-version-20111-iron-lts-rafaelgss-prepared-by-marco-ippolito
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c63fc58");
  # https://vuxml.freebsd.org/freebsd/77a6f1c9-d7d2-11ee-bb12-001b217b3468.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?895eaaf0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21896");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node21");
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
    'node16>=16.0.0<16.20.3',
    'node18>=18.0.0<18.19.1',
    'node20>=20.0.0<20.11.1',
    'node21>=21.0.0<21.6.2',
    'node>=16.0.0<16.20.3',
    'node>=18.0.0<18.19.1',
    'node>=20.0.0<20.11.1',
    'node>=21.0.0<21.6.2'
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
