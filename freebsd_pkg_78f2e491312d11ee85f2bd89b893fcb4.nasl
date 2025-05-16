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
  script_id(179210);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2023-24539",
    "CVE-2023-24540",
    "CVE-2023-29400",
    "CVE-2023-29402",
    "CVE-2023-29403",
    "CVE-2023-29404",
    "CVE-2023-29406"
  );
  script_xref(name:"IAVB", value:"2023-B-0029-S");
  script_xref(name:"IAVB", value:"2023-B-0040-S");
  script_xref(name:"IAVB", value:"2023-B-0052-S");
  script_xref(name:"IAVB", value:"2023-B-0080-S");

  script_name(english:"FreeBSD : go -- multiple vulnerabilities (78f2e491-312d-11ee-85f2-bd89b893fcb4)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 78f2e491-312d-11ee-85f2-bd89b893fcb4 advisory.

  - Angle brackets (<>) are not considered dangerous characters when inserted into CSS contexts. Templates
    containing multiple actions separated by a '/' character can result in unexpectedly closing the CSS
    context and allowing for injection of unexpected HTML, if executed with untrusted input. (CVE-2023-24539)

  - Not all valid JavaScript whitespace characters are considered to be whitespace. Templates containing
    whitespace characters outside of the character set \t\n\f\r\u0020\u2028\u2029 in JavaScript contexts
    that also contain actions may not be properly sanitized during execution. (CVE-2023-24540)

  - Templates containing actions in unquoted HTML attributes (e.g. attr={{.}}) executed with empty input can
    result in output with unexpected results when parsed due to HTML normalization rules. This may allow
    injection of arbitrary attributes into tags. (CVE-2023-29400)

  - The go command may generate unexpected code at build time when using cgo. This may result in unexpected
    behavior when running a go program which uses cgo. This may occur when running an untrusted module which
    contains directories with newline characters in their names. Modules which are retrieved using the go
    command, i.e. via go get, are not affected (modules retrieved using GOPATH-mode, i.e. GO111MODULE=off,
    may be affected). (CVE-2023-29402)

  - On Unix platforms, the Go runtime does not behave differently when a binary is run with the setuid/setgid
    bits. This can be dangerous in certain cases, such as when dumping memory state, or assuming the status of
    standard i/o file descriptors. If a setuid/setgid binary is executed with standard I/O file descriptors
    closed, opening any files can result in unexpected content being read or written with elevated privileges.
    Similarly, if a setuid/setgid program is terminated, either via panic or signal, it may leak the contents
    of its registers. (CVE-2023-29403)

  - The go command may execute arbitrary code at build time when using cgo. This may occur when running go
    get on a malicious module, or when running any other command which builds untrusted code. This is can by
    triggered by linker flags, specified via a #cgo LDFLAGS directive. The arguments for a number of flags
    which are non-optional are incorrectly considered optional, allowing disallowed flags to be smuggled
    through the LDFLAGS sanitization. This affects usage of both the gc and gccgo compilers. (CVE-2023-29404)

  - The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/u/1/g/golang-announce/c/2q13H6LEEx0");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/u/1/g/golang-announce/c/MEb0UyuSMsU");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/u/1/g/golang-announce/c/q5135a9d924");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/u/1/g/golang-announce/c/X0b6CsSAaYI");
  # https://vuxml.freebsd.org/freebsd/78f2e491-312d-11ee-85f2-bd89b893fcb4.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?535952b2");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29404");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go119");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go120");
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
    'go119<1.19.12',
    'go120<1.20.7'
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
