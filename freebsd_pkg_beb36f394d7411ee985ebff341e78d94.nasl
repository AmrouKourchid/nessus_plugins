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
  script_id(180583);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39320",
    "CVE-2023-39321",
    "CVE-2023-39322"
  );
  script_xref(name:"IAVB", value:"2023-B-0068-S");
  script_xref(name:"IAVB", value:"2023-B-0080-S");

  script_name(english:"FreeBSD : go -- multiple vulnerabilities (beb36f39-4d74-11ee-985e-bff341e78d94)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the beb36f39-4d74-11ee-985e-bff341e78d94 advisory.

  - The Go project reports: cmd/go: go.mod toolchain directive allows arbitrary            execution The
    go.mod toolchain directive, introduced in Go 1.21,            could be leveraged to execute scripts and
    binaries            relative to the root of the module when the go command            was executed
    within the module. This applies to modules            downloaded using the go command from the module
    proxy,            as well as modules downloaded directly using VCS software. html/template: improper
    handling of HTML-like comments            within script contexts The html/template package did not
    properly handle            HMTL-like <!-- and -->            comment tokens, nor hashbang #! comment
    tokens, in            <script> contexts. This may cause the template            parser to improperly
    interpret the contents of            <script> contexts, causing actions to be improperly
    escaped. This could be leveraged to perform an XSS attack. html/template: improper handling of special
    tags within            script contexts The html/template package did not apply the proper rules
    for handling occurrences            of <script, <!--, and </script within JS            literals in
    <script< contexts. This may cause the            template parser to improperly consider script contexts to
    be terminated early, causing actions to be improperly            escaped. This could be leveraged to
    perform an XSS attack. crypto/tls: panic when processing post-handshake message            on QUIC
    connections Processing an incomplete post-handshake message for a QUIC            connection caused a
    panic. (CVE-2023-39318, CVE-2023-39319, CVE-2023-39320, CVE-2023-39321, CVE-2023-39322)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://groups.google.com/g/golang-dev/c/2C5vbR-UNkI/m/L1hdrPhfBAAJ?pli=1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ff96fa9e");
  # https://vuxml.freebsd.org/freebsd/beb36f39-4d74-11ee-985e-bff341e78d94.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6256c0e3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39320");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go120");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:go121");
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
    'go120<1.20.8',
    'go121<1.21.1'
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
