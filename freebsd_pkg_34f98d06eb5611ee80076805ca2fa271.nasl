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
  script_id(192717);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/30");

  script_cve_id("CVE-2024-1410", "CVE-2024-1765");

  script_name(english:"FreeBSD : quiche -- Multiple Vulnerabilities (34f98d06-eb56-11ee-8007-6805ca2fa271)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 34f98d06-eb56-11ee-8007-6805ca2fa271 advisory.

  - Cloudflare quiche was discovered to be vulnerable to unbounded storage of information related to
    connection ID retirement, which could lead to excessive resource consumption. Each QUIC connection
    possesses a set of connection Identifiers (IDs); see RFC 9000 Section 5.1
    https://datatracker.ietf.org/doc/html/rfc9000#section-5.1 . Endpoints declare the number of active
    connection IDs they are willing to support using the active_connection_id_limit transport parameter. The
    peer can create new IDs using a NEW_CONNECTION_ID frame but must stay within the active ID limit. This is
    done by retirement of old IDs, the endpoint sends NEW_CONNECTION_ID includes a value in the
    retire_prior_to field, which elicits a RETIRE_CONNECTION_ID frame as confirmation. An unauthenticated
    remote attacker can exploit the vulnerability by sending NEW_CONNECTION_ID frames and manipulating the
    connection (e.g. by restricting the peer's congestion window size) so that RETIRE_CONNECTION_ID frames can
    only be sent at a slower rate than they are received, leading to storage of information related to
    connection IDs in an unbounded queue. Quiche versions 0.19.2 and 0.20.1 are the earliest to address this
    problem. There is no workaround for affected versions. (CVE-2024-1410)

  - Cloudflare Quiche (through version 0.19.1/0.20.0) was affected by an unlimited resource allocation
    vulnerability causing rapid increase of memory usage of the system running quiche server or client. A
    remote attacker could take advantage of this vulnerability by repeatedly sending an unlimited number of
    1-RTT CRYPTO frames after previously completing the QUIC handshake. Exploitation was possible for the
    duration of the connection which could be extended by the attacker. quiche 0.19.2 and 0.20.1 are the
    earliest versions containing the fix for this issue. (CVE-2024-1765)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/cloudflare/quiche/releases/tag/0.20.1");
  # https://vuxml.freebsd.org/freebsd/34f98d06-eb56-11ee-8007-6805ca2fa271.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4caaba3d");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1765");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:quiche");
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
    'quiche<0.20.1'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
