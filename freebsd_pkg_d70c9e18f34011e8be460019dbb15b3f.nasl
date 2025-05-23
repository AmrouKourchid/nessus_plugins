#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2022 Jacques Vidrine and contributors
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
  script_id(119274);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/18");

  script_cve_id(
    "CVE-2016-1000031",
    "CVE-2016-5528",
    "CVE-2017-3239",
    "CVE-2017-3247",
    "CVE-2017-3249",
    "CVE-2017-3250"
  );
  script_xref(name:"TRA", value:"TRA-2016-12");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"FreeBSD : payara -- Multiple vulnerabilities (d70c9e18-f340-11e8-be46-0019dbb15b3f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Apache Commons FileUpload before 1.3.3 DiskFileItem File Manipulation
Remote Code Execution.

Vulnerability in the Oracle GlassFish Server component of Oracle
Fusion Middleware (subcomponent: Administration). Supported versions
that are affected are 3.0.1 and 3.1.2. Easily exploitable
vulnerability allows low privileged attacker with logon to the
infrastructure where Oracle GlassFish Server executes to compromise
Oracle GlassFish Server. Successful attacks of this vulnerability can
result in unauthorized read access to a subset of Oracle GlassFish
Server accessible data. CVSS v3.0 Base Score 3.3 (Confidentiality
impacts).

Vulnerability in the Oracle GlassFish Server component of Oracle
Fusion Middleware (subcomponent: Core). Supported versions that are
affected are 2.1.1, 3.0.1 and 3.1.2. Easily exploitable vulnerability
allows unauthenticated attacker with network access via SMTP to
compromise Oracle GlassFish Server. Successful attacks require human
interaction from a person other than the attacker. Successful attacks
of this vulnerability can result in unauthorized update, insert or
delete access to some of Oracle GlassFish Server accessible data. CVSS
v3.0 Base Score 4.3 (Integrity impacts).

Vulnerability in the Oracle GlassFish Server component of Oracle
Fusion Middleware (subcomponent: Security). Supported versions that
are affected are 2.1.1, 3.0.1 and 3.1.2. Easily exploitable
vulnerability allows unauthenticated attacker with network access via
LDAP to compromise Oracle GlassFish Server. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Oracle GlassFish Server accessible data as well as
unauthorized read access to a subset of Oracle GlassFish Server
accessible data and unauthorized ability to cause a partial denial of
service (partial DOS) of Oracle GlassFish Server. CVSS v3.0 Base Score
7.3 (Confidentiality, Integrity and Availability impacts).

Vulnerability in the Oracle GlassFish Server component of Oracle
Fusion Middleware (subcomponent: Security). Supported versions that
are affected are 2.1.1, 3.0.1 and 3.1.2. Easily exploitable
vulnerability allows unauthenticated attacker with network access via
HTTP to compromise Oracle GlassFish Server. Successful attacks of this
vulnerability can result in unauthorized update, insert or delete
access to some of Oracle GlassFish Server accessible data as well as
unauthorized read access to a subset of Oracle GlassFish Server
accessible data and unauthorized ability to cause a partial denial of
service (partial DOS) of Oracle GlassFish Server. CVSS v3.0 Base Score
7.3 (Confidentiality, Integrity and Availability impacts).

Vulnerability in the Oracle GlassFish Server component of Oracle
Fusion Middleware (subcomponent: Security). Supported versions that
are affected are 2.1.1, 3.0.1 and 3.1.2. Difficult to exploit
vulnerability allows unauthenticated attacker with network access via
multiple protocols to compromise Oracle GlassFish Server. While the
vulnerability is in Oracle GlassFish Server, attacks may significantly
impact additional products. Successful attacks of this vulnerability
can result in takeover of Oracle GlassFish Server. CVSS v3.0 Base
Score 9.0 (Confidentiality, Integrity and Availability impacts).");
  # https://vuxml.freebsd.org/freebsd/d70c9e18-f340-11e8-be46-0019dbb15b3f.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8055159");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2016-12");
  script_set_attribute(attribute:"solution", value:
"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3250");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-1000031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:payara");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"payara=4.1.2.173")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
