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
  script_id(213068);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id(
    "CVE-2024-37302",
    "CVE-2024-37303",
    "CVE-2024-52805",
    "CVE-2024-52815",
    "CVE-2024-53863",
    "CVE-2024-53867"
  );

  script_name(english:"FreeBSD : py-matrix-synapse -- multiple vulnerabilities in versions prior to 1.120.1 (71f3e9f0-bafc-11ef-885d-901b0e934d69)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 71f3e9f0-bafc-11ef-885d-901b0e934d69 advisory.

    element-hq/synapse developers report:
    [The 1.120.1] release fixes multiple security
                    vulnerabilities, some affecting all prior versions of
                    Synapse. Server administrators are encouraged to
                    update Synapse as soon as possible. We are not aware
                    of these vulnerabilities being exploited in the
                    wild.
    Administrators who are unable to update Synapse may
                    use the workarounds described in the linked GitHub
                    Security Advisory below.

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-4mhg-xv73-xq2x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4aba52d1");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-56w4-5538-8v8h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00f7b831");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-f3r3-h2mq-hx2h
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3897bc60");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-gjgr-7834-rhxr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?359b9ffc");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-rfq8-j7rh-8hf2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?53f6f480");
  # https://github.com/element-hq/synapse/security/advisories/GHSA-vp6v-whfm-rv3g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?195b2c61");
  # https://vuxml.freebsd.org/freebsd/71f3e9f0-bafc-11ef-885d-901b0e934d69.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76dfd5ec");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37303");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-52815");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py310-matrix-synapse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py311-matrix-synapse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py38-matrix-synapse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py39-matrix-synapse");
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
    'py310-matrix-synapse<1.120.1',
    'py311-matrix-synapse<1.120.1',
    'py38-matrix-synapse<1.120.1',
    'py39-matrix-synapse<1.120.1'
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
