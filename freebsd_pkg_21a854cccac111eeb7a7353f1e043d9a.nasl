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
  script_id(190577);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/21");

  script_cve_id("CVE-2023-50387", "CVE-2023-50868");

  script_name(english:"FreeBSD : DNSSEC validators -- denial-of-service/CPU exhaustion from KeyTrap and NSEC3 vulnerabilities (21a854cc-cac1-11ee-b7a7-353f1e043d9a)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 21a854cc-cac1-11ee-b7a7-353f1e043d9a advisory.

  - Certain DNSSEC aspects of the DNS protocol (in RFC 4035 and related RFCs) allow remote attackers to cause
    a denial of service (CPU consumption) via one or more DNSSEC responses when there is a zone with many
    DNSKEY and RRSIG records, aka the KeyTrap issue. The protocol specification implies that an algorithm
    must evaluate all combinations of DNSKEY and RRSIG records. (CVE-2023-50387)

  - The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped)
    allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC
    responses in a random subdomain attack, aka the NSEC3 issue. The RFC 5155 specification implies that an
    algorithm must perform thousands of iterations of a hash function in certain situations. (CVE-2023-50868)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://blog.powerdns.com/2024/02/13/powerdns-recursor-4-8-6-4-9-3-5-0-2-released
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fae9cd7a");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2023-50387");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/docs/cve-2023-50868");
  # https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2024q1/017430.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca294afc");
  script_set_attribute(attribute:"see_also", value:"https://nlnetlabs.nl/news/2024/Feb/13/unbound-1.19.1-released/");
  # https://vuxml.freebsd.org/freebsd/21a854cc-cac1-11ee-b7a7-353f1e043d9a.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65034879");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind9-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind916");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind918");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dnsmasq-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:powerdns-recursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:unbound");
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
    'bind9-devel<9.19.21',
    'bind916<9.16.48',
    'bind918<9.18.24',
    'dnsmasq-devel<2.90',
    'dnsmasq<2.90',
    'powerdns-recursor<5.0.2',
    'unbound<1.19.1'
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
