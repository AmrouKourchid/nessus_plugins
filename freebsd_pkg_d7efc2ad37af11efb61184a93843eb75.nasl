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
  script_id(201253);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-36387",
    "CVE-2024-38473",
    "CVE-2024-38474",
    "CVE-2024-38475",
    "CVE-2024-38476",
    "CVE-2024-38477",
    "CVE-2024-39573"
  );
  script_xref(name:"IAVA", value:"2024-A-0378-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/05/22");

  script_name(english:"FreeBSD : Apache httpd -- Multiple vulnerabilities (d7efc2ad-37af-11ef-b611-84a93843eb75)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the d7efc2ad-37af-11ef-b611-84a93843eb75 advisory.

    The Apache httpd project reports:
    DoS by Null pointer in websocket over HTTP/2 (CVE-2024-36387) (Low).
                Serving WebSocket protocol upgrades over a HTTP/2 connection could
                result in a Null Pointer dereference, leading to a crash of the server
                process, degrading performance.
    Proxy encoding problem (CVE-2024-38473) (Moderate).
                Encoding problem in mod_proxy in Apache HTTP Server 2.4.59 and earlier
                allows request URLs with incorrect encoding to be sent to backend
                services, potentially bypassing authentication via crafted requests.
    Weakness with encoded question marks in backreferences
                (CVE-2024-38474) (Important). Substitution encoding issue in
                mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows attacker
                to execute scripts in directories permitted by the configuration but
                not directly reachable by any URL or source disclosure of scripts
                meant to only to be executed as CGI.
    Weakness in mod_rewrite when first segment of substitution matches
                filesystem path (CVE-2024-38475) (Important). Improper escaping of
                output in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows
                an attacker to map URLs to filesystem locations that are permitted to
                be served by the server but are not intentionally/directly reachable
                by any URL, resulting in code execution or source code disclosure.
                Substitutions in server context that use a backreferences or variables
                as the first segment of the substitution are affected. Some unsafe
                RewiteRules will be broken by this change and the rewrite flag
                UnsafePrefixStat can be used to opt back in once ensuring the
                substitution is appropriately constrained.
    may use exploitable/malicious backend application output to run local
                handlers via internal redirect (CVE-2024-38476) (Important).
                Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are
                vulnerable to information disclosure, SSRF or local script execution
                via backend applications whose response headers are malicious or
                exploitable.
    Crash resulting in Denial of Service in mod_proxy via a malicious
                request (CVE-2024-38477) (Important). Null pointer dereference in
                mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker
                to crash the server via a malicious request.
    mod_rewrite proxy handler substitution (CVE-2024-39573) (Moderate).
                Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier
                allows an attacker to cause unsafe RewriteRules to unexpectedly setup
                URL's to be handled by mod_proxy.

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_24.html");
  # https://vuxml.freebsd.org/freebsd/d7efc2ad-37af-11ef-b611-84a93843eb75.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7db50c31");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38476");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache24");
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
    'apache24<2.4.60'
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
