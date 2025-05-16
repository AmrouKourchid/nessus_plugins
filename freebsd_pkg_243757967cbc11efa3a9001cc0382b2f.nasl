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
  script_id(207895);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/25");

  script_cve_id("CVE-2024-47076", "CVE-2024-47175", "CVE-2024-47176");

  script_name(english:"FreeBSD : cups-filters -- remote code execution (24375796-7cbc-11ef-a3a9-001cc0382b2f)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 24375796-7cbc-11ef-a3a9-001cc0382b2f advisory.

    OpenPrinting reports:
    Due to the service binding to *:631 ( INADDR_ANY ), multiple bugs
                in cups-browsed can be exploited in sequence to introduce a
                malicious printer to the system. This chain of exploits ultimately
                enables an attacker to execute arbitrary commands remotely on the
                target machine without authentication when a print job is started.
                Posing a significant security risk over the network. Notably, this
                vulnerability is particularly concerning as it can be exploited
                from the public internet, potentially exposing a vast number of
                systems to remote attacks if their CUPS services are enabled.
    The vulnerability allows an attacker on the internet to create a
              new printer device with arbitrary commands in the PPD file of the
              printer. Attacks using mDNS on the local network can also replace an
              existing printer. The commands are executed when a user attempts to
              print on the malicious device. They run with the privileges of the
              user cups.
    It is recommended to disable the cups_browsed service until patches
              become available. On FreeBSD this is the default. You can check the
              status and disable the service with the following commands:
    # service cups_browsed status
              # service cups_browsed stop
              # service cups_browsed disable
    If you choose to leave the service enabled, attacks from the
              internet can be blocked by removing the cups protocol from the
              BrowseRemoteProtocols and BrowseProtocols directives in
              /usr/local/etc/cups/cups-browsed.conf. Attacks using mDNS can be
              blocked by removing the dnssd protocol as well. Access can be
              limited to specific IP addresses using BrowseAllow, BrowseDeny, and
              BrowseOrder directives as documented in cups-browsed.conf(5). Then
              restart the service with the following command:
    # service cups_browsed restart

Tenable has extracted the preceding description block directly from the FreeBSD security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebf4de66");
  # https://vuxml.freebsd.org/freebsd/24375796-7cbc-11ef-a3a9-001cc0382b2f.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3af2185c");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47076");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-47175");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS IPP Attributes LAN Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cups-filters");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:cups");
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
    'cups-filters<1.28.17_6',
    'cups<2.4.11'
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
