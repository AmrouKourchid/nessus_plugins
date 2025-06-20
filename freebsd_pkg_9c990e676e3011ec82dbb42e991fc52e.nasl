#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
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

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156470);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/06");

  script_cve_id("CVE-2021-43172", "CVE-2021-43173", "CVE-2021-43174");

  script_name(english:"FreeBSD : routinator -- multiple vulnerabilities (9c990e67-6e30-11ec-82db-b42e991fc52e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 9c990e67-6e30-11ec-82db-b42e991fc52e advisory.

  - NLnet Labs Routinator prior to 0.10.2 happily processes a chain of RRDP repositories of infinite length
    causing it to never finish a validation run. In RPKI, a CA can choose the RRDP repository it wishes to
    publish its data in. By continuously generating a new child CA that only consists of another CA using a
    different RRDP repository, a malicious CA can create a chain of CAs of de-facto infinite length.
    Routinator prior to version 0.10.2 did not contain a limit on the length of such a chain and will
    therefore continue to process this chain forever. As a result, the validation run will never finish,
    leading to Routinator continuing to serve the old data set or, if in the initial validation run directly
    after starting, never serve any data at all. (CVE-2021-43172)

  - In NLnet Labs Routinator prior to 0.10.2, a validation run can be delayed significantly by an RRDP
    repository by not answering but slowly drip-feeding bytes to keep the connection alive. This can be used
    to effectively stall validation. While Routinator has a configurable time-out value for RRDP connections,
    this time-out was only applied to individual read or write operations rather than the complete request.
    Thus, if an RRDP repository sends a little bit of data before that time-out expired, it can continuously
    extend the time it takes for the request to finish. Since validation will only continue once the update of
    an RRDP repository has concluded, this delay will cause validation to stall, leading to Routinator
    continuing to serve the old data set or, if in the initial validation run directly after starting, never
    serve any data at all. (CVE-2021-43173)

  - NLnet Labs Routinator versions 0.9.0 up to and including 0.10.1, support the gzip transfer encoding when
    querying RRDP repositories. This encoding can be used by an RRDP repository to cause an out-of-memory
    crash in these versions of Routinator. RRDP uses XML which allows arbitrary amounts of white space in the
    encoded data. The gzip scheme compresses such white space extremely well, leading to very small compressed
    files that become huge when being decompressed for further processing, big enough that Routinator runs out
    of memory when parsing input data waiting for the next XML element. (CVE-2021-43174)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://nlnetlabs.nl/projects/rpki/security-advisories/");
  # https://vuxml.freebsd.org/freebsd/9c990e67-6e30-11ec-82db-b42e991fc52e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0382271b");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:routinator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'routinator<0.10.1'
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
