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
  script_id(179872);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/15");

  script_cve_id("CVE-2023-37905", "CVE-2023-38499", "CVE-2023-38500");

  script_name(english:"FreeBSD : typo3 -- multiple vulnerabilities (b1ac663f-3aa9-11ee-b887-b42e991fc52e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the b1ac663f-3aa9-11ee-b887-b42e991fc52e advisory.

  - ckeditor-wordcount-plugin is an open source WordCount Plugin for CKEditor. It has been discovered that the
    `ckeditor-wordcount-plugin` plugin for CKEditor4 is susceptible to cross-site scripting when switching to
    the source code mode. This issue has been addressed in version 1.17.12 of the `ckeditor-wordcount-plugin`
    plugin and users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-37905)

  - TYPO3 is an open source PHP based web content management system. Starting in version 9.4.0 and prior to
    versions 9.5.42 ELTS, 10.4.39 ELTS, 11.5.30, and 12.4.4, in multi-site scenarios, enumerating the HTTP
    query parameters `id` and `L` allowed out-of-scope access to rendered content in the website frontend. For
    instance, this allowed visitors to access content of an internal site by adding handcrafted query
    parameters to the URL of a site that was publicly available. TYPO3 versions 9.5.42 ELTS, 10.4.39 ELTS,
    11.5.30, 12.4.4 fix the problem. (CVE-2023-38499)

  - TYPO3 HTML Sanitizer is an HTML sanitizer, written in PHP, aiming to provide cross-site-scripting-safe
    markup based on explicitly allowed tags, attributes and values. Starting in version 1.0.0 and prior to
    versions 1.5.1 and 2.1.2, due to an encoding issue in the serialization layer, malicious markup nested in
    a `noscript` element was not encoded correctly. `noscript` is disabled in the default configuration, but
    might have been enabled in custom scenarios. This allows bypassing the cross-site scripting mechanism of
    TYPO3 HTML Sanitizer. Versions 1.5.1 and 2.1.2 fix the problem. (CVE-2023-38500)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://typo3.org/article/typo3-1244-and-11530-security-releases-published
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?284f1232");
  # https://vuxml.freebsd.org/freebsd/b1ac663f-3aa9-11ee-b887-b42e991fc52e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebca10fc");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-38500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-11-php80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-11-php81");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-12-php80");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:typo3-12-php81");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    'typo3-11-php80<11.5.30',
    'typo3-11-php81<11.5.30',
    'typo3-12-php80<12.4.4',
    'typo3-12-php81<12.4.4'
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
