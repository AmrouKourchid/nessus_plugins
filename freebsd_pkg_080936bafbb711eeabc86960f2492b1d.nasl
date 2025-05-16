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
  script_id(193367);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/13");

  script_cve_id("CVE-2024-31497");
  script_xref(name:"IAVA", value:"2024-A-0243");

  script_name(english:"FreeBSD : PuTTY and embedders (f.i., filezilla) -- biased RNG with NIST P521/ecdsa-sha2-nistp521 signatures permits recovering private key (080936ba-fbb7-11ee-abc8-6960f2492b1d)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 080936ba-fbb7-11ee-abc8-6960f2492b1d advisory.

  - In PuTTY 0.68 through 0.80 before 0.81, biased ECDSA nonce generation allows an attacker to recover a
    user's NIST P-521 secret key via a quick attack in approximately 60 signatures. This is especially
    important in a scenario where an adversary is able to read messages signed by PuTTY or Pageant. The
    required set of signed messages may be publicly readable because they are stored in a public Git service
    that supports use of SSH for commit signing, and the signatures were made by Pageant through an agent-
    forwarding mechanism. In other words, an adversary may already have enough signature information to
    compromise a victim's private key, even if there is no further use of vulnerable PuTTY versions. After a
    key compromise, an adversary may be able to conduct supply-chain attacks on software maintained in Git. A
    second, independent scenario is that the adversary is an operator of an SSH server to which the victim
    authenticates (for remote login or file copy), even though this server is not fully trusted by the victim,
    and the victim uses the same private key for SSH connections to other services operated by other entities.
    Here, the rogue server operator (who would otherwise have no way to determine the victim's private key)
    can derive the victim's private key, and then use it for unauthorized access to those other services. If
    the other services include Git services, then again it may be possible to conduct supply-chain attacks on
    software maintained in Git. This also affects, for example, FileZilla before 3.67.0, WinSCP before 6.3.3,
    TortoiseGit before 2.15.0.1, and TortoiseSVN through 1.14.6. (CVE-2024-31497)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://filezilla-project.org/versions.php");
  # https://git.tartarus.org/?h=c193fe9848f50a88a4089aac647fecc31ae96d27&p=simon/putty.git
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b14fd0a");
  script_set_attribute(attribute:"see_also", value:"https://lists.tartarus.org/pipermail/putty-announce/2024/000038.html");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2024-31497");
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-p521-bias.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e57529e");
  # https://vuxml.freebsd.org/freebsd/080936ba-fbb7-11ee-abc8-6960f2492b1d.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?efd844aa");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31497");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:filezilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty-nogtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'filezilla<3.67.0',
    'putty-nogtk>=0.68<0.81',
    'putty>=0.68<0.81'
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
