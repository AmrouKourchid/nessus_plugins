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
  script_id(179385);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/12");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2023-3347",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );
  script_xref(name:"IAVA", value:"2023-A-0376-S");

  script_name(english:"FreeBSD : samba -- multiple vulnerabilities (441e1e1a-27a5-11ee-a156-080027f5fec9)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by multiple
vulnerabilities as referenced in the 441e1e1a-27a5-11ee-a156-080027f5fec9 advisory.

  - An out-of-bounds read vulnerability was found in Samba due to insufficient length checks in
    winbindd_pam_auth_crap.c. When performing NTLM authentication, the client replies to cryptographic
    challenges back to the server. These replies have variable lengths, and Winbind fails to check the lan
    manager response length. When Winbind is used for NTLM authentication, a maliciously crafted request can
    trigger an out-of-bounds read in Winbind, possibly resulting in a crash. (CVE-2022-2127)

  - A vulnerability was found in Samba's SMB2 packet signing mechanism. The SMB2 packet signing is not
    enforced if an admin configured server signing = required or for SMB2 connections to Domain Controllers
    where SMB2 packet signing is mandatory. This flaw allows an attacker to perform attacks, such as a man-in-
    the-middle attack, by intercepting the network traffic and modifying the SMB2 messages between client and
    server, affecting the integrity of the data. (CVE-2023-3347)

  - An infinite loop vulnerability was found in Samba's mdssvc RPC service for Spotlight. When parsing
    Spotlight mdssvc RPC packets sent by the client, the core unmarshalling function sl_unpack_loop() did not
    validate a field in the network packet that contains the count of elements in an array-like structure. By
    passing 0 as the count value, the attacked function will run in an endless loop consuming 100% CPU. This
    flaw allows an attacker to issue a malformed RPC request, triggering an infinite loop, resulting in a
    denial of service condition. (CVE-2023-34966)

  - A Type Confusion vulnerability was found in Samba's mdssvc RPC service for Spotlight. When parsing
    Spotlight mdssvc RPC packets, one encoded data structure is a key-value style dictionary where the keys
    are character strings, and the values can be any of the supported types in the mdssvc protocol. Due to a
    lack of type checking in callers of the dalloc_value_for_key() function, which returns the object
    associated with a key, a caller may trigger a crash in talloc_get_size() when talloc detects that the
    passed-in pointer is not a valid talloc pointer. With an RPC worker process shared among multiple client
    connections, a malicious client or attacker can trigger a process crash in a shared RPC mdssvc worker
    process, affecting all other clients this worker serves. (CVE-2023-34967)

  - A path disclosure vulnerability was found in Samba. As part of the Spotlight protocol, Samba discloses the
    server-side absolute path of shares, files, and directories in the results for search queries. This flaw
    allows a malicious client or an attacker with a targeted RPC request to view the information that is part
    of the disclosed path. (CVE-2023-34968)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-2127.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-3347.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34966.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34967.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34968.html");
  # https://vuxml.freebsd.org/freebsd/441e1e1a-27a5-11ee-a156-080027f5fec9.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6c377cb");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba413");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:samba416");
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
    'samba413<4.13.18',
    'samba416<4.16.11'
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
