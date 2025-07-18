#%NASL_MIN_LEVEL 70300
## 
# (C) Tenable Network Security, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2021-22.
# The text itself is copyright (C) Mozilla Foundation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149528);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/01");

  script_cve_id("CVE-2021-29956", "CVE-2021-29957");
  script_xref(name:"IAVA", value:"2021-A-0246-S");

  script_name(english:"Mozilla Thunderbird < 78.10.2");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 78.10.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2021-22 advisory.

  - If a MIME encoded email contains an OpenPGP inline signed or encrypted message part, but also contains an
    additional unprotected part, Thunderbird did not indicate that only parts of the message are protected.
    (CVE-2021-29957)

  - OpenPGP secret keys that were imported using Thunderbird version 78.8.1 up to version 78.10.1 were stored
    unencrypted on the user's local disk. The master password protection was inactive for those keys. Version
    78.10.2 will restore the protection mechanism for newly imported keys, and will automatically protect keys
    that had been imported using affected Thunderbird versions. (CVE-2021-29956)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-22/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 78.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29957");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"III");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'78.10.2', severity:SECURITY_WARNING);
