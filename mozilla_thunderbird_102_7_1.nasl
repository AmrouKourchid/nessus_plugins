#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-04.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(170918);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/05");

  script_cve_id("CVE-2023-0430");
  script_xref(name:"IAVA", value:"2023-A-0063-S");

  script_name(english:"Mozilla Thunderbird < 102.7.1");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 102.7.1. It is, therefore, affected by a
vulnerability as referenced in the mfsa2023-04 advisory.

  - Certificate OCSP revocation status was not checked when verifying S/Mime signatures. Mail signed with a
    revoked certificate would be displayed as having a valid signature. Thunderbird versions from 68 to
    102.7.0 were affected by this bug. (CVE-2023-0430)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-04/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 102.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0430");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'102.7.1', severity:SECURITY_HOLE);
