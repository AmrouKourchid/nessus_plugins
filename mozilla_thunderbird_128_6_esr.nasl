#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2025-05.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(213631);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/31");

  script_cve_id(
    "CVE-2025-0237",
    "CVE-2025-0238",
    "CVE-2025-0239",
    "CVE-2025-0240",
    "CVE-2025-0241",
    "CVE-2025-0242",
    "CVE-2025-0243"
  );

  script_name(english:"Mozilla Thunderbird ESR < 128.6");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird ESR installed on the remote Windows host is prior to 128.6. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2025-05 advisory.

  - Memory safety bugs present in Firefox 133, Thunderbird 133, Firefox ESR 115.18, Firefox ESR 128.5,
    Thunderbird 115.18, and Thunderbird 128.5. Some of these bugs showed evidence of memory corruption and we
    presume that with enough effort some of these could have been exploited to run arbitrary code.
    (CVE-2025-0242)

  - The WebChannel API, which is used to transport various information across processes, did not check the
    sending principal but rather accepted the principal being sent. This could have led to privilege
    escalation attacks. (CVE-2025-0237)

  - Assuming a controlled failed memory allocation, an attacker could have caused a use-after-free, leading to
    a potentially exploitable crash. (CVE-2025-0238)

  - When using Alt-Svc, ALPN did not properly validate certificates when the original server is redirecting to
    an insecure site. (CVE-2025-0239)

  - Parsing a JavaScript module as JSON could under some circumstances cause cross-compartment access, which
    may result in a use-after-free. (CVE-2025-0240)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2025-05/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird ESR version 128.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0242");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-0241");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Thunderbird/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Thunderbird');

mozilla_check_version(installs:installs, product:'thunderbird', esr:TRUE, fix:'128.6', min:'128.0.0', severity:SECURITY_HOLE);
