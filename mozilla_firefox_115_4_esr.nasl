#%NASL_MIN_LEVEL 80900
## 
# (C) Tenable, Inc.
#                                  
# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2023-46.
# The text itself is copyright (C) Mozilla Foundation.
##

include('compat.inc');

if (description)
{
  script_id(183784);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/01");

  script_cve_id(
    "CVE-2023-5721",
    "CVE-2023-5724",
    "CVE-2023-5725",
    "CVE-2023-5726",
    "CVE-2023-5727",
    "CVE-2023-5728",
    "CVE-2023-5730",
    "CVE-2023-5732"
  );
  script_xref(name:"IAVA", value:"2023-A-0585-S");

  script_name(english:"Mozilla Firefox ESR < 115.4");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Firefox ESR installed on the remote Windows host is prior to 115.4. It is, therefore, affected by
multiple vulnerabilities as referenced in the mfsa2023-46 advisory.

  - It was possible for certain browser prompts and dialogs to be activated or dismissed unintentionally by
    the user due to an insufficient activation-delay. (CVE-2023-5721)

  - An attacker could have created a malicious link using bidirectional characters to spoof the location in
    the address bar when visited. (CVE-2023-5732)

  - Drivers are not always robust to extremely large draw calls and in some cases this scenario could have led
    to a crash. (CVE-2023-5724)

  - A malicious installed WebExtension could open arbitrary URLs, which under the right circumstance could be
    leveraged to collect sensitive user data. (CVE-2023-5725)

  - A website could have obscured the full screen notification by using the file open dialog. This could have
    led to user confusion and possible spoofing attacks.  Note: This issue only affected macOS operating
    systems. Other operating systems are unaffected. (CVE-2023-5726)

  - The executable file warning was not presented when downloading .msix, .msixbundle, .appx, and .appxbundle
    files, which can run commands on a user's computer.   Note: This issue only affected Windows operating
    systems. Other operating systems are unaffected. (CVE-2023-5727)

  - During garbage collection extra operations were performed on a object that should not be. This could have
    led to a potentially exploitable crash. (CVE-2023-5728)

  - Memory safety bugs present in Firefox 118, Firefox ESR 115.3, and Thunderbird 115.3. Some of these bugs
    showed evidence of memory corruption and we presume that with enough effort some of these could have been
    exploited to run arbitrary code. (CVE-2023-5730)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-46/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Firefox ESR version 115.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5730");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox_esr");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Firefox/Version");

  exit(0);
}

include('mozilla_version.inc');

var port = get_kb_item('SMB/transport');
if (!port) port = 445;

var installs = get_kb_list('SMB/Mozilla/Firefox/*');
if (isnull(installs)) audit(AUDIT_NOT_INST, 'Firefox');

mozilla_check_version(installs:installs, product:'firefox', esr:TRUE, fix:'115.4', min:'115.0.0', severity:SECURITY_HOLE);
