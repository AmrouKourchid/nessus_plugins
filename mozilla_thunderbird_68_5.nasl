#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from Mozilla Foundation Security Advisory mfsa2020-07.
# The text itself is copyright (C) Mozilla Foundation.

include('compat.inc');

if (description)
{
  script_id(133691);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id(
    "CVE-2020-6792",
    "CVE-2020-6793",
    "CVE-2020-6794",
    "CVE-2020-6795",
    "CVE-2020-6798",
    "CVE-2020-6800"
  );
  script_xref(name:"MFSA", value:"2020-07");
  script_xref(name:"IAVA", value:"2020-A-0072-S");

  script_name(english:"Mozilla Thunderbird < 68.5");

  script_set_attribute(attribute:"synopsis", value:
"A mail client installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is prior to 68.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the mfsa2020-07 advisory.

  - When processing an email message with an ill-formed
    envelope, Thunderbird could read data from a random
    memory location. (CVE-2020-6793)

  - If a user saved passwords before Thunderbird 60 and then
    later set a master password, an unencrypted copy of
    these passwords is still accessible. This is because the
    older stored password file was not deleted when the data
    was copied to a new format starting in Thunderbird 60.
    The new master password is added only on the new file.
    This could allow the exposure of stored password data
    outside of user expectations. (CVE-2020-6794)

  - When processing a message that contains multiple S/MIME
    signatures, a bug in the MIME processing code caused a
    null pointer dereference, leading to an unexploitable
    crash. (CVE-2020-6795)

  - If a <template> tag was used in a
    <select%gt; tag, the parser could be
    confused and allow JavaScript parsing and execution when
    it should not be allowed. A site that relied on the
    browser behaving correctly could suffer a cross-site
    scripting vulnerability as a result.In general, this
    flaw cannot be exploited through email in the
    Thunderbird product because scripting is disabled when
    reading mail, but is potentially a risk in browser or
    browser-like contexts. (CVE-2020-6798)

  - When deriving an identifier for an email message,
    uninitialized memory was used in addition to the message
    contents. (CVE-2020-6792)

  - Mozilla developers and community members Raul Gurzau,
    Tyson Smith, Bob Clary, Liz Henry, and Christian Holler
    reported memory safety bugs present in Firefox 72 and
    Firefox ESR 68.4. Some of these bugs showed evidence of
    memory corruption and we presume that with enough effort
    some of these could have been exploited to run arbitrary
    code.In general, these flaws cannot be exploited
    through email in the Thunderbird product because
    scripting is disabled when reading mail, but are
    potentially risks in browser or browser-like contexts.
    (CVE-2020-6800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-07/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mozilla Thunderbird version 68.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include('mozilla_version.inc');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'68.5', severity:SECURITY_WARNING);
