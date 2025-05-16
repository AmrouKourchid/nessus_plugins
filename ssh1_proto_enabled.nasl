#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10882);
 script_version("1.37");

 script_cve_id("CVE-2001-0361", "CVE-2001-0572", "CVE-2001-1473");
 script_bugtraq_id(2344);
 

 script_name(english:"SSH Protocol Version 1 Session Key Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service offers an insecure cryptographic protocol." );
 script_set_attribute(attribute:"description", value:
"The remote SSH daemon supports connections made using the version 1.33
and/or 1.5 of the SSH protocol. 

These protocols are not completely cryptographically safe so they
should not be used." );
 script_set_attribute(attribute:"solution", value:
"Disable compatibility with version 1 of the SSH protocol." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2001-1473");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/06");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:ssh:ssh");
script_end_attributes();

 
 script_summary(english:"Negotiate SSH connections");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2023 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencies("ssh_proto_version.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}


var port = get_kb_item("Services/ssh");
if(!port) port = 22;

if (  get_kb_item("SSH/" + port + "/v1_supported" ) )
	security_hole(port);
