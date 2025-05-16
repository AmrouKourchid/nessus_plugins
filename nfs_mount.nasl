#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(11356);
 script_version("1.23");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

 script_cve_id("CVE-1999-0170", "CVE-1999-0211", "CVE-1999-0554");

 script_name(english:"NFS Exported Share Information Disclosure");
 script_summary(english:"Checks for NFS");

 script_set_attribute(
  attribute:"synopsis",
  value:
"It is possible to access NFS shares on the remote host."
 );
 script_set_attribute(
  attribute:"description",
  value:
"At least one of the NFS shares exported by the remote server could be
mounted by the scanning host.  An attacker may be able to leverage
this to read (and possibly write) files on remote host.

Note: Shares protected by an ACL that includes the IP of the Nessus
host will not be tested."
 );
 script_set_attribute(
  attribute:"solution",
  value:
"Configure NFS on the remote host so that only authorized hosts can
mount its remote shares."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0554");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'NFS Mount Scanner');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"RPC");

 script_dependencies("rpc_portmap.nasl", "showmount.nasl", "nessus_product_setup.nasl");
 script_require_keys("rpc/portmap", "nfs/exportlist");
 script_exclude_keys("nfs/noshares");

 exit(0);
}

include("nfs_func.inc");
include("sunrpc_func.inc");
include("network_func.inc");

function open_soc(id, name)
{
  local_var port, soc;

  port = get_rpc_port2(program:id, protocol:IPPROTO_UDP);
  if (!port)
    audit(AUDIT_NOT_DETECT, name);

  if (!get_udp_port_state(port))
    audit(AUDIT_NOT_LISTEN, name, port);

  soc = open_priv_sock_udp(dport:port);
  if (!soc)
    audit(AUDIT_SOCK_FAIL, port, "UDP");

  return soc;
}

get_kb_item_or_exit("rpc/portmap");

var shares = get_kb_list_or_exit("nfs/exportlist");
shares = make_list(shares);
if (max_index(shares) == 0)
  exit(1, "No exported shares were found.");

# Before going further, check if the scanner IP is allowed in the share's ACL, 
# as that would negate the vulnerability for the share.
var share_acls = get_kb_list_or_exit("nfs/share_acl");
var acl_check = FALSE;
var no_acls = {};
var open_share = NULL;
var scanner_ip, acl, subnet_w_cidr, subnet_w_wild;

if (!get_kb_item("Host/msp_scanner"))  # Tenable.io Cloud Scanner
{
  scanner_ip = compat::this_host();
  dbg::detailed_log(lvl:1, msg:'Scanner IP: ' + scanner_ip);
}

if (!empty_or_null(scanner_ip))
{
  no_acls = make_list(no_acls);
  foreach acl (share_acls)
  {
    subnet_w_cidr = pregmatch(pattern:"(\/\S+)\s(\d+\.\d+\.\d+\.\d\/\d+)$", string:acl);
    if (!empty_or_null(subnet_w_cidr))
    {
      # check if the scanner IP is within the ACL range - no need to test it if it is
      acl_check = check_ipv4_in_cidr(ip:scanner_ip, cidr:subnet_w_cidr[2]);
      if (acl_check == 0)
      {
        # List of exports with ACLs that exclude scanner IP to test
        open_share = subnet_w_cidr[1];
        dbg::detailed_log(lvl:1, msg:'ACL range excludes scanner IP for share: ' + obj_rep(open_share));
        if(!isnull(open_share))
          append_element(var:no_acls, value:open_share);
      }
    }  
    if (empty_or_null(subnet_w_cidr))
    {
      # If ACLs are defined by a wildcard, still test it.
      subnet_w_wild = pregmatch(pattern:"(\/\S+)\s(\*)$", string:acl);
      if (!empty_or_null(subnet_w_wild))
      {
        # Add exports whose ACL is a wildcard to the list to test
        open_share = subnet_w_wild[1];
        dbg::detailed_log(lvl:1, msg:'ACL defined with wildcard for share: ' + obj_rep(open_share));
        if (!isnull(open_share))
          append_element(var:no_acls, value:open_share);
      }
    } 
    else continue;
  }
}

if (max_index(no_acls) == 0)
  dbg::detailed_log(lvl:1, msg:'All shares protected by ACLs that include the scanner IP. No further testing will be done.');
else
  dbg::detailed_log(lvl:2, msg:'Shares to test after checking ACLs for scanner IP: ' + obj_rep(no_acls));

var soc1 = open_soc(id:100005, name:"Mount Daemon");

# RFC 1094, Section A.1: Introduction
#
# Version one of the mount protocol is used with version two of the
# NFS protocol. The only information communicated between these two
# protocols is the "fhandle" structure.

var mountable = "";
var soc2, share, c, content, fid;

foreach share (sort(no_acls))
{
  fid = nfs_mount(soc:soc1, share:share, ver:1);
  if (!fid)
    continue;

  # Due to a bug in Nessus, we need to open the NFS socket up
  # after the mount socket has already been used.
  if (soc2)
    close(soc2);
  soc2 = open_soc(id:100003, name:"NFS Daemon");

  mountable += '\n+ ' + share + '\n';
  content = nfs_readdir(soc:soc2, fid:fid, ver:2);
  if (max_index(content) != 0)
    mountable += '  + Contents of ' + share + ' : \n';
  
  foreach c (sort(content))
    mountable += '    - ' + c + '\n';

  nfs_umount(soc:soc1, share:share);
}

close(soc1);

if (!mountable)
  exit(1, "Failed to mount any NFS shares on the remote host.");

var report =
  '\nThe following NFS shares could be mounted :' +
  '\n' + mountable;
security_hole(port:2049, proto:"udp", extra:report);
