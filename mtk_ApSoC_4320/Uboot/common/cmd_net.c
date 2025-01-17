/*
 * (C) Copyright 2000
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * See file CREDITS for list of people who contributed to this
 * project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

/*
 * Boot support
 */
#include <common.h>
#include <command.h>
#include <net.h>
#undef DEBUG
#if (CONFIG_COMMANDS & CFG_CMD_NET)


extern int do_bootm (cmd_tbl_t *, int, int, char *[]);
extern int modifies;
static int netboot_common (int, cmd_tbl_t *, int , char *[]);

#ifdef RALINK_CMDLINE
#ifdef RT2880_U_BOOT_CMD_OPEN
int do_bootp (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	return netboot_common (BOOTP, cmdtp, argc, argv);
}

U_BOOT_CMD(
	bootp,	3,	1,	do_bootp,
	"bootp\t- boot image via network using BootP/TFTP protocol\n",
	"[loadAddress] [bootfilename]\n"
);
#endif
#endif

int do_tftpb (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
#ifdef DEBUG
   printf("File: %s, Func: %s, Line: %d\n", __FILE__,__FUNCTION__ , __LINE__);
#endif   
	return netboot_common (TFTP, cmdtp, argc, argv);
}

//#ifdef RALINK_CMDLINE
#if defined (CONFIG_TINY_UBOOT)
U_BOOT_CMD(
	tftpboot,	3,	1,	do_tftpb,
	"",
	""
);
#else
U_BOOT_CMD(
	tftpboot,	3,	1,	do_tftpb,
	"tftpboot- boot image via network using TFTP protocol\n",
	"[loadAddress] [bootfilename]\n"
);
#endif
//#endif

#ifdef RT2880_U_BOOT_CMD_OPEN
#ifdef RALINK_CMDLINE
int do_rarpb (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	return netboot_common (RARP, cmdtp, argc, argv);
}

U_BOOT_CMD(
	rarpboot,	3,	1,	do_rarpb,
	"rarpboot- boot image via network using RARP/TFTP protocol\n",
	"[loadAddress] [bootfilename]\n"
);
#endif
#endif
#if (CONFIG_COMMANDS & CFG_CMD_DHCP)
int do_dhcp (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	return netboot_common(DHCP, cmdtp, argc, argv);
}

U_BOOT_CMD(
	dhcp,	3,	1,	do_dhcp,
	"dhcp\t- invoke DHCP client to obtain IP/boot params\n",
	"\n"
);
#endif	/* CFG_CMD_DHCP */

#if (CONFIG_COMMANDS & CFG_CMD_NFS)
int do_nfs (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	return netboot_common(NFS, cmdtp, argc, argv);
}

U_BOOT_CMD(
	nfs,	3,	1,	do_nfs,
	"nfs\t- boot image via network using NFS protocol\n",
	"[loadAddress] [host ip addr:bootfilename]\n"
);
#endif	/* CFG_CMD_NFS */

#if (CONFIG_COMMANDS & CFG_CMD_ENV)
static void netboot_update_env (void)
{
	char tmp[22];

	if (NetOurGatewayIP) {
		ip_to_string (NetOurGatewayIP, tmp);
		setenv ("gatewayip", tmp);
	}

	if (NetOurSubnetMask) {
		ip_to_string (NetOurSubnetMask, tmp);
		setenv ("netmask", tmp);
	}

	if (NetOurHostName[0])
		setenv ("hostname", NetOurHostName);

	if (NetOurRootPath[0])
		setenv ("rootpath", NetOurRootPath);

	if (NetOurIP) {
		ip_to_string (NetOurIP, tmp);
		setenv ("ipaddr", tmp);
	}

	if (NetServerIP) {
		ip_to_string (NetServerIP, tmp);
		setenv ("serverip", tmp);
	}

	if (NetOurDNSIP) {
		ip_to_string (NetOurDNSIP, tmp);
		setenv ("dnsip", tmp);
	}
#if (CONFIG_BOOTP_MASK & CONFIG_BOOTP_DNS2)
	if (NetOurDNS2IP) {
		ip_to_string (NetOurDNS2IP, tmp);
		setenv ("dnsip2", tmp);
	}
#endif
	if (NetOurNISDomain[0])
		setenv ("domain", NetOurNISDomain);

}
#endif

static int
netboot_common (int proto, cmd_tbl_t *cmdtp, int argc, char *argv[])
{
	char *s;
	int   rcode = 0;
	int   size;


		printf("\n netboot_common, argc= %d \n", argc);
	/* pre-set load_addr */
	if ((s = getenv("loadaddr")) != NULL) {
		load_addr = simple_strtoul(s, NULL, 16);
	}

	switch (argc) {
	case 1:
		break;

	case 2:	/* only one arg - accept two forms:
		       * just load address, or just boot file name.
		       * The latter form must be written "filename" here.
		       */
		if (argv[1][0] == '"') {	/* just boot filename */
			copy_filename (BootFile, argv[1], sizeof(BootFile));
		} else {			/* load address	*/
			load_addr = simple_strtoul(argv[1], NULL, 16);
		}
		break;

	case 3:	load_addr = simple_strtoul(argv[1], NULL, 16);
		copy_filename (BootFile, argv[2], sizeof(BootFile));
   #ifdef DEBUG		
      printf("load addr= 0x%08x\n", load_addr);
      printf("boot file= %s\n", BootFile);
   #endif      
		break;

	default: printf ("Usage:\n%s\n", cmdtp->usage);
		return 1;
	}

	if ((size = NetLoop(proto)) < 0)
		return 1;
   printf("NetBootFileXferSize= %08x\n", size);
   
	/* NetLoop ok, update environment */
#if (CONFIG_COMMANDS & CFG_CMD_ENV)
	netboot_update_env();
#endif
   
	/* done if no file was loaded (no errors though) */
	if (size == 0)
		return 0;

	/* flush cache */
	flush_cache(load_addr, size);
	
	/* Loading ok, check if we should attempt an auto-start */
	if (((s = getenv("autostart")) != NULL) && (strcmp(s,"yes") == 0)) {
		char *local_args[2];
		local_args[0] = argv[0];
		local_args[1] = NULL;

      if(modifies) {
         setenv("autostart", "no");
         setenv ("bootfile", BootFile);
      #ifdef DEBUG         
         s = getenv("bootfile");
	      printf("save bootfile= %s\n", s);
      #endif
#if (CONFIG_COMMANDS & CFG_CMD_ENV)
         saveenv();		
#endif
      }

		printf ("Automatic boot of image at addr 0x%08lX ...\n",	load_addr);
		rcode = do_bootm (cmdtp, 0, 1, local_args);
	}

#ifdef CONFIG_AUTOSCRIPT
	if (((s = getenv("autoscript")) != NULL) && (strcmp(s,"yes") == 0)) {
		printf("Running autoscript at addr 0x%08lX ...\n", load_addr);
		rcode = autoscript (load_addr);
	}
#endif
	return rcode;
}

#if (CONFIG_COMMANDS & CFG_CMD_PING)
int do_ping (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	

	if (argc < 2)
		return -1;
    
	NetPingIP = string_to_ip(argv[1]);
	if (NetPingIP == 0) {
		printf ("Usage:\n%s\n", cmdtp->usage);
		return -1;
	}

	if (NetLoop(PING) < 0) {
		printf("ping failed; host %s is not alive\n", argv[1]);
		return 1;
	}

	printf("host %s is alive\n", argv[1]);

	return 0;
}

U_BOOT_CMD(
	ping,	2,	1,	do_ping,
	"ping\t- send ICMP ECHO_REQUEST to network host\n",
	"pingAddress\n"
);
#endif	/* CFG_CMD_PING */

#if (CONFIG_COMMANDS & CFG_CMD_CDP)

static void cdp_update_env(void)
{
	char tmp[16];

	if (CDPApplianceVLAN != htons(-1)) {
		printf("CDP offered appliance VLAN %d\n", ntohs(CDPApplianceVLAN));
		VLAN_to_string(CDPApplianceVLAN, tmp);
		setenv("vlan", tmp);
		NetOurVLAN = CDPApplianceVLAN;
	}

	if (CDPNativeVLAN != htons(-1)) {
		printf("CDP offered native VLAN %d\n", ntohs(CDPNativeVLAN));
		VLAN_to_string(CDPNativeVLAN, tmp);
		setenv("nvlan", tmp);
		NetOurNativeVLAN = CDPNativeVLAN;
	}

}

int do_cdp (cmd_tbl_t *cmdtp, int flag, int argc, char *argv[])
{
	int r;

	r = NetLoop(CDP);
	if (r < 0) {
		printf("cdp failed; perhaps not a CISCO switch?\n");
		return 1;
	}

	cdp_update_env();

	return 0;
}

U_BOOT_CMD(
	cdp,	1,	1,	do_cdp,
	"cdp\t- Perform CDP network configuration\n",
);
#endif	/* CFG_CMD_CDP */

#endif	/* CFG_CMD_NET */
