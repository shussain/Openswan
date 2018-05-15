struct iface_dev  sun_ifd1 = {
	.id_count = 1,
	.id_vname = "ipsec0",
	.id_rname = "eth0"
};

struct iface_port sun_if1 = {
	.ip_dev = &sun_ifd1,
	.port   = 500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 0,
	.change    = IFN_KEEP
};

struct iface_port sun_if2 = {
	.ip_dev = &sun_ifd1,
	.port   = 4500,
        .socktypename = "AF_INET",
	.ip_addr.u.v4.sin_family = AF_INET,
	.fd     = -1,
	.next   = NULL,
	.ike_float = 1,
	.change    = IFN_KEEP
};

void init_sun_interface(bool doipv6 UNUSED)
{
  init_iface_port(&sun_if1);
  sun_if1.next = interfaces;
  inet_pton(AF_INET, "192.168.0.2", &sun_if1.ip_addr.u.v4.sin_addr);
  interfaces = &sun_if1;

  init_iface_port(&sun_if2);
  sun_if2.next = interfaces;
  inet_pton(AF_INET, "192.168.0.2", &sun_if2.ip_addr.u.v4.sin_addr);
  interfaces = &sun_if2;
}
