

#include "mbuf.h"
#include "if.h"
#include "route.h"
#include "socket.h"
#include "radix.h"
#include "in_var.h"
#include "in_var.h"
#include "if_ether.h"


extern struct mbuf arp_m;

extern struct ifnet loif;
extern struct sl_softc sl_softc[2];
extern struct le_softc le_softc[NLE]; 

extern struct ifnet *ifnet;
extern struct ifaddr **ifnet_addrs;

extern int if_index;

extern struct in_ifaddr *in_ifaddr;

extern	struct domain inetdomain;
extern	struct protosw inetsw[];

extern int max_linkhdr;
extern int max_protodhr;
extern int max_hdr;
extern int max_datalen;
extern struct route_cb route_cb;
			
extern struct	ifqueue ipintrq;

extern void test_add_route_r();

struct pdevinit {
   void (*pdev_attach)(int);
   int pdev_count;
};

struct pdevinit pdevinit[] = {
    	{slattach, 1},
    	{loopattach, 1},
    	{0,0},			
};


int  handle_inter_proc ()
{
    input_eth(); 
    ipintr();    
    arpintr();
  
}

void create_ethernet_interface()
{
  main_le();
}

  void add_route_r()
{
//  test_add_route_r();
}


max_protohdr = 40; 
max_linkhdr =  16;
  
int
main(argc, argv)
	int argc;
	char *argv[];
{ 
 
  int s;
  struct pdevinit* pdev;

  route_cb.any_count = 2;

  s = splimp();
  domaininit();   /* initialize protocal domains */
  splx(s);

  mtrace();
  /* initialize ethernet interface devices */
  create_ethernet_interface (); 

  /* Attach pseudo-device.( e.g.  loopback and P2P interfacs.)*/
  for (pdev = pdevinit; pdev->pdev_attach != NULL; pdev++)
	 (*pdev->pdev_attach)(pdev->pdev_count);

  ifinit() ;            /* initialize network interface */

#if 0
  s = splimp();
  ifinit() ;            /* initialize network interface */
  domaininit();   /* initialize protocal domains */
  splx(s);
#endif

  create_ip_addr_r();

  cfg_bpf( );

  create_vlan_r();
  create_vlan_ip__r();

  output_ethernet();

  /* simulate the arp messate*/ 
  handle_inter_proc();
  
  add_route_r();

//  send_data_via_sock_r();
  handle_inter_proc();

  delete_ethernet_interface_r();

  output_ethernet();  
  output_ip();

  handle_inter_proc();

#if ACL
  test_pool_main(argc, argv);
#endif

   test_bpf();

   return 0;
}


/*
  main_sock();
*/
  


 /*  init the parcial tree for route
      it could be invoke in domaininit for routedomain.
      it manually invoke when routedomain not attach
 
  
    route_init();
 

   init the domain list
    
    domaininit(); 

 test the function of mbuf  
   main_buf();

 
   create two ethernet interface eth0 and eth1. init it

 
    main_le();
 
    main_loop();
	
 
   set the max queue length
 
    ifinit() ;  
  

    allocate some IP address for eth0 interface

  test_raw_sock();

  test_rt_sock();

    test_rt_sock();
    main_inc();
    

    allocate some route in route entry

    main_route();

    simulate to output IP data


    output_ethernet();
    
       output_ip();

	main_sock();


	*/
        	 
