# define macro for name of comiler

CC = gcc

# define a macro for compiler flags.
#CFLAGS = -g -w  -D_is_cgywin -DRN_DEBUG
CFLAGS = -g -pg -w  -D_is_cgywin

OBJ =  que.o if.o in.o mbuf.o route.o radix.o  main.o in_proto.o \
       ip_input.o uipc_domain.o if_ether.o if_ethersubr.o \
       if_le.o if_sl.o ip_output.o raw_cb.o raw_usrreq.o rtsock.o \
       in_pcb.o lalr.o ip_icmp.o  uipc_socket.o raw_ip.o \
       uipc_syscalls.o udp_usrreq.o uipc_socket2.o \
       descrip.o igmp.o  if_vlan.o pfil.o  ip_pool.o  ip_htable.o \
       fil.o ip_lookup.o ip_nat.o ip_fil_netbsd.o ip_frag.o \
       ip_scan.o ip_state.o ip_proxy.o ip_auth.o ip_log.o \
       bpf.o bpf_filter.o


route: $(OBJ)
	$(CC) $(CFLAGS) -o route $(OBJ)
	
test:
	insight route

clean:
	rm *.o;
 


