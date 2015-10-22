# define macro for name of comiler

CC = gcc

# define a macro for compiler flags.
CFLAGS = -g -w 

OBJ = que.o if.o in.o mbuf.o route.o radix.o  main.o in_proto.o \
       ip_input.o uipc_domain.o if_ether.o if_ethersubr.o \
       if_le.o if_sl.o ip_output.o raw_cb.o raw_usrreq.o rtsock.o \
       in_pcb.o lalr.o ip_icmp.o  uipc_socket.o raw_ip.o \
       uipc_syscalls.o udp_usrreq.o uipc_socket2.o \
       descrip.o

CBJ = que.c if.c in.c mbuf.c route.c  radix.c  main.c in_proto.c \
       ip_input.c uipc_domain.c if_ether.c if_ethersubr.c \
       if_le.c if_sl.c ip_output.c raw_cb.c raw_usrreq.c rtsock.c \
       in_pcb.c lalr.c ip_icmp.c uipc_socket.c raw_ip.c \
       uipc_syscalls.c udp_usrreq.c uipc_socket2.c \
       descrip.c
       
HFILE =  if.h mbuf.h socket.h route.h radix.h if_ether.h in.h \
         raw_cb.h  in_pcb.h udp_var.h   

route: $(OBJ)
	$(CC) $(CFLAGS) -o route $(OBJ)
	
mbuf.o: mbuf.c if.h mbuf.h

if.o: if.c if.h mbuf.h socket.h route.h

que.o: que.c generic.h

uipc_syscalls.o: uipc_syscalls.c $(HFILE)

in.o: in.c $(HFILE)

descrip.o: descrip.c $(HFILE)

route.o: route.c $(HFILE)
  
radix.o: radix.c $(HFILE)

main.o: main.c $(HFILE)

ip_input.o : ip_input.c $(HFILE)

ip_output.o : ip_output.c $(HFILE)

in_proto.o: in_proto.c ip_input.c $(HFILE)

uipc_domain.o: uipc_domain.c $(HFILE)

if_ethersubr.o: if_ethersubr.c $(HFILE)

if_le.o: if_le.c $(HFILE)

if_sl.o: if_sl.c $(HFILE)

if_ether.o: if_ether.c $(HFILE)

raw_cb.o: raw_cb.c $(HFILE)

raw_usrreq.o: raw_usrreq.c $(HFILE)

rt_sock.o: rt_sock.c $(HFILE)

in_pcb.o: in_pcb.c $(HFILE)

lalr.o: lalr.c $(HFILE)

ip_icmp.o: ip_icmp.c $(HFILE)

uipc_socket.o: uipc_socket.c $(HFILE)

uipc_socket2.o: uipc_socket2.c $(HFILE)

raw_ip.o: raw_ip.c $(HFILE)

udp_usrreq.o: udp_usrreq.c $(HFILE)

