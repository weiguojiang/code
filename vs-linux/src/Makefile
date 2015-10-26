# define macro for name of comiler

vpath %.h ../inc

CC = gcc

# define a macro for compiler flags.
#CFLAGS = -g -w  -D_is_cgywin -DRN_DEBUG
CFLAGS = -g -w -DLUTTEST -D_IS_LINUX_ -I/home/w5jiang/workingcopy/SS_ILEITP/src/ovs_dp/inc -I/home/w5jiang/workingcopy/SS_ILEITP/src/ovs_dp/src

OBJ =  ovs_test.o ovs_se_stub.o ovs_flow_dissector.o datapath.o  flow_table.o flow.o vport.o  actions.o flow_netlink.o flex_array.o
       
ovs: $(OBJ)
	$(CC) $(CFLAGS) -o ovs $(OBJ)
	
test:
	gdb  ovs

clean:
	rm *.o; rm ovs;
 


