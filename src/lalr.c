
#include "generic.h"
#include "radix.h"


/*

typedef
  struct shorts
    {
      struct shorts *next;
      short value;
    }
  shorts;

short *lookaheads;
short *LAruleno;
unsigned *LA;
short *accessing_symbol;
short *goto_map;
short *from_state;
short *to_state;

int tokensetsize;
static int infinity;

static int maxrhs;
static int ngotos;
static short **includes;
static shorts **lookback;

static short **R;
static unsigned *F;
static short *INDEX;
static short *VERTICES;
static int top;

void traverse(i)
 int i;
{
  register unsigned *fp1;
  register unsigned *fp2;
  register unsigned *fp3;
  register int j;
  register short *rp;

  int height;
  unsigned *base;

  VERTICES[++top] = i;
  INDEX[i] = height = top;

  base = F + i * tokensetsize;
  fp3 = base + tokensetsize;

  rp = R[i];
  if (rp)
    {
      while ((j = *rp++) >= 0)
	{
	  if (INDEX[j] == 0)
	    traverse(j);

	  if (INDEX[i] > INDEX[j])
	    INDEX[i] = INDEX[j];

	  fp1 = base;
	  fp2 = F + j * tokensetsize;

	  while (fp1 < fp3)
	    *fp1++ |= *fp2++;
	}
    }

  if (INDEX[i] == height)
    {
      for (;;)
	{
	  j = VERTICES[top--];
	  INDEX[j] = infinity;

	  if (i == j)
	    break;

	  fp1 = base;
	  fp2 = F + j * tokensetsize;

	  while (fp1 < fp3)
	    *fp2++ = *fp1++;
	}
    }
}

*/

  extern struct radix_node * rn_clist;

 void traverse(i)
   int i;
{

#ifdef RN_DEBUG	
	struct radix_node * rad_node_ptr;

      printf("begin the traverse the route tree  \n\r \n\r\n\r");	

	for (rad_node_ptr = rn_clist; rad_node_ptr;rad_node_ptr = rad_node_ptr->rn_ybro){
	   printf(" nodenum: %d \n\r",rad_node_ptr->rn_info); 
	   printf(" rn_b: %d  \n\r",rad_node_ptr->rn_b);		   	

  	   if(rad_node_ptr->rn_twin) 
  	   {
     	      printf(" nodenum: %d \n\r",rad_node_ptr->rn_twin->rn_info); 
	      printf(" rn_b: %d  \n\r",rad_node_ptr->rn_twin->rn_b);		   	
  	   }
	          	   
	}
     
	printf("exit the traverse the route tree  \n\r \n\r\n\r");
#endif

    return;
}




