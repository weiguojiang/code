/*
 * Copyright (c) 1990, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


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




