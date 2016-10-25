/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*-
 *
 * Copyright (c) 1997 Regents of the University of California.
 * All rights reserved.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 * $Header: /nfs/jade/vint/CVSROOT/ns-2/mac/mac-802_11.cc,v 1.50 2005/09/18 23:33:33 tomh Exp $
 *
 * Ported from CMU/Monarch's code, nov'98 -Padma.
 * Contributions by:
 *   - Mike Holland
 *   - Sushmita
 */

#include "delay.h"
#include "connector.h"
#include "packet.h"
#include "random.h"
#include "mobilenode.h"

// #define DEBUG 99

#include "arp.h"
#include "ll.h"
#include "mac.h"
#include "mac-timers.h"
#include "mac-802_11.h"
#include "cmu-trace.h"

// Added by Sushmita to support event tracing
#include "agent.h"
#include "basetrace.h"

#ifdef SEMITCP
#include <iostream> 
#include<fstream>
#endif

/* our backoff timer doesn't count down in idle times during a
 * frame-exchange sequence as the mac tx state isn't idle; genreally
 * these idle times are less than DIFS and won't contribute to
 * counting down the backoff period, but this could be a real
 * problem if the frame exchange ends up in a timeout! in that case,
 * i.e. if a timeout happens we've not been counting down for the
 * duration of the timeout, and in fact begin counting down only
 * DIFS after the timeout!! we lose the timeout interval - which
 * will is not the REAL case! also, the backoff timer could be NULL
 * and we could have a pending transmission which we could have
 * sent! one could argue this is an implementation artifact which
 * doesn't violate the spec.. and the timeout interval is expected
 * to be less than DIFS .. which means its not a lot of time we
 * lose.. anyway if everyone hears everyone the only reason a ack will
 * be delayed will be due to a collision => the medium won't really be
 * idle for a DIFS for this to really matter!!
 */

inline void
Mac802_11::checkBackoffTimer()
{
	if(is_idle() && mhBackoff_.paused())
		mhBackoff_.resume(phymib_.getDIFS());
	if(! is_idle() && mhBackoff_.busy() && ! mhBackoff_.paused())
		mhBackoff_.pause();
	
	// Inter nodes do not have the following process
	if (!local_congested() && p_to_tcp != nullptr)
	{
		//p_to_tcp->setBackoffTimer();
		p_to_tcp->setSendTimer();
		p_to_tcp->sendTime_ = avgSendTime_;
		p_to_tcp->minSendTime_ = minSendTime_;
	}
}

inline void
Mac802_11::transmit(Packet *p, double timeout)
{
	tx_active_ = 1;
	
	if (EOTtarget_) {
		assert (eotPacket_ == NULL);
		eotPacket_ = p->copy();
	}

	/*
	 * If I'm transmitting without doing CS, such as when
	 * sending an ACK, any incoming packet will be "missed"
	 * and hence, must be discarded.
	 */
	if(rx_state_ != MAC_IDLE) {
		//assert(dh->dh_fc.fc_type == MAC_Type_Control);
		//assert(dh->dh_fc.fc_subtype == MAC_Subtype_ACK);
		assert(pktRx_);
		struct hdr_cmn *ch = HDR_CMN(pktRx_);
		ch->error() = 1;        /* force packet discard */
	}

	/*
	 * pass the packet on the "interface" which will in turn
	 * place the packet on the channel.
	 *
	 * NOTE: a handler is passed along so that the Network
	 *       Interface can distinguish between incoming and
	 *       outgoing packets.
	 */
	downtarget_->recv(p->copy(), this);	
	mhSend_.start(timeout);
	mhIF_.start(txtime(p));
}
inline void
Mac802_11::setRxState(MacState newState)
{
	rx_state_ = newState;
	checkBackoffTimer();
}

inline void
Mac802_11::setTxState(MacState newState)
{
	tx_state_ = newState;
	checkBackoffTimer();
}


/* ======================================================================
   TCL Hooks for the simulator
   ====================================================================== */
static class Mac802_11Class : public TclClass {
public:
	Mac802_11Class() : TclClass("Mac/802_11") {}
	TclObject* create(int, const char*const*) {
	return (new Mac802_11());

}
} class_mac802_11;


/* ======================================================================
   Mac  and Phy MIB Class Functions
   ====================================================================== */

PHY_MIB::PHY_MIB(Mac802_11 *parent)
{
	/*
	 * Bind the phy mib objects.  Note that these will be bound
	 * to Mac/802_11 variables
	 */

	parent->bind("CWMin_", &CWMin);
	parent->bind("CWMax_", &CWMax);
	parent->bind("SlotTime_", &SlotTime);
	parent->bind("SIFS_", &SIFSTime);
	parent->bind("PreambleLength_", &PreambleLength);
	parent->bind("PLCPHeaderLength_", &PLCPHeaderLength);
	parent->bind_bw("PLCPDataRate_", &PLCPDataRate);
}

MAC_MIB::MAC_MIB(Mac802_11 *parent)
{
	/*
	 * Bind the phy mib objects.  Note that these will be bound
	 * to Mac/802_11 variables
	 */
	
	parent->bind("RTSThreshold_", &RTSThreshold);
	parent->bind("ShortRetryLimit_", &ShortRetryLimit);
	parent->bind("LongRetryLimit_", &LongRetryLimit);
}

/* ======================================================================
   Mac Class Functions
   ====================================================================== */
Mac802_11::Mac802_11() : 
	Mac(), 
		maxAckQueueSize_(0),
#ifdef SEMITCP
	avgSendTime_(0.0),
	maxSendTime_(0.0),
	minSendTime_(100000.0),
	sendingDataSeqno_(-1),
	receiveTime_(0.0),
	totalTime_(0.0),
	totalCount_(0),
	nb_congested(-1.0),
	kk(0),
	KK(2),
	last_rts_frame(nullptr),
	round_trip_time(0.020),
	CALLRT(1),
	p_aodv_agent(nullptr),
	p_to_prique(nullptr),
	
	prev_time_(0.0),
	start_time(0.0),
	end_time(0.0),

/*******MHC DEBUG************/

	refuse_other_rts(0),
	dead_lock(0),
 
	RTS_send(0),
	CTS_recv(0),
	CTSC_recv(0),
	DATA_send(0),
	ACK_recv(0),
    
	RTS_recv(0),
	CTS_send(0),
	CTSC_send(0),
	DATA_recv(0),
	ACK_send(0),
	
	RTS_drop(0),
	
	forward_data_send(0),
	backward_ack_send(0),
	forward_data_retransmit(0),
	backward_ack_retransmit(0),
	forward_data_drop(0),
	backward_ack_drop(0),	
       
/*******MHC DEBUG***********/
phymib_(this), macmib_(this),  
	pktPre_(nullptr),
	nbtimer(this),
#endif
mhIF_(this), mhNav_(this),
	mhRecv_(this), mhSend_(this), 
	mhDefer_(this), mhBackoff_(this)
{
#ifdef SEMITCP
	bind ( "K_", &KK );
	bind ( "RTT_", &round_trip_time);
	round_trip_time = round_trip_time * KK;
	bind ( "CALLRT_", &CALLRT); ///SEMIDEBUG
#endif	
	nav_ = 0.0;
	tx_state_ = rx_state_ = MAC_IDLE;
	tx_active_ = 0;
	eotPacket_ = nullptr;
	pktRTS_ = 0;
	pktCTRL_ = 0;		
	cw_ = phymib_.getCWMin();
	ssrc_ = slrc_ = 0;
	// Added by Sushmita
        et_ = new EventTrace();
	
	sta_seqno_ = 1;
	cache_ = 0;
	cache_node_count_ = 0;
	
	// chk if basic/data rates are set
	// otherwise use bandwidth_ as default;
	
	Tcl& tcl = Tcl::instance();
	tcl.evalf("Mac/802_11 set basicRate_");
	if (strcmp(tcl.result(), "0") != 0) 
		bind_bw("basicRate_", &basicRate_);
	else
		basicRate_ = bandwidth_;

	tcl.evalf("Mac/802_11 set dataRate_");
	if (strcmp(tcl.result(), "0") != 0) 
		bind_bw("dataRate_", &dataRate_);
	else
		dataRate_ = bandwidth_;

        EOTtarget_ = nullptr;
       	bss_id_ = IBSS_ID;
	//printf("bssid in constructor %d\n",bss_id_);
}


int
Mac802_11::command(int argc, const char*const* argv)
{
if ( argc ==2 ) 
{
#ifdef SEMITCP
    if ( strcmp ( argv[1], "printavgqlen" ) == 0 ) 
    {
printf("\n--------------------------NODE: %d--------------------\n", index_);

printf("     RTS(C)_send:\t%d\n", RTS_send);
printf("        CTS_recv:\t%d\n", CTS_recv);
printf("       CTSC_recv:\t%d\n", CTSC_recv);
printf("       DATA_send:\t%d\n", DATA_send);
printf("forward_data_send:\t%d\n", forward_data_send);
printf("backward_ack_send:\t%d\n", backward_ack_send);
printf("        ACK_recv:\t%d\n\n", ACK_recv);

printf("     RTS(C)_recv:\t%d\n", RTS_recv);
printf("        CTS_send:\t%d\n", CTS_send);
printf("       CTSC_send:\t%d\n", CTSC_send);
printf("       DATA_recv:\t%d\n", DATA_recv);
printf("        ACK_send:\t%d\n\n", ACK_send);

printf("   RTS_retransmit:\t%d\n", macmib_.RTSFailureCount);
printf("  DATA_retransmit:\t%d\n", macmib_.ACKFailureCount);
printf("backward_ack_retransmit:\t%d\n", backward_ack_retransmit);
printf("forward_data_retransmit:\t%d\n\n", forward_data_retransmit);

printf("      RTS_drop:\t%d\n", RTS_drop);
printf("     DATA_drop:\t%d\n", macmib_.FailedCount);
printf("forward_data_drop:\t%d\n", forward_data_drop);
printf("backward_ack_drop:\t%d\n\n", backward_ack_drop);

if (totalCount_ > 0)
{
printf("	 minSendTime:\t%.2f　mS\n", minSendTime_*1000);
printf("	 avgSendTime:\t%.2f　mS\n\n", totalTime_*1000 / totalCount_);
}

printf("  	  avg_length:\t%.12f\n\n", p_to_prique->avg_length());

double RTS_CTS_rate = 0.0;
double RTS_retransmit_rate = 0.0;
double forward_data_retransmit_rate = 0.0;
double RTS_drop_rate = 0.0;
double forward_data_drop_rate = 0.0;
double all_success_rate = 0.0;

if(RTS_send > 0)
{
    RTS_CTS_rate = (double)(CTS_recv+CTSC_recv) / RTS_send;
	all_success_rate = (double)ACK_recv / (DATA_send + macmib_.RTSFailureCount);
	
	RTS_retransmit_rate = (double)macmib_.RTSFailureCount / RTS_send;
	forward_data_retransmit_rate = (double)forward_data_retransmit / forward_data_send;
	RTS_drop_rate = (double)RTS_drop / RTS_send;
	forward_data_drop_rate = (double)forward_data_drop / forward_data_send;
	
	printf("RTS_per_forward_data:\t%.2f\n\n", (double)RTS_send / forward_data_send);	
}
else
{
    all_success_rate = (double)ACK_recv / DATA_send;
}

printf("    RTS_CTS_rate:\t%.2f%%\n", RTS_CTS_rate * 100.0);
printf("all_success_rate:\t%.2f%%\n\n", all_success_rate * 100.0);

printf("RTS_retransmit_rate:\t%.2f%%\n", RTS_retransmit_rate * 100.0);
printf("forward_data_retransmit_rate:\t%.2f%%\n", forward_data_retransmit_rate * 100.0);
printf("RTS_drop_rate:\t%.2f%%\n", RTS_drop_rate * 100.0);
printf("forward_data_drop_rate:\t%.2f%%\n\n", forward_data_drop_rate * 100.0);

for (const auto &pr : send_time_vec)
{
	fprintf(stdout, "send_time_vec:\t%.6f\t%.6f\n", pr.first, pr.second*1000);
}

	return TCL_OK;
    }   
#endif
}
else if (argc == 3) {
		if (strcmp(argv[1], "eot-target") == 0) {
			EOTtarget_ = (NsObject*) TclObject::lookup(argv[2]);
			if (EOTtarget_ == 0)
				return TCL_ERROR;
			return TCL_OK;
		} else if (strcmp(argv[1], "bss_id") == 0) {
			bss_id_ = atoi(argv[2]);
			return TCL_OK;
		} else if (strcmp(argv[1], "log-target") == 0) { 
			logtarget_ = (NsObject*) TclObject::lookup(argv[2]);
			if(logtarget_ == 0)
				return TCL_ERROR;
			return TCL_OK;
		} else if(strcmp(argv[1], "nodes") == 0) {
			if(cache_) return TCL_ERROR;
			cache_node_count_ = atoi(argv[2]);
			cache_ = new Host[cache_node_count_ + 1];
			assert(cache_);
			bzero(cache_, sizeof(Host) * (cache_node_count_+1 ));
			return TCL_OK;
		} else if(strcmp(argv[1], "eventtrace") == 0) {
			// command added to support event tracing by Sushmita
                        et_ = (EventTrace *)TclObject::lookup(argv[2]);
                        return (TCL_OK);
                }
#ifdef SEMITCP
		else if ( strcmp ( argv[1], "mac-get-ifq" ) == 0 ) {
			p_to_prique= ( PriQueue* ) TclObject::lookup ( argv[2] );
			if ( p_to_prique==0 ) {
				return TCL_ERROR;
			} else {
				return TCL_OK;
			}
		} else if ( strcmp ( argv[1], "mac-get-aodv" ) == 0 ) {
			p_aodv_agent = ( AODV* ) TclObject::lookup ( argv[2] );
			if ( p_aodv_agent == 0 ) {
				return TCL_ERROR;
			} else {
				return TCL_OK;
			}
		}
		else if (strcmp(argv[1], "mac-get-matcp") == 0)
		{
			p_to_tcp = (MaTcpAgent*)TclObject::lookup(argv[2]);
			return (p_to_tcp != nullptr) ? TCL_OK : TCL_ERROR;
		}
#endif
	}
	return Mac::command(argc, argv);
}

// Added by Sushmita to support event tracing
void Mac802_11::trace_event(char *eventtype, Packet *p) 
{
        if (et_ == NULL) return;
        char *wrk = et_->buffer();
        char *nwrk = et_->nbuffer();
	
        //char *src_nodeaddr =
	//       Address::instance().print_nodeaddr(iph->saddr());
        //char *dst_nodeaddr =
        //      Address::instance().print_nodeaddr(iph->daddr());
	
        struct hdr_mac802_11* dh = HDR_MAC802_11(p);
	
        //struct hdr_cmn *ch = HDR_CMN(p);
	
	if(wrk != 0) {
		sprintf(wrk, "E -t " TIME_FORMAT " %s %2x ",
			et_->round(Scheduler::instance().clock()),
                        eventtype,
                        //ETHER_ADDR(dh->dh_sa)
                        ETHER_ADDR(dh->dh_ta)
                        );
        }
        if(nwrk != 0) {
                sprintf(nwrk, "E -t " TIME_FORMAT " %s %2x ",
                        et_->round(Scheduler::instance().clock()),
                        eventtype,
                        //ETHER_ADDR(dh->dh_sa)
                        ETHER_ADDR(dh->dh_ta)
                        );
        }
        et_->dump();
}

/* ======================================================================
   Debugging Routines
   ====================================================================== */
void
Mac802_11::trace_pkt(Packet *p) 
{
	struct hdr_cmn *ch = HDR_CMN(p);
	struct hdr_mac802_11* dh = HDR_MAC802_11(p);
	u_int16_t *t = (u_int16_t*) &dh->dh_fc;

	fprintf(stderr, "\t[ %2x %2x %2x %2x ] %x %s %d\n",
		*t, dh->dh_duration,
		 ETHER_ADDR(dh->dh_ra), ETHER_ADDR(dh->dh_ta),
		index_, packet_info.name(ch->ptype()), ch->size());
}

void
Mac802_11::dump(char *fname)
{
	fprintf(stderr,
		"\n%s --- (INDEX: %d, time: %2.9f)\n",
		fname, index_, Scheduler::instance().clock());

	fprintf(stderr,
		"\ttx_state_: %x, rx_state_: %x, nav: %2.9f, idle: %d\n",
		tx_state_, rx_state_, nav_, is_idle());

	fprintf(stderr,
		"\tpktTx_: %lx, pktRx_: %lx, pktRTS_: %lx, pktCTRL_: %lx, callback: %lx\n",
		(long) pktTx_, (long) pktRx_, (long) pktRTS_,
		(long) pktCTRL_, (long) callback_);

	fprintf(stderr,
		"\tDefer: %d, Backoff: %d (%d), Recv: %d, Timer: %d Nav: %d\n",
		mhDefer_.busy(), mhBackoff_.busy(), mhBackoff_.paused(),
		mhRecv_.busy(), mhSend_.busy(), mhNav_.busy());
	fprintf(stderr,
		"\tBackoff Expire: %f\n",
		mhBackoff_.expire());
}


/* ======================================================================
   Packet Headers Routines
   ====================================================================== */
inline int
Mac802_11::hdr_dst(char* hdr, int dst )
{
	struct hdr_mac802_11 *dh = (struct hdr_mac802_11*) hdr;
	
       if (dst > -2) {
               if ((bss_id() == ((int)IBSS_ID)) || (addr() == bss_id())) {
                       /* if I'm AP (2nd condition above!), the dh_3a
                        * is already set by the MAC whilst fwding; if
                        * locally originated pkt, it might make sense
                        * to set the dh_3a to myself here! don't know
                        * how to distinguish between the two here - and
                        * the info is not critical to the dst station
                        * anyway!
                        */
                       STORE4BYTE(&dst, (dh->dh_ra));
               } else {
                       /* in BSS mode, the AP forwards everything;
                        * therefore, the real dest goes in the 3rd
                        * address, and the AP address goes in the
                        * destination address
                        */
                       STORE4BYTE(&bss_id_, (dh->dh_ra));
                       STORE4BYTE(&dst, (dh->dh_3a));
               }
       }


       return (u_int32_t)ETHER_ADDR(dh->dh_ra);
}

inline int 
Mac802_11::hdr_src(char* hdr, int src )
{
	struct hdr_mac802_11 *dh = (struct hdr_mac802_11*) hdr;
        if(src > -2)
               STORE4BYTE(&src, (dh->dh_ta));
        return ETHER_ADDR(dh->dh_ta);
}

inline int 
Mac802_11::hdr_type(char* hdr, u_int16_t type)
{
	struct hdr_mac802_11 *dh = (struct hdr_mac802_11*) hdr;
	if(type)
		STORE2BYTE(&type,(dh->dh_body));
	return GET2BYTE(dh->dh_body);
}


/* ======================================================================
   Misc Routines
   ====================================================================== */
inline int
Mac802_11::is_idle()
{
	if(rx_state_ != MAC_IDLE)
		return 0;
	if(tx_state_ != MAC_IDLE)
		return 0;
	if(nav_ > Scheduler::instance().clock()) //nav的作用体现在这里
		return 0;
	
	return 1;
}

void
Mac802_11::discard(Packet *p, const char* why)
{
	hdr_mac802_11* mh = HDR_MAC802_11(p);
	hdr_cmn *ch = HDR_CMN(p);

	/* if the rcvd pkt contains errors, a real MAC layer couldn't
	   necessarily read any data from it, so we just toss it now */
	if(ch->error() != 0) {
		Packet::free(p);
		return;
	}

	switch(mh->dh_fc.fc_type) {
	case MAC_Type_Management:
		drop(p, why);
		return;
	case MAC_Type_Control:
		switch(mh->dh_fc.fc_subtype) {
		case MAC_Subtype_RTS:
		#ifdef SEMITCP
		case MAC_Subtype_uRTS:
		#endif
			 if((u_int32_t)ETHER_ADDR(mh->dh_ta) ==  (u_int32_t)index_) {
				drop(p, why);
				return;
			}
			/* fall through - if necessary */
		case MAC_Subtype_CTS:
		case MAC_Subtype_ACK:
			if((u_int32_t)ETHER_ADDR(mh->dh_ra) == (u_int32_t)index_) {
				drop(p, why);
				return;
			}
			break;
		default:
			fprintf(stderr, "invalid MAC Control subtype\n");
			assert(0);///SEMITCP DEBUG
			exit(1);
		}
		break;
	case MAC_Type_Data:
		switch(mh->dh_fc.fc_subtype) {
		case MAC_Subtype_Data:
			if((u_int32_t)ETHER_ADDR(mh->dh_ra) == \
                           (u_int32_t)index_ ||
                          (u_int32_t)ETHER_ADDR(mh->dh_ta) == \
                           (u_int32_t)index_ ||
                          (u_int32_t)ETHER_ADDR(mh->dh_ra) == MAC_BROADCAST) {
                                drop(p,why);
                                return;
			}
			break;
		default:
			fprintf(stderr, "invalid MAC Data subtype\n");
			exit(1);
		}
		break;
	default:
		fprintf(stderr, "invalid MAC type (%x)\n", mh->dh_fc.fc_type);
		trace_pkt(p);
		exit(1);
	}
	Packet::free(p);
}

void
Mac802_11::capture(Packet *p)
{
	/*
	 * Update the NAV so that this does not screw
	 * up carrier sense.
	 */	
	set_nav(usec(phymib_.getEIFS() + txtime(p)));
	Packet::free(p);
}

void
Mac802_11::collision(Packet *p)
{
	switch(rx_state_) {
	case MAC_RECV:
		setRxState(MAC_COLL);
		/* fall through */
	case MAC_COLL:
		assert(pktRx_);
		assert(mhRecv_.busy());
		/*
		 *  Since a collision has occurred, figure out
		 *  which packet that caused the collision will
		 *  "last" the longest.  Make this packet,
		 *  pktRx_ and reset the Recv Timer if necessary.
		 */
		if(txtime(p) > mhRecv_.expire()) {
			mhRecv_.stop();
			discard(pktRx_, DROP_MAC_COLLISION);
			pktRx_ = p;
			mhRecv_.start(txtime(pktRx_));
		}
		else {
			discard(p, DROP_MAC_COLLISION);
		}
		break;
	default:
		assert(0);
	}
}

void
Mac802_11::tx_resume()
{
	double rTime;
	assert(mhSend_.busy() == 0);
	assert(mhDefer_.busy() == 0);

	if(pktCTRL_) {
		/*
		 *  Need to send a CTS or ACK.
		 */
		if (mhDefer_.busy())
			mhDefer_.stop();
		mhDefer_.start(phymib_.getSIFS());
	} else if(pktRTS_) {
		if (mhBackoff_.busy() == 0) {
			rTime = (Random::random() % cw_) * phymib_.getSlotTime();
			mhDefer_.start( phymib_.getDIFS() + rTime);
		}
	} else if(pktTx_) {
		if (mhBackoff_.busy() == 0) {
			hdr_cmn *ch = HDR_CMN(pktTx_);
			struct hdr_mac802_11 *mh = HDR_MAC802_11(pktTx_);
			
			if ((u_int32_t) ch->size() < macmib_.getRTSThreshold()
			    || (u_int32_t) ETHER_ADDR(mh->dh_ra) == MAC_BROADCAST) {
			#ifdef SEMITCP
				rTime = (Random::random() % (cw_ - 10) + Random::random() % 10)
					* phymib_.getSlotTime();
				mhDefer_.start(phymib_.getDIFS() + rTime);
			#else
				rTime = (Random::random() % cw_)
					* phymib_.getSlotTime();
				mhDefer_.start(phymib_.getDIFS() + rTime);
			#endif
                        } else {
				mhDefer_.start(phymib_.getSIFS());
                        }
		}
#ifdef SEMITCP
	} else if(pktPre_ && !nbtimer.busy()) {
		restore_tx();
	} else if(callback_) { //有指向队列的回调指针
		bool call = false;
		if(!pktPre_)
			call = true;
		else {
			Packet* tmp = p_to_prique->q_->lookup( 0 );
			if(tmp) {
				Packet* first = tmp;
				call = HDR_CMN(first)->control_packet();
			} else {
				call = false;
				assert(nbtimer.busy());
			}
		}
		if(call) {
			Handler *h = callback_;     //callback_ is queue
			callback_ = nullptr;
			h->handle((Event*) 0); 	//从queue拉数据下来
		}
	}
#else
	} else if(callback_) {
		Handler *h = callback_;
		callback_ = 0;
		h->handle((Event*) 0);
	}
#endif
	setTxState(MAC_IDLE);
}

void
Mac802_11::rx_resume()
{
	assert(pktRx_ == 0);
	assert(mhRecv_.busy() == 0);
	setRxState(MAC_IDLE);
}


/* ======================================================================
   Timer Handler Routines
   ====================================================================== */
void
Mac802_11::backoffHandler()
{
	if(pktCTRL_) {
		assert(mhSend_.busy() || mhDefer_.busy());
		return;
	}
	if(check_pktRTS() == 0)
		return;

	if(check_pktTx() == 0)
		return;
}

void
Mac802_11::deferHandler()
{
	assert(pktCTRL_ || pktRTS_ || pktTx_);

	if(check_pktCTRL() == 0) {
		return;
	}
	assert(mhBackoff_.busy() == 0);
	if(check_pktRTS() == 0)
		return;
	if(check_pktTx() == 0)
		return;
}

void
Mac802_11::navHandler()
{
	if(is_idle() && mhBackoff_.paused())
		mhBackoff_.resume(phymib_.getDIFS());
}

void
Mac802_11::recvHandler()
{
	recv_timer();
}

void
Mac802_11::sendHandler()
{
	send_timer();
}


void
Mac802_11::txHandler()
{
	if (EOTtarget_) {
		assert(eotPacket_);
		EOTtarget_->recv(eotPacket_, (Handler *) 0);
		eotPacket_ = NULL;
	}
	tx_active_ = 0;
}


/* ======================================================================
   The "real" Timer Handler Routines
   ====================================================================== */
void
Mac802_11::send_timer()
{
	switch(tx_state_) {
	/*
	 * Sent a RTS, but did not receive a CTS.
	 */
	case MAC_RTS: {	//RTS的发送时间包括接收CTS所需的时间
		RetransmitRTS();
		break;
	}
	/*
	 * Sent a CTS, but did not receive a DATA packet.
	 */
	case MAC_CTS:
	{
		assert(pktCTRL_);
	#ifdef SEMITCP
		Neighbour *nb = nbs[RECEIVER(pktCTRL_)];
		struct cts_frame *cf = (struct cts_frame*)pktCTRL_->access(hdr_mac::offset_);

		if(cf->cf_fc.fc_order) {///CTSC
			nb->set_helped_by_me(false);///If fail to recv DATA, reset helped_by_me
			if(TotalCongested() && pktPre_ && !pktTx_ && RECEIVER(pktPre_) == RECEIVER(pktCTRL_))
				restore_tx();
		}
	#endif
		Packet::free(pktCTRL_); 
		pktCTRL_ = nullptr;
		break;
	}
	/*
	 * Sent DATA, but did not receive an ACK packet.
	 */
	case MAC_SEND:
		RetransmitDATA();
		break;
	/*
	 * Sent an ACK, and now ready to resume transmission.
	 */
	case MAC_ACK: {
		assert(pktCTRL_);
#ifdef SEMITCP
		Neighbour* nb = nbs[RECEIVER(pktCTRL_)];
		
		if(nb->get_helped_by_me()) {
			if(pktPre_ && !pktTx_)
				restore_tx();
		}
		if(nb->get_helped_time() > 0.0) {
			nb->set_helped_time(-1.0);
		}
#endif
		Packet::free(pktCTRL_); 
		pktCTRL_ = 0;
		break;
	}
	case MAC_IDLE:
		break;
	default:
		assert(0);
	}
	tx_resume();
}


/* ======================================================================
   Outgoing Packet Routines
   ====================================================================== */
int
Mac802_11::check_pktCTRL()
{
	struct hdr_mac802_11 *mh;
	double timeout;

	if(pktCTRL_ == 0)
		return -1;
	if(tx_state_ == MAC_CTS || tx_state_ == MAC_ACK)
		return -1;

	mh = HDR_MAC802_11(pktCTRL_);
							  
	switch(mh->dh_fc.fc_subtype) {
	/*
	 *  If the medium is not IDLE, don't send the CTS.
	 */
	case MAC_Subtype_CTS:
	{
		if(!is_idle()) { //Hinden terminal
			discard(pktCTRL_, DROP_MAC_BUSY); 
			pktCTRL_ = 0;
			Packet::free(last_rts_frame);
			last_rts_frame = NULL;
			///Fix the bug when the original backoff was stop by comming request
			if(pktRTS_ && !mhBackoff_.busy())
				mhBackoff_.start(cw_, is_idle());
			///End
			return 0;
		}
		assert(last_rts_frame);

		refuse_state rs = refuse(last_rts_frame);
		struct rts_frame *rf = (struct rts_frame*)last_rts_frame->access(hdr_mac::offset_);

		if(rs == CTS) 	//normal condition，continue
			CTS_send++;
		else {
			discard(pktCTRL_, "~~~~");
			pktCTRL_ = 0;
			if(rs == REFUSE) {
				if(!pktTx_ && !pktRTS_) {
					assert(pktPre_);
					pktTx_ = pktPre_;
					RecordStatus(How::incr);
					if(nbtimer.busy())
						nbtimer.stop();
					pktPre_ = NULL;
					struct hdr_mac802_11* dh = HDR_MAC802_11(pktTx_);
					sendRTS(ETHER_ADDR(dh->dh_ra));
					ssrc_++;///To avoid deadlock formed in loop
				}
				if(pktRTS_) {
					if(mhBackoff_.busy())
						mhBackoff_.stop();
					check_pktRTS();
					
				} else if(pktTx_ && tx_state_ != MAC_SEND) {
					if(mhBackoff_.busy())
						mhBackoff_.stop();
					check_pktTx();
				} else {
					assert(mhSend_.busy());
				}
				discard(last_rts_frame, "Congested");
				last_rts_frame = NULL;
				return 0;
			} else { ///Avoid deadlock
				assert(rs == CTS_C);
				sendCTS (ETHER_ADDR(rf->rf_ta), rf->rf_duration, true);
				Neighbour* nb = nbs[RECEIVER(pktCTRL_)];
				if(nb->get_helped_time() < 0.0)
					nb->set_helped_by_me(true);
				Packet::free(last_rts_frame);
				last_rts_frame = NULL;
				CTSC_send++;
			}
		}
		mh = HDR_MAC802_11(pktCTRL_);
		if(MAC_Subtype_CTS == mh->dh_fc.fc_subtype) {
			setTxState(MAC_CTS);
			/*
			* timeout:  cts + data tx time calculated by
			*           adding cts tx time to the cts duration
			*           minus ack tx time -- this timeout is
			*           a guess since it is unspecified
			*           (note: mh->dh_duration == cf->cf_duration)
			*/		
			timeout = txtime(phymib_.getCTSlen(), basicRate_)
				+ DSSS_MaxPropagationDelay                      // XXX
				+ sec(mh->dh_duration)
				+ DSSS_MaxPropagationDelay                      // XXX
			      - phymib_.getSIFS()
			      - txtime(phymib_.getACKlen(), basicRate_);
		}

		if (last_rts_frame != nullptr)
		{
			Packet::free(last_rts_frame);
			last_rts_frame = nullptr;
		}
		break;
	}
		/*
		 * IEEE 802.11 specs, section 9.2.8
		 * Acknowledments are sent after an SIFS, without regard to
		 * the busy/idle state of the medium.
		 */
	case MAC_Subtype_ACK:		
		setTxState(MAC_ACK);
		timeout = txtime(phymib_.getACKlen(), basicRate_);
#ifdef SEMITCP
		ACK_send++;
#endif
		break;
	default:
	    
	    fprintf(stderr, "check_pktCTRL:Invalid MAC Control subtype\n");
		exit(1);
	}
	transmit(pktCTRL_, timeout);
	return 0;
}

int
Mac802_11::check_pktRTS()
{
#ifdef SEMITCP
	if(pktRTS_ && pktPre_)
		assert(HDR_CMN(pktTx_)->control_packet());
#endif
	
	struct hdr_mac802_11 *mh;
	double timeout;

	assert(mhBackoff_.busy() == 0);

	if(pktRTS_ == nullptr)
 		return -1;
	mh = HDR_MAC802_11(pktRTS_);

 	switch(mh->dh_fc.fc_subtype) {
	case MAC_Subtype_RTS:
	#ifdef SEMITCP
	case MAC_Subtype_uRTS:
	#endif
	{
		if(! is_idle()) {	//竞争信道失败
			inc_cw();
			mhBackoff_.start(cw_, is_idle());
			return 0;
		}
		setTxState(MAC_RTS); 
		timeout = txtime(phymib_.getRTSlen(), basicRate_)
			+ DSSS_MaxPropagationDelay                      // XXX
			+ phymib_.getSIFS()
		#ifdef SEMITCP
			+ txtime(phymib_.getRTSlen(), basicRate_) 	//？
		#else
			+ txtime(phymib_.getCTSlen(), basicRate_)
		#endif
			+ DSSS_MaxPropagationDelay;
		break;
	}
	default:
		fprintf(stderr, "check_pktRTS:Invalid MAC Control subtype\n");
		exit(1);
	}
#ifdef SEMITCP
	mh->dh_fc.fc_order = false;///RTS
	if(TotalCongested())
		mh->dh_fc.fc_order = true;///RTSC

	RTS_send++;
#endif
	transmit(pktRTS_, timeout);
	return 0;
}

int
Mac802_11::check_pktTx()
{
	struct hdr_mac802_11 *mh;
	double timeout;
	
	assert(mhBackoff_.busy() == 0);

	if(pktTx_ == nullptr)
		return -1;

	mh = HDR_MAC802_11(pktTx_);

	switch(mh->dh_fc.fc_subtype) {
	case MAC_Subtype_Data:
		if(! is_idle()) {
			sendRTS(ETHER_ADDR(mh->dh_ra));
			inc_cw();	//也要增加窗口？
			mhBackoff_.start(cw_, is_idle());
			#ifdef SEMITCP
			if(pktRTS_ && !HDR_CMN(pktTx_)->control_packet()) {
				Neighbour *nb = nbs[RECEIVER(pktRTS_)];
				if(nb->get_helped_time() > 0.0) {
					nb->set_helped_time(-1.0);
				}
			}
			#endif
			return 0;
		}
		setTxState(MAC_SEND);
		if((u_int32_t)ETHER_ADDR(mh->dh_ra) != MAC_BROADCAST)
                        timeout = txtime(pktTx_)
                                + DSSS_MaxPropagationDelay              // XXX
                               + phymib_.getSIFS()
                               + txtime(phymib_.getACKlen(), basicRate_)
                               + DSSS_MaxPropagationDelay;             // XXX
		else
			timeout = txtime(pktTx_);
		break;
	default:
		fprintf(stderr, "check_pktTx:Invalid MAC Control subtype\n");
		assert(0); ///SEMITCP DEBUG
		exit(1);
	}
#ifdef SEMITCP
	DATA_send++;
	if (HDR_CMN(pktTx_)->ptype() == PT_TCP)
	{
		forward_data_send++;
	}
	else if (HDR_CMN(pktTx_)->ptype() == PT_ACK)
	{
		backward_ack_send++;
	}
#endif
	transmit(pktTx_, timeout);
	return 0;
}
/*
 * Low-level transmit functions that actually place the packet onto
 * the channel.
 */
void
Mac802_11::sendRTS(int dst)
{
	Packet *p = Packet::alloc();
	hdr_cmn* ch = HDR_CMN(p);
	struct rts_frame *rf = (struct rts_frame*)p->access(hdr_mac::offset_);
	
	assert(pktTx_);
	if (HDR_CMN(pktTx_)->ptype() == PT_TCP && HDR_CMN(pktTx_)->size() > 300)
	{
		sendingDataSeqno_ = HDR_TCP(pktTx_)->seqno();
		receiveTime_ = Scheduler::instance().clock();
	}
	
	assert(pktRTS_ == 0);

	/*
	 *  If the size of the packet is larger than the
	 *  RTSThreshold, then perform the RTS/CTS exchange.
	 */

	if( (u_int32_t) HDR_CMN(pktTx_)->size() < macmib_.getRTSThreshold() ||
            (u_int32_t) dst == MAC_BROADCAST) {
		Packet::free(p);    //put this section in the front of this function is better
		return;
	}

	ch->uid() = 0;
	ch->ptype() = PT_MAC;
	ch->size() = phymib_.getRTSlen();
	ch->iface() = -2;
	ch->error() = 0;

	bzero(rf, MAC_HDR_LEN);

	rf->rf_fc.fc_protocol_version = MAC_ProtocolVersion;
 	rf->rf_fc.fc_type	= MAC_Type_Control;
	#ifdef SEMITCP
	assert(pktTx_);
	rf->rf_fc.fc_subtype	= HDR_CMN(pktTx_)->control_packet() ? MAC_Subtype_uRTS : MAC_Subtype_RTS;
	#else
	rf->rf_fc.fc_subtype	= MAC_Subtype_RTS;
	#endif
 	rf->rf_fc.fc_to_ds	= 0;
 	rf->rf_fc.fc_from_ds	= 0;
 	rf->rf_fc.fc_more_frag	= 0;
 	rf->rf_fc.fc_retry	= 0;
 	rf->rf_fc.fc_pwr_mgt	= 0;
 	rf->rf_fc.fc_more_data	= 0;
 	rf->rf_fc.fc_wep	= 0;
 	rf->rf_fc.fc_order	= 0;

	//rf->rf_duration = RTS_DURATION(pktTx_);
	STORE4BYTE(&dst, (rf->rf_ra));
	
	/* store rts tx time */
 	ch->txtime() = txtime(ch->size(), basicRate_); //not include the size of common
	
	STORE4BYTE(&index_, (rf->rf_ta));

	/* calculate rts duration field */	
	rf->rf_duration = usec(phymib_.getSIFS()
			       + txtime(phymib_.getCTSlen(), basicRate_)
			       + phymib_.getSIFS()
                               + txtime(pktTx_)
			       + phymib_.getSIFS()
			       + txtime(phymib_.getACKlen(), basicRate_));
	pktRTS_ = p;
	#ifdef SEMITCP // DEBUG
	if(pktPre_)
		assert(HDR_CMN(pktTx_)->control_packet());
	#endif
}
#ifdef SEMITCP
void Mac802_11::sendCTS(int dst, double rts_duration, bool congested)
#else
void
Mac802_11::sendCTS(int dst, double rts_duration)
#endif
{
	Packet *p = Packet::alloc();
	hdr_cmn* ch = HDR_CMN(p);
	struct cts_frame *cf = (struct cts_frame*)p->access(hdr_mac::offset_);

	assert(pktCTRL_ == 0);

	ch->uid() = 0;
	ch->ptype() = PT_MAC;
	ch->size() = phymib_.getCTSlen();


	ch->iface() = -2;
	ch->error() = 0;
	//ch->direction() = hdr_cmn::DOWN;
	bzero(cf, MAC_HDR_LEN);

	cf->cf_fc.fc_protocol_version = MAC_ProtocolVersion;
	cf->cf_fc.fc_type	= MAC_Type_Control;
	cf->cf_fc.fc_subtype	= MAC_Subtype_CTS;
 	cf->cf_fc.fc_to_ds	= 0;
 	cf->cf_fc.fc_from_ds	= 0;
 	cf->cf_fc.fc_more_frag	= 0;
 	cf->cf_fc.fc_retry	= 0;
 	cf->cf_fc.fc_pwr_mgt	= 0;
 	cf->cf_fc.fc_more_data	= 0;
 	cf->cf_fc.fc_wep	= 0;
#ifdef SEMITCP
	cf->cf_fc.fc_order	= congested;
#else
	cf->cf_fc.fc_order	= 0;
#endif	
	//cf->cf_duration = CTS_DURATION(rts_duration);
	STORE4BYTE(&dst, (cf->cf_ra));
	
	/* store cts tx time */
	ch->txtime() = txtime(ch->size(), basicRate_);
	
	/* calculate cts duration */
	cf->cf_duration = usec(sec(rts_duration)
                              - phymib_.getSIFS()
                              - txtime(phymib_.getCTSlen(), basicRate_));
	
	pktCTRL_ = p;
}

void
Mac802_11::sendACK(int dst)
{
	Packet *p = Packet::alloc();
	hdr_cmn* ch = HDR_CMN(p);
	struct ack_frame *af = (struct ack_frame*)p->access(hdr_mac::offset_);

	assert(pktCTRL_ == 0);

	ch->uid() = 0;
	ch->ptype() = PT_MAC;
	// CHANGE WRT Mike's code
	ch->size() = phymib_.getACKlen();
	ch->iface() = -2;
	ch->error() = 0;
	
	bzero(af, MAC_HDR_LEN);

	af->af_fc.fc_protocol_version = MAC_ProtocolVersion;
 	af->af_fc.fc_type	= MAC_Type_Control;
 	af->af_fc.fc_subtype	= MAC_Subtype_ACK;
 	af->af_fc.fc_to_ds	= 0;
 	af->af_fc.fc_from_ds	= 0;
 	af->af_fc.fc_more_frag	= 0;
 	af->af_fc.fc_retry	= 0;
 	af->af_fc.fc_pwr_mgt	= 0;
 	af->af_fc.fc_more_data	= 0;
 	af->af_fc.fc_wep	= 0;
 	af->af_fc.fc_order	= 0;

	//af->af_duration = ACK_DURATION();
	STORE4BYTE(&dst, (af->af_ra));

	/* store ack tx time */
 	ch->txtime() = txtime(ch->size(), basicRate_);
	
	/* calculate ack duration */
 	af->af_duration = 0;	
	
	pktCTRL_ = p;
}

void
Mac802_11::sendDATA(Packet *p)
{
	hdr_cmn* ch = HDR_CMN(p);
	struct hdr_mac802_11* dh = HDR_MAC802_11(p);

	assert(pktTx_ == 0);

	/*
	 * Update the MAC header
	 */
	ch->size() += phymib_.getHdrLen11();

	dh->dh_fc.fc_protocol_version = MAC_ProtocolVersion;
	dh->dh_fc.fc_type       = MAC_Type_Data;
	dh->dh_fc.fc_subtype    = MAC_Subtype_Data;
	
	dh->dh_fc.fc_to_ds      = 0;
	dh->dh_fc.fc_from_ds    = 0;
	dh->dh_fc.fc_more_frag  = 0;
	dh->dh_fc.fc_retry      = 0;
	dh->dh_fc.fc_pwr_mgt    = 0;
	dh->dh_fc.fc_more_data  = 0;
	dh->dh_fc.fc_wep        = 0;
	dh->dh_fc.fc_order      = 0;

	/* store data tx time */
 	ch->txtime() = txtime(ch->size(), dataRate_);

	if((u_int32_t)ETHER_ADDR(dh->dh_ra) != MAC_BROADCAST) {
		/* store data tx time for unicast packets */
		ch->txtime() = txtime(ch->size(), dataRate_);
		
		dh->dh_duration = usec(txtime(phymib_.getACKlen(), basicRate_)
				       + phymib_.getSIFS());



	} else {
		/* store data tx time for broadcast packets (see 9.6) */
		ch->txtime() = txtime(ch->size(), basicRate_);
		
		dh->dh_duration = 0;
	}
	pktTx_ = p;
	RecordStatus(How::incr);
}

/* ======================================================================
   Retransmission Routines
   ====================================================================== */
void
Mac802_11::RetransmitRTS()
{
	assert(pktTx_);
	assert(pktRTS_);
	assert(mhBackoff_.busy() == 0);
	macmib_.RTSFailureCount++;

	ssrc_ += 1;			// STA Short Retry Count
		
	if(ssrc_ >= macmib_.getShortRetryLimit()) {
		RTS_drop++;
		discard(pktRTS_, DROP_MAC_RETRY_COUNT_EXCEEDED);
		pktRTS_ = 0;
		/* tell the callback the send operation failed 
		   before discarding the packet */
		hdr_cmn *ch = HDR_CMN(pktTx_);
#ifdef SEMITCP 
		if(ch->xmit_failure_) {
		      /*
			*  Need to remove the MAC header so that 
			*  re-cycled packets don't keep getting
			*  bigger.
			*/
			if(CALLRT) {    //call the router layer
				ch->size() -= phymib_.getHdrLen11();
				ch->xmit_reason_ = XMIT_REASON_RTS;
				ch->xmit_failure_(pktTx_->copy(),
						  ch->xmit_failure_data_);
			}
		}
		discard(pktTx_, DROP_MAC_RETRY_COUNT_EXCEEDED); 
		pktTx_ = 0;
		RecordStatus(How::decr);
		
		rst_cw();
		ssrc_ = 0;
#else
		if (ch->xmit_failure_ && CALLRT) {
                       /*
                         *  Need to remove the MAC header so that 
                         *  re-cycled packets don't keep getting
                         *  bigger.
                         */
			ch->size() -= phymib_.getHdrLen11();
                        ch->xmit_reason_ = XMIT_REASON_RTS;
                        ch->xmit_failure_(pktTx_->copy(),
                                          ch->xmit_failure_data_);
                }
		discard(pktTx_, DROP_MAC_RETRY_COUNT_EXCEEDED); 
		pktTx_ = 0;
		ssrc_ = 0;
		rst_cw();
#endif
	} else {
		struct rts_frame *rf;
		rf = (struct rts_frame*)pktRTS_->access(hdr_mac::offset_);
		rf->rf_fc.fc_retry = 1;
		inc_cw();
		mhBackoff_.start(cw_, is_idle());
	}
}

void
Mac802_11::RetransmitDATA()
{
	struct hdr_cmn *ch;
	struct hdr_mac802_11 *mh;
	u_int32_t *rcount, thresh;
	assert(mhBackoff_.busy() == 0);

	assert(pktTx_);
	assert(pktRTS_ == 0);   //RTS was successfully transmited or no RTS

	ch = HDR_CMN(pktTx_);
	mh = HDR_MAC802_11(pktTx_);

	/*static int AODVCount = 0;
	if (ch->ptype() == PT_AODV)
	{
		if (AODVCount < 2) //retry 2 times
		{
			struct hdr_mac802_11 *dh;
			dh = HDR_MAC802_11(pktTx_);
			dh->dh_fc.fc_retry = 1;
			AODVCount++;
			rst_cw();
			mhBackoff_.start(cw_, is_idle());
		}
		else
		{
			Packet::free(pktTx_);
			pktTx_ = nullptr;
			AODVCount = 0;
			rst_cw();
			mhBackoff_.start(cw_, is_idle());
		}
		
		return;
	}*/
	
	/*
	 *  Broadcast packets don't get ACKed and therefore
	 *  are never retransmitted.
	 */
	if((u_int32_t)ETHER_ADDR(mh->dh_ra) == MAC_BROADCAST) {
		Packet::free(pktTx_); 
		pktTx_ = 0;
		RecordStatus(How::decr);
		/*
		 * Backoff at end of TX.
		 */
		rst_cw();
		mhBackoff_.start(cw_, is_idle());

		return;
	}
	macmib_.ACKFailureCount++;
	
	if (ch->ptype() == PT_TCP)
	{
		forward_data_retransmit++;
	}
	else
	{
		backward_ack_retransmit++;
	}

	if((u_int32_t) ch->size() <= macmib_.getRTSThreshold()) {
                rcount = &ssrc_; //SSRL包括DATA的重传次数
               thresh = macmib_.getShortRetryLimit();
        } else {
                rcount = &slrc_;
               thresh = macmib_.getLongRetryLimit();
        }

	(*rcount)++;

	if(*rcount >= thresh) {
		/* IEEE Spec section 9.2.3.5 says this should be greater than
		   or equal */
		macmib_.FailedCount++;	//丢包
		//avg_length += 1;
		/* tell the callback the send operation failed 
		   before discarding the packet */
		hdr_cmn *ch = HDR_CMN(pktTx_);
		if (ch->ptype() == PT_TCP)
		{
			forward_data_drop++;
		}
		else if (ch->ptype() == PT_ACK)
		{
			backward_ack_drop++;
		}
		
		if (ch->xmit_failure_) {
		if(CALLRT) {
                        ch->size() -= phymib_.getHdrLen11();
			ch->xmit_reason_ = XMIT_REASON_ACK;
                        ch->xmit_failure_(pktTx_->copy(),
                                          ch->xmit_failure_data_);
		}
                }
		discard(pktTx_, DROP_MAC_RETRY_COUNT_EXCEEDED); 
		pktTx_ = 0;
		RecordStatus(How::decr);
		*rcount = 0;
		rst_cw();
	}
	else {
		struct hdr_mac802_11 *dh;
		dh = HDR_MAC802_11(pktTx_);
		dh->dh_fc.fc_retry = 1;


		sendRTS(ETHER_ADDR(mh->dh_ra));
		inc_cw();
		mhBackoff_.start(cw_, is_idle());
	}
	#ifdef SEMITCP
	if(pktRTS_) { 	//数据包传输不成功，当然没有帮助到别人了
		Neighbour *nb = nbs[RECEIVER(pktRTS_)];
		if(nb->get_helped_time() > 0.0)
			nb->set_helped_time(-1.0);
	}
	#endif
}

/* ======================================================================
   Incoming Packet Routines
   ====================================================================== */
void
Mac802_11::send(Packet *p, Handler *h)
{
	double rTime;
	struct hdr_mac802_11* dh = HDR_MAC802_11(p);

	EnergyModel *em = netif_->node()->energy_model();
	if (em && em->sleep()) {
		em->set_node_sleep(0);
		em->set_node_state(EnergyModel::INROUTE);
	}
	
	callback_ = h;
	
	sendDATA(p);
	sendRTS(ETHER_ADDR(dh->dh_ra));

	/*
	 * Assign the data packet a sequence number.
	 */
	dh->dh_scontrol = sta_seqno_++;
	
	#ifdef SEMITCP
	if(pktRTS_ && pktPre_)
		assert(HDR_CMN(pktTx_)->control_packet());

	if(pktRTS_ && !HDR_CMN(pktTx_)->control_packet()) {
		Neighbour* nb = nbs[RECEIVER(pktTx_)];
		if(defer_rts(nb)) {	//推迟发送
			assert(!nbtimer.busy());
			assert(!pktPre_);
			store_tx();	 //将要发送的数据包储存起来
			nbtimer.start(round_trip_time);
			if(!pktCTRL_) {
				assert(!mhSend_.busy());
				tx_resume(); //如果store不把数据包储存起来，则在这个函数又会发送RTS
			}
			return;
		}
	}
	#endif
	/*
	 *  If the medium is IDLE, we must wait for a DIFS
	 *  Space before transmitting.
	 */
	if(mhBackoff_.busy() == 0) {
		if (HDR_CMN(p)->ptype() == PT_AODV)
			rst_cw();
		
		if(is_idle()) {
			if (mhDefer_.busy() == 0) {
				/*
				 * If we are already deferring, there is no
				 * need to reset the Defer timer.
				 */

				rTime = (Random::random() % cw_)
					* (phymib_.getSlotTime());
				mhDefer_.start(phymib_.getDIFS() + rTime);
			}
		} else {
			/*
			 * If the medium is NOT IDLE, then we start
			 * the backoff timer.
			 */
			mhBackoff_.start(cw_, is_idle());
		}
	}
}

void
Mac802_11::recv(Packet *p, Handler *h)
{    
	struct hdr_cmn *hdr = HDR_CMN(p);
	/*
	 * Sanity Check
	 */
	assert(initialized());

	/*
	 *  Handle outgoing packets.
	 */
	if(hdr->direction() == hdr_cmn::DOWN) {
                send(p, h);
                return;
        }
	/*
	 *  Handle incoming packets.
	 *
	 *  We just received the 1st bit of a packet on the network
	 *  interface.
	 *
	 */

	/*
	 *  If the interface is currently in transmit mode, then
	 *  it probably won't even see this packet.  However, the
	 *  "air" around me is BUSY so I need to let the packet
	 *  proceed.  Just set the error flag in the common header
	 *  to that the packet gets thrown away.
	 */
	if(tx_active_ && hdr->error() == 0) {
		hdr->error() = 1;
	}

	if(rx_state_ == MAC_IDLE) {
		setRxState(MAC_RECV);
		pktRx_ = p;
		/*
		 * Schedule the reception of this packet, in
		 * txtime seconds.
		 */
		mhRecv_.start(txtime(p));
	} else {
		/*
		 *  If the power of the incoming packet is smaller than the
		 *  power of the packet currently being received by at least
                 *  the capture threshold, then we ignore the new packet.
		 */
		if(pktRx_->txinfo_.RxPr / p->txinfo_.RxPr >= p->txinfo_.CPThresh) {
			capture(p);
		} else {
			collision(p);
		}
	}
}

void
Mac802_11::recv_timer()
{
	u_int32_t src; 
	hdr_cmn *ch = HDR_CMN(pktRx_);
	hdr_mac802_11 *mh = HDR_MAC802_11(pktRx_);
	u_int32_t dst = ETHER_ADDR(mh->dh_ra);
	
	u_int8_t  type = mh->dh_fc.fc_type;
	u_int8_t  subtype = mh->dh_fc.fc_subtype;

	assert(pktRx_);
	assert(rx_state_ == MAC_RECV || rx_state_ == MAC_COLL);
	
        /*
         *  If the interface is in TRANSMIT mode when this packet
         *  "arrives", then I would never have seen it and should
         *  do a silent discard without adjusting the NAV.
         */
        if(tx_active_) {
                Packet::free(pktRx_);
                goto done;
        }

	/*
	 * Handle collisions.
	 */
	if(rx_state_ == MAC_COLL) {
		discard(pktRx_, DROP_MAC_COLLISION);		
		set_nav(usec(phymib_.getEIFS()));
		goto done;
	}

	/*
	 * Check to see if this packet was received with enough
	 * bit errors that the current level of FEC still could not
	 * fix all of the problems - ie; after FEC, the checksum still
	 * failed.
	 */
	if( ch->error() ) {
		Packet::free(pktRx_);
		set_nav(usec(phymib_.getEIFS()));
		goto done;
	}

	/*
	 * IEEE 802.11 specs, section 9.2.5.6
	 *	- update the NAV (Network Allocation Vector)
	 */
	if(dst != (u_int32_t)index_) { 	//不是发给自己的包，设置nav
		set_nav(mh->dh_duration);
	}
	#ifdef SEMITCP
	overHear( pktRx_ ); 	//对接收到的包进行统计记录
	#endif

        /* tap out - */
        if (tap_ && type == MAC_Type_Data &&
            MAC_Subtype_Data == subtype ) 
		tap_->tap(pktRx_);
	/*
	 * Adaptive Fidelity Algorithm Support - neighborhood infomation 
	 * collection
	 *
	 * Hacking: Before filter the packet, log the neighbor node
	 * I can hear the packet, the src is my neighbor
	 */
	if (netif_->node()->energy_model() && 
	    netif_->node()->energy_model()->adaptivefidelity()) {
		src = ETHER_ADDR(mh->dh_ta);
		netif_->node()->energy_model()->add_neighbor(src);
	}
	/*
	 * Address Filtering
	 */
	if(dst != (u_int32_t)index_ && dst != MAC_BROADCAST) {
		/*
		 *  We don't want to log this event, so we just free
		 *  the packet instead of calling the drop routine.
		 */
		discard(pktRx_, "---");
		goto done;
	}

	switch(type) {

	case MAC_Type_Management:
		discard(pktRx_, DROP_MAC_PACKET_ERROR);
		goto done;
	case MAC_Type_Control:
		switch(subtype) {
		case MAC_Subtype_RTS:
		#ifdef SEMITCP
		case MAC_Subtype_uRTS:
		#endif
			recvRTS(pktRx_);
			break;
		case MAC_Subtype_CTS:
			recvCTS(pktRx_);
			break;
		case MAC_Subtype_ACK:
			recvACK(pktRx_);
			break;
		default:
			fprintf(stderr,"recvTimer1:Invalid MAC Control Subtype %x\n",
				subtype);
			exit(1);
		}
		break;
	case MAC_Type_Data:
		switch(subtype) {
		case MAC_Subtype_Data:
			recvDATA(pktRx_);
			break;
		default:
			fprintf(stderr, "recv_timer2:Invalid MAC Data Subtype %x\n",
				subtype);
			exit(1);
		}
		break;
	default:
		fprintf(stderr, "recv_timer3:Invalid MAC Type %x\n", subtype);
		exit(1);
	}
 done:
	pktRx_ = 0;
	rx_resume();
}


void
Mac802_11::recvRTS(Packet *p)
{
	struct rts_frame *rf = (struct rts_frame*)p->access(hdr_mac::offset_);

	if(tx_state_ != MAC_IDLE) {
		discard(p, DROP_MAC_BUSY);
		return;
	}

	/*
	 *  If I'm responding to someone else, discard this RTS.
	 */
	if(pktCTRL_) {
		discard(p, DROP_MAC_BUSY);
		return;
	}
	#ifdef SEMITCP
	last_rts_frame = p->copy();
	#endif
	
	sendCTS (ETHER_ADDR(rf->rf_ta), rf->rf_duration);
	/*
	 *  Stop deferring - will be reset in tx_resume().
	 */
	if(mhDefer_.busy()) mhDefer_.stop();
#ifdef SEMITCP
	RTS_recv++;
#endif
	tx_resume();
	mac_log(p);
}

/*
 * txtime()	- pluck the precomputed tx time from the packet header
 */
double
Mac802_11::txtime(Packet *p)
{
	struct hdr_cmn *ch = HDR_CMN(p);
	double t = ch->txtime();
	if (t < 0.0) {
		drop(p, "XXX");
 		exit(1);
	}
	return t;
}

 
/*
 * txtime()	- calculate tx time for packet of size "psz" bytes 
 *		  at rate "drt" bps
 */
double
Mac802_11::txtime(double psz, double drt)
{
	double dsz = psz - phymib_.getPLCPhdrLen();
        int plcp_hdr = phymib_.getPLCPhdrLen() << 3;	
	int datalen = (int)dsz << 3;
	double t = (((double)plcp_hdr)/phymib_.getPLCPDataRate())
                                       + (((double)datalen)/drt);
	return(t);
}

void
Mac802_11::recvCTS(Packet *p)
{
	if(tx_state_ != MAC_RTS) {
		discard(p, DROP_MAC_INVALID_STATE);
		return;
	}

#ifdef SEMITCP

	if (nbs.find( RECEIVER(pktRTS_) ) == nbs.end()) {
		nbs[RECEIVER(pktRTS_)] = new Neighbour(SENDER(p));
	}
	Neighbour *nb = nbs[RECEIVER(pktRTS_)];
	
	struct cts_frame *cf = (struct cts_frame*)p->access(hdr_mac::offset_);
	
	if(cf->cf_fc.fc_order && nb->get_helped_time() > 0.0) {
		assert(0);
	}
	///SEP
	if(cf->cf_fc.fc_order)
	{
	    nb->set_helped_by_me(false);
	    CTSC_recv++;
	}
	else
	    CTS_recv++;
	///End SEP
	
#endif
	assert(pktRTS_);
	Packet::free(pktRTS_); 
	pktRTS_ = nullptr;
	assert(pktTx_);	

	mhSend_.stop();

	/*
	 * The successful reception of this CTS packet implies
	 * that our RTS was successful. 
	 * According to the IEEE spec 9.2.5.3, you must 
	 * reset the ssrc_, but not the congestion window, which is reset when data successfully send
	 */
	ssrc_ = 0;
	tx_resume();

	mac_log(p);
}

void
Mac802_11::recvDATA(Packet *p)
{
	struct hdr_mac802_11 *dh = HDR_MAC802_11(p);
	u_int32_t dst, src, size;
	struct hdr_cmn *ch = HDR_CMN(p);

	dst = ETHER_ADDR(dh->dh_ra);
	src = ETHER_ADDR(dh->dh_ta);
	size = ch->size();
	/*
	 * Adjust the MAC packet size - ie; strip
	 * off the mac header
	 */
	ch->size() -= phymib_.getHdrLen11();
	ch->num_forwards() += 1;

	/*
	 *  If we sent a CTS, clean up...
	 */
	if(dst != MAC_BROADCAST) {
		if(size >= macmib_.getRTSThreshold()) {
			if (tx_state_ == MAC_CTS) { //correct situation
				assert(pktCTRL_);
				Packet::free(pktCTRL_); pktCTRL_ = 0;
				mhSend_.stop();
				/*
				 * Our CTS got through.
				 */
			} else {    //incorrect situation
				discard(p, DROP_MAC_BUSY);
				return;
			}
#ifdef SEMITCP
			DATA_recv++;
#endif
			sendACK(src);
			tx_resume();
		} else {
			/*
			 *  We did not send a CTS and there's no
			 *  room to buffer an ACK.
			 */
			if(pktCTRL_) {  //no need to send CTS, but it did
				discard(p, DROP_MAC_BUSY);
				return;
			}
#ifdef SEMITCP
			DATA_recv++;
#endif
			sendACK(src);
			if(mhSend_.busy() == 0)
				tx_resume();
		}
	}
	
	/* ============================================================
	   Make/update an entry in our sequence number cache.
	   ============================================================ */

	/* Changed by Debojyoti Dutta. This upper loop of if{}else was 
	   suggested by Joerg Diederich <dieder@ibr.cs.tu-bs.de>. 
	   Changed on 19th Oct'2000 */

        if(dst != MAC_BROADCAST) {
                if (src < (u_int32_t) cache_node_count_) {
                        Host *h = &cache_[src];

                        if(h->seqno && h->seqno == dh->dh_scontrol) {
                                discard(p, DROP_MAC_DUPLICATE);
                                return;
                        }
                        h->seqno = dh->dh_scontrol;
                } else {
			static int count = 0;
			if (++count <= 10) {
				printf ("MAC_802_11: accessing MAC cache_ array out of range (src %u, dst %u, size %d)!\n", src, dst, cache_node_count_);
				if (count == 10)
					printf ("[suppressing additional MAC cache_ warnings]\n");
			};
		};
	}

	/*
	 *  Pass the packet up to the link-layer.
	 *  XXX - we could schedule an event to account
	 *  for this processing delay.
	 */
	
	/* in BSS mode, if a station receives a packet via
	 * the AP, and higher layers are interested in looking
	 * at the src address, we might need to put it at
	 * the right place - lest the higher layers end up
	 * believing the AP address to be the src addr! a quick
	 * grep didn't turn up any higher layers interested in
	 * the src addr though!
	 * anyway, here if I'm the AP and the destination
	 * address (in dh_3a) isn't me, then we have to fwd
	 * the packet; we pick the real destination and set
	 * set it up for the LL; we save the real src into
	 * the dh_3a field for the 'interested in the info'
	 * receiver; we finally push the packet towards the
	 * LL to be added back to my queue - accomplish this
	 * by reversing the direction!*/

	if ((bss_id() == addr()) && ((u_int32_t)ETHER_ADDR(dh->dh_ra)!= MAC_BROADCAST)&& ((u_int32_t)ETHER_ADDR(dh->dh_3a) != ((u_int32_t)addr()))) {
		struct hdr_cmn *ch = HDR_CMN(p);
		u_int32_t dst = ETHER_ADDR(dh->dh_3a);
		u_int32_t src = ETHER_ADDR(dh->dh_ta);
		/* if it is a broadcast pkt then send a copy up
		 * my stack also
		 */
		if (dst == MAC_BROADCAST) {
			uptarget_->recv(p->copy(), (Handler*) 0);
		}

		ch->next_hop() = dst;
		STORE4BYTE(&src, (dh->dh_3a));
		ch->addr_type() = NS_AF_ILINK;
		ch->direction() = hdr_cmn::DOWN;
	}

	uptarget_->recv(p, (Handler*) 0);
}


void
Mac802_11::recvACK(Packet *p)
{
	if(tx_state_ != MAC_SEND) {
		discard(p, DROP_MAC_INVALID_STATE);
		return;
	}
	assert(pktTx_);

#ifdef SEMITCP
	const double now = Scheduler::instance().clock();

	
	if ( nbs.find( RECEIVER(pktTx_) ) == nbs.end() ) {
		nbs[ RECEIVER(pktTx_) ] = new Neighbour (SENDER(p));
	}

	Neighbour *nb = nbs[RECEIVER(pktTx_)];

	if(nb->get_helped_by_me()) {
		nb->set_helped_by_me(false);
	}
	if(nb->get_helped_time() > 0.0) {
		nb->set_helped_time(now);
		nb_congested = now;
	}
#endif

	mhSend_.stop();

	/*
	 * The successful reception of this ACK packet implies
	 * that our DATA transmission was successful.  Hence,
	 * we can reset the Short/Long Retry Count and the CW.
	 *
	 * need to check the size of the packet we sent that's being
	 * ACK'd, not the size of the ACK packet.
	 */
	
	if((u_int32_t) HDR_CMN(pktTx_)->size() <= macmib_.getRTSThreshold())
	{
		ssrc_ = 0;
	}
	else
	{
		slrc_ = 0;
	}
	
	if (HDR_CMN(pktTx_)->ptype() == PT_TCP && HDR_CMN(pktTx_)->size() > 300)
	{
		if (sendingDataSeqno_ == HDR_TCP(pktTx_)->seqno())
		{
			double now = Scheduler::instance().clock();
			double interval = now - receiveTime_;
		
			maxSendTime_ = std::max(maxSendTime_, interval);
			minSendTime_ = std::min(minSendTime_, interval);
		
			if (avgSendTime_ < 0.0001) 	// first time
			{
				avgSendTime_ = interval;
			}
			else
			{
				avgSendTime_ = avgSendTime_ * 0.875 + interval * 0.125;
				double now = Scheduler::instance().clock();
				send_time_vec.push_back(std::make_pair(now, avgSendTime_));
			}
			totalTime_ += interval;
			++totalCount_;
		}
	}
	
	rst_cw();
	Packet::free(pktTx_); 
	pktTx_ = nullptr;
	RecordStatus(How::decr);
#ifdef SEMITCP
	ACK_recv++;
#endif
	/*
	 * Backoff before sending again.
	 */
	assert(mhBackoff_.busy() == 0);
	mhBackoff_.start(cw_, is_idle());
	tx_resume();
	mac_log(p);
}

#ifdef SEMITCP
//NOTE:use for inter-node congestion control. if is true, send RTSC or CTSC
//this function count the number of packets in a node, but just count the packets
//receive from from other node for absolutely seperate the function of Tc and m

bool Mac802_11::neighbor_congested()
{	
	int pktCount = p_to_prique->length() + p_aodv_agent->length();
	return pktCount >= p_to_prique->congestionThreshold();
}

bool Mac802_11::local_congested()
{
	return TotalCongested() || !is_idle();
}
bool Mac802_11::TotalCongested() const
{
	int pktCount = p_to_prique->DataLength() + p_aodv_agent->DataLength();
	if (pktTx_ != nullptr && !HDR_CMN(pktTx_)->control_packet())
	{
		pktCount++;
	}
	return pktCount >= 1;
}

void Mac802_11::overHear( Packet* p )
{
	hdr_mac802_11 *mh = HDR_MAC802_11 ( p );
	u_int8_t  type = mh->dh_fc.fc_type;
	u_int8_t  subtype = mh->dh_fc.fc_subtype;
	const double now = Scheduler::instance().clock();
	
	if(type == MAC_Type_Control && subtype == MAC_Subtype_CTS) {
		struct cts_frame *cf = (struct cts_frame*)p->access(hdr_mac::offset_);
		if(cf->cf_fc.fc_order) {
			nb_congested = now;     //it's unit is time
			kk = 0;
		}
		return; 	//对接收到的CTS不作进一步的处理
	}

	if(type == MAC_Type_Control && subtype == MAC_Subtype_ACK)
		return;//对接收到的CTS不作进一步的处理

	assert(SENDER(p) != index_);
    
	//注册新邻居
	if(nbs.find(SENDER(p)) == nbs.end()) {
		nbs[SENDER(p)] = new Neighbour (SENDER(p));
	}
	
	if(type == MAC_Type_Data && subtype == MAC_Subtype_Data) {
		if(nb_congested > 0.0)
			kk++;   //kk 代表了邻居节点发送的数据包数
		if(pktPre_ && !pktTx_) {
			if(kk >= KK) {
				assert(nbtimer.busy());
				nbtimer.stop();
				restore_tx();
			}
		}
	}
	
	if((type == MAC_Type_Control && subtype == MAC_Subtype_RTS && mh->dh_fc.fc_order)
	  || (type == MAC_Type_Control && subtype == MAC_Subtype_uRTS)){ ///RTSC or uRTS
		nb_congested = now;
		kk = 0;
		//刚刚发送的RTS没有收到CTS，而现在对方又发送RTSC过来，说明刚才的RTS因为对方
		//节点拥塞被拒绝了，但是RTS是发送成功的（也有可能发送失败--海城）
		if(pktRTS_ && RECEIVER(pktRTS_) == SENDER(p) && tx_state_ == MAC_RTS) { ///This RTSC means refusing
			assert (pktTx_);
			assert (!pktPre_);

			mhSend_.stop();  //停掉了发送计时器，所以就不会重传RTS了
			discard(pktRTS_, "DIY");
			pktRTS_ = nullptr;
			store_tx(); 	//将要发送的数据包保存起来
			nbtimer.start(round_trip_time);
			tx_resume();
			assert(tx_state_ == MAC_IDLE);
		}
	}
}

//NOTE:key function
//check whether defer to send RTS nor not
bool
Mac802_11::defer_rts(Neighbour *nb)
{
    const double now = Scheduler::instance().clock();
	
    if(TotalCongested())	//本节点拥塞了，不推迟发送RTS or RTSC
		return false;
    else if(kk < KK && now - nb_congested < round_trip_time)
		return true;
    else
		return false;
}

// NOTE: key function 
// decide how to react to the received RTS
refuse_state Mac802_11::refuse( Packet* p )
{
	Packet* pkt = pktTx_ ? pktTx_ :(pktPre_ ? pktPre_ : p_to_prique->q_->lookup(0));
	
	bool queue_head_data_to_rts_sender = false;
	
	struct rts_frame *rf = (struct rts_frame*)p->access(hdr_mac::offset_);
	int rts_sender = SENDER(p);
	
	if (rf->rf_fc.fc_subtype == MAC_Subtype_uRTS)///the RTS packet is sent for control packet like
		return CTS;		// NOTE: But actually, the control packets are broadcast, Would not send a RTS
	bool RTSC = rf->rf_fc.fc_order;
	bool me_congested = TotalCongested();
	
	if(pkt) {   //have data packet to send
		if(!HDR_CMN(pkt)->control_packet())
			queue_head_data_to_rts_sender = ((RECEIVER(pkt) == rts_sender));
		else
			queue_head_data_to_rts_sender = false;
	} else { ///we don't count route queue here.--the route queue usually empty
		return CTS;     //no packet to send, of course it's always not congested
	}
	
	if(!me_congested) {
	    return CTS;
	} else {	//me congested
		Neighbour* nb = nbs[rts_sender];
		if(RTSC) {
			if(nb->get_helped_by_me()) {    //avoid monopolization situation
				refuse_other_rts++;
				return REFUSE;
			} else {
				if(queue_head_data_to_rts_sender) ///Deadlock
				{
					dead_lock++;
					return CTS_C;
				}
				else
				{
					refuse_other_rts++;
					return REFUSE;
				}
			}
		} else { // recv RTS, but me congested. So, refuse it.
			refuse_other_rts++;
			return REFUSE;
		}
	}
}
/*
 * It's just a function to store the packet ready to send. 
 * But why should we need it? 
 */
void Mac802_11::store_tx()
{
	assert (pktTx_);
	assert (!pktPre_);
	assert (!HDR_CMN(pktTx_)->control_packet());
	
	if(pktRTS_) { //do not store RTS packet
		discard(pktRTS_, "DIY");
	}
	pktRTS_ = nullptr;
		
	// Just store the data packet
	assert(!HDR_CMN(pktTx_)->control_packet());
	pktPre_ = pktTx_;
	pktTx_ = nullptr;
	RecordStatus(How::decr);
		
	assert(!pktRTS_);
	if(!pktCTRL_ && mhDefer_.busy())
		mhDefer_.stop();
	if(mhBackoff_.busy())
		mhBackoff_.stop();
}

/*
 * NOTE:the function is the opposite of the function store_tx()
 */
void
Mac802_11::restore_tx()
{
	nb_congested = -1.0; ///NEWK
	if(!pktPre_)
		return;
	if(pktTx_) {
		assert(mhBackoff_.busy() || mhSend_.busy() || mhDefer_.busy());
		return;
	}
    
	pktTx_ = pktPre_;
	RecordStatus(How::incr);
	if(nbtimer.busy())
		nbtimer.stop();
	pktPre_ = NULL;
	struct hdr_mac802_11* dh = HDR_MAC802_11( pktTx_ );
	sendRTS ( ETHER_ADDR ( dh->dh_ra ) );

	if (mhBackoff_.busy())
		mhBackoff_.stop();
	if(is_idle()) {
		if (mhDefer_.busy() == 0) {
			double rTime = (Random::random() % cw_)
				* (phymib_.getSlotTime());
			mhDefer_.start(phymib_.getDIFS() + rTime);
		}
	} else {
		mhBackoff_.start(cw_, is_idle());
	}
}
#endif