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
 * $Header: /nfs/jade/vint/CVSROOT/ns-2/mac/mac-802_11.h,v 1.24 2004/04/02 01:00:25 xuanc Exp $
 *
 * Ported from CMU/Monarch's code, nov'98 -Padma.
 * wireless-mac-802_11.h
 */

#ifndef ns_mac_80211_h
#define ns_mac_80211_h

// Added by Sushmita to support event tracing (singal@nunki.usc.edu)
#include "address.h"
#include "ip.h"

#include "mac-timers.h"
#include "marshall.h"
#include <math.h>

#include <string>
#include <map>
#include<vector>
#include<unordered_map>
#include<stdio.h>

#include "priqueue.h"
#include "dsr-priqueue.h"
#include "aodv/aodv.h"
#include "dsr/dsragent.h"
//#include "tcp/matcp.h"
#include <mac.h>

class MaTcpAgent;

//#define MACDEBUG
#ifdef SEMITCP
#define RECEIVER(p) ETHER_ADDR(HDR_MAC802_11(p)->dh_ra)
#define SENDER(p) ETHER_ADDR(HDR_MAC802_11(p)->dh_ta)
enum refuse_state {CTS, CTS_C, REFUSE};

class Neighbour {
  private:
	u_int32_t id; ///the id of this neighbour
	bool helped_by_me; ///whether this neighbour has been helped by me
	double helped_time;///the time it sent a CTSC to me.
  public:
	Neighbour(u_int32_t nodeid): id( nodeid ) {
		helped_by_me =false;
		helped_time = -1.0;
	}
	void set_helped_by_me(bool bin) {
	      helped_by_me = bin;
	}
	bool get_helped_by_me() {
	      return helped_by_me;
	}
	void set_helped_time(double t) {
	      helped_time = t;
	}
	double get_helped_time() {
	      return helped_time;
	}
	int get_id() {
		return id;
	}
};
#endif

class EventTrace;

#define GET_ETHER_TYPE(x)		GET2BYTE((x))
#define SET_ETHER_TYPE(x,y)            {u_int16_t t = (y); STORE2BYTE(x,&t);}

/* ======================================================================
   Frame Formats
   ====================================================================== */

#define	MAC_ProtocolVersion	0x00

#define MAC_Type_Management	0x00
#define MAC_Type_Control	0x01
#define MAC_Type_Data		0x02
#define MAC_Type_Reserved	0x03

#define MAC_Subtype_RTS		0x0B
#define MAC_Subtype_CTS		0x0C
#define MAC_Subtype_ACK		0x0D
#define MAC_Subtype_Data	0x00
#ifdef SEMITCP
#define MAC_Subtype_uRTS	0x0E ///Urgent RTR
#endif
struct frame_control {
	u_char		fc_subtype		: 4;
	u_char		fc_type			: 2;
	u_char		fc_protocol_version	: 2;

	u_char		fc_order		: 1;
	u_char		fc_wep			: 1;
	u_char		fc_more_data		: 1;
	u_char		fc_pwr_mgt		: 1;
	u_char		fc_retry		: 1;
	u_char		fc_more_frag		: 1;
	u_char		fc_from_ds		: 1;
	u_char		fc_to_ds		: 1;
};

struct rts_frame {
	struct frame_control	rf_fc;
	u_int16_t		rf_duration;
	u_char			rf_ra[ETHER_ADDR_LEN];
	u_char			rf_ta[ETHER_ADDR_LEN];
	u_char			rf_fcs[ETHER_FCS_LEN];
};

struct cts_frame {
	struct frame_control	cf_fc;
	u_int16_t		cf_duration;
	u_char			cf_ra[ETHER_ADDR_LEN];
	u_char			cf_fcs[ETHER_FCS_LEN];
};

struct ack_frame {
	struct frame_control	af_fc;
	u_int16_t		af_duration;
	u_char			af_ra[ETHER_ADDR_LEN];
	u_char			af_fcs[ETHER_FCS_LEN];
};

// XXX This header does not have its header access function because it shares
// the same header space with hdr_mac.
struct hdr_mac802_11 {
	struct frame_control	dh_fc;
	u_int16_t		dh_duration;
	u_char          dh_ra[ETHER_ADDR_LEN];
    u_char          dh_ta[ETHER_ADDR_LEN];
    u_char          dh_3a[ETHER_ADDR_LEN];
	u_int16_t		dh_scontrol;
	u_char			dh_body[0]; // XXX Non-ANSI
};


/* ======================================================================
   Definitions
   ====================================================================== */

/* Must account for propagation delays added by the channel model when
 * calculating tx timeouts (as set in tcl/lan/ns-mac.tcl).
 *   -- Gavin Holland, March 2002
 */
#define DSSS_MaxPropagationDelay        0.000002        // 2us   XXXX

class PHY_MIB {
public:
	PHY_MIB(Mac802_11 *parent);

	inline u_int32_t getCWMin() { return(CWMin); }
    inline u_int32_t getCWMax() { return(CWMax); }
	inline double getSlotTime() { return(SlotTime); }
	inline double getSIFS() { return(SIFSTime); }
	inline double getPIFS() { return(SIFSTime + SlotTime); }
	inline double getDIFS() { return(SIFSTime + 2 * SlotTime); }
	inline double getEIFS() {
		// see (802.11-1999, 9.2.10)
		return(SIFSTime + getDIFS() + (8 *  getACKlen())/PLCPDataRate);
	}
	inline u_int32_t getPreambleLength() { return(PreambleLength); }
	inline double getPLCPDataRate() { return(PLCPDataRate); }
	
	inline u_int32_t getPLCPhdrLen() {
		return((PreambleLength + PLCPHeaderLength) >> 3);
	}

	inline u_int32_t getHdrLen11() {
		return(getPLCPhdrLen() + sizeof(struct hdr_mac802_11)
                       + ETHER_FCS_LEN);
	}
	
	inline u_int32_t getRTSlen() {
		return(getPLCPhdrLen() + sizeof(struct rts_frame));
	}
	
	inline u_int32_t getCTSlen() {
		return(getPLCPhdrLen() + sizeof(struct cts_frame));
	}
	
	inline u_int32_t getACKlen() {
		return(getPLCPhdrLen() + sizeof(struct ack_frame));
	}

 private:

	u_int32_t	CWMin;
	u_int32_t	CWMax;
	double		SlotTime;
	double		SIFSTime;
	u_int32_t	PreambleLength;
	u_int32_t	PLCPHeaderLength;
	double		PLCPDataRate;
};


/*
 * IEEE 802.11 Spec, section 11.4.4.2
 *      - default values for the MAC Attributes
 */
#define MAC_FragmentationThreshold	2346		// bytes
#define MAC_MaxTransmitMSDULifetime	512		// time units
#define MAC_MaxReceiveLifetime		512		// time units

class MAC_MIB {
public:
	MAC_MIB(Mac802_11 *parent);

private:
	u_int32_t	RTSThreshold;
	u_int32_t	ShortRetryLimit;    //有RTS机制时的尝试重传次数限制
	u_int32_t	LongRetryLimit;     //没有RTS机制时的尝试重传次数限制
public:
	u_int32_t	FailedCount;	
	u_int32_t	RTSFailureCount;
	u_int32_t	ACKFailureCount;
 public:
       inline u_int32_t getRTSThreshold() { return(RTSThreshold);}
       inline u_int32_t getShortRetryLimit() { return(ShortRetryLimit);}
       inline u_int32_t getLongRetryLimit() { return(LongRetryLimit);}
};


/* ======================================================================
   The following destination class is used for duplicate detection.
   ====================================================================== */
class Host {
public:
	LIST_ENTRY(Host) link;
	u_int32_t	index;
	u_int32_t	seqno;
};


/* ======================================================================
   The actual 802.11 MAC class.
   ====================================================================== */
class Mac802_11 : public Mac {
  
	friend class DeferTimer;
	friend class BackoffTimer;
	friend class IFTimer;
	friend class NavTimer;
	friend class RxTimer;
	friend class TxTimer;
	#ifdef SEMITCP
	friend class NBTimer;
	#endif
public:
	Mac802_11();
	void		recv(Packet *p, Handler *h);
	inline int	hdr_dst(char* hdr, int dst = -2);
	inline int	hdr_src(char* hdr, int src = -2);
	inline int	hdr_type(char* hdr, u_int16_t type = 0);
	
	inline int bss_id() { return bss_id_; }
	
	// Added by Sushmita to support event tracing
        void trace_event(char *, Packet *);
        EventTrace *et_;
		size_t maxAckQueueSize_;
		double avgSendTime_;
		double maxSendTime_;
		double minSendTime_;
		int sendingDataSeqno_;
		double receiveTime_;
		double totalTime_;
		int totalCount_;
		std::vector<std::pair<double, double>> send_time_vec;

protected:
	void	backoffHandler(void);
	void	deferHandler(void);
	void	navHandler(void);
	void	recvHandler(void);
	void	sendHandler(void);
	void	txHandler(void);

private:
	int		command(int argc, const char*const* argv);

	/*
	 * Called by the timers.
	 */
	void    recv_timer();
	void	send_timer();
	int		check_pktCTRL();
	int		check_pktRTS();
	int		check_pktTx();

	/*
	 * Packet Transmission Functions.
	 */
	void	send(Packet *p, Handler *h);
	void 	sendRTS(int dst);   //Just to construct RTS packet
#ifdef SEMITCP
	void	sendCTS(int dst, double duration, bool congested = false);
#else
	void	sendCTS(int dst, double duration);
#endif
	void	sendACK(int dst);
	void	sendDATA(Packet *p);
	void	RetransmitRTS();
	void	RetransmitDATA();

	/*
	 * Packet Reception Functions.
	 */
	void	recvRTS(Packet *p);
	void	recvCTS(Packet *p);
	void	recvACK(Packet *p);
	void	recvDATA(Packet *p);

	void		capture(Packet *p);
	void		collision(Packet *p);
	void		discard(Packet *p, const char* why);
	void		rx_resume();
	void		tx_resume();

	inline int	is_idle();

	/*
	 * Debugging Functions.
	 */
	void		trace_pkt(Packet *p);
	void		dump(char* fname);

	inline int initialized() {	
		return (cache_ && logtarget_
                        && Mac::initialized());
	}

	inline void mac_log(Packet *p) {
                logtarget_->recv(p, (Handler*) 0);
        }

	double txtime(Packet *p);
	double txtime(double psz, double drt);
	double txtime(int bytes) { /* clobber inherited txtime() */ abort(); return 0;}

	inline void transmit(Packet *p, double timeout);
	inline void checkBackoffTimer(void);
	inline void postBackoff(int pri);
	inline void setRxState(MacState newState);
	inline void setTxState(MacState newState);


#ifdef SEMITCP
	
	typedef map<u_int32_t, Neighbour*, less<u_int32_t> > neighbour_map;
	neighbour_map nbs; ///nbs is short for neighbour set
	
	double nb_congested;///NEWK
	int kk;///NEWK
	int KK;///KK is set from the tcl file
	Packet* last_rts_frame; ///store the rts frame for future judgement
	double round_trip_time;//the time to judge whether the neighbour has moved away.
	
	void overHear(Packet* p);   //the handler function to record the packet information needed
	

	void store_tx();    
	void restore_tx();

	refuse_state refuse ( Packet* p );  //是否拒绝回复CTS或者回复CTSC
	bool defer_rts(Neighbour *);    //decide whether defer to send RTS or not
public:
	bool neighbor_congested(); 
	bool local_congested();
	bool TotalCongested() const;
private:
	void print_to_trace(Packet* p, char* function = NULL);

	int CALLRT;     //发送多次RTS或者DATA失败后将数据包回退给路由层，路由层重新找路
	
	MaTcpAgent *p_to_tcp;
	AODV* p_aodv_agent;
	PriQueue* p_to_prique;
	
	double prev_time_;
	double start_time;
	double end_time;
	std::unordered_map<int, std::vector<double>> intervals;
	
	void RecordStatus(How how)
	{
		double now = Scheduler::instance().clock();
		if (start_time < 0.0)
			start_time = now;
		end_time = now;
		
		int prev_len = 0;
		if (how == How::incr)
		{
			prev_len = 0;
		}
		else
		{
			prev_len = 1;
		}
		
		if (prev_len <= 0)
			return;
		
		if (intervals.find(prev_len) == intervals.end())
		{
			intervals[prev_len] = std::vector<double>();
		}
		
		double interval = now - prev_time_;
		prev_time_ = now;
		intervals[prev_len].push_back(interval);				
	}
	
    double avg_length() const
	{ 
		if (intervals.empty())
			return 0.0;
		
		double total_len = 0.0;
		for (auto pr : intervals)
		{
			int queue_len = pr.first;
			vector<double> interval_vec = pr.second;
			
			if (queue_len <= 0 || interval_vec.empty())
				continue;
			
			for (auto d : interval_vec)
			{
				total_len += (queue_len * d);
			}
		}
		return total_len / (end_time - start_time);
    }	
	
/*******MHC DEBUG************/
 
    int refuse_other_rts;
    int dead_lock;
           
    int RTS_send;
    int CTS_recv;
    int CTSC_recv;
    int DATA_send;
    int ACK_recv;
    
    int RTS_recv;
    int CTS_send;
    int CTSC_send;
    int DATA_recv;
    int ACK_send;
	
	int RTS_drop;
	
	int forward_data_send;
	int backward_ack_send;
	int forward_data_retransmit;
	int backward_ack_retransmit;
	int forward_data_drop;
	int backward_ack_drop;
	       
/*******MHC DEBUG***********/
#endif

	inline void inc_cw() {
		cw_ = (cw_ << 1) + 1;
		if(cw_ > phymib_.getCWMax())
			cw_ = phymib_.getCWMax();
	}
	inline void rst_cw() { cw_ = phymib_.getCWMin(); }

	inline double sec(double t) { return(t *= 1.0e-6); }
	inline u_int16_t usec(double t) {
		u_int16_t us = (u_int16_t)floor((t *= 1e6) + 0.5);
		return us;
	}
	inline void set_nav(u_int16_t us) {
		double now = Scheduler::instance().clock();
		double t = us * 1e-6;
		if((now + t) > nav_) {
			nav_ = now + t;
			if(mhNav_.busy())
				mhNav_.stop();
			mhNav_.start(t);
		}
	}
protected:
    PHY_MIB     phymib_;
    MAC_MIB     macmib_;

       /* the macaddr of my AP in BSS mode; for IBSS mode
        * this is set to a reserved value IBSS_ID - the
        * MAC_BROADCAST reserved value can be used for this
        * purpose
        */
       int     bss_id_;
       enum    {IBSS_ID=MAC_BROADCAST};


private:
	double		basicRate_;
 	double		dataRate_;
	
	/*
	 * Mac Timers
	 */
	Packet* pktPre_;    //it's the previous packet?
	NBTimer nbtimer;
	IFTimer		mhIF_;		// interface timer
	NavTimer	mhNav_;		// NAV timer
	RxTimer		mhRecv_;		// incoming packets
	TxTimer		mhSend_;		// outgoing packets

	DeferTimer	mhDefer_;	// defer timer
	BackoffTimer	mhBackoff_;	// backoff timer

	/* ============================================================
	   Internal MAC State
	   ============================================================ */
	double		nav_;		// Network Allocation Vector

	MacState	rx_state_;	// incoming state (MAC_RECV or MAC_IDLE)
	MacState	tx_state_;	// outgoint state (MAC_SEND or MAC_IDLE)
	int		    tx_active_;	// transmitter is ACTIVE

	Packet      *eotPacket_;    // copy for eot callback

	Packet		*pktRTS_;	// outgoing RTS packet
	Packet		*pktCTRL_;	// outgoing non-RTS packet (CTS or ACK)

	u_int32_t	cw_;		// Contention Window
	u_int32_t	ssrc_;		// STA Short Retry Count
	u_int32_t	slrc_;		// STA Long Retry Count

	int		min_frame_len_;     //not used

	NsObject*	logtarget_;
	NsObject*   EOTtarget_;     // given a copy of packet at TX end




	/* ============================================================
	   Duplicate Detection state
	   ============================================================ */
	u_int16_t	sta_seqno_;	// next seqno that I'll use
	int		cache_node_count_;
	Host		*cache_;
};

#endif /*end of mac-802_11.h*/