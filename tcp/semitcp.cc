﻿/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) 1991-1997 Regents of the University of California.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include "ip.h"
#include "tcp.h"
#include "semitcp.h"
#include <algorithm>
#include <unistd.h>

#ifdef SEMITCP

void TcpBackoffTimer::expire(Event *)
{
	a_->backoffHandler();
}

static class SemiTcpClass : public TclClass
{
public:
        SemiTcpClass() : TclClass ( "Agent/TCP/Semi" ) {}
        TclObject* create ( int, const char*const* ) {
                return ( new SemiTcpAgent() );
        }
} class_semi;

SemiTcpAgent::SemiTcpAgent() 
	: backoffTimer_(this), 
	p_to_mac(NULL), 
	cw_(1),
	timeslot(0.00002), // TODO: need to define the proper timeslot?
	isFirstPacket_(true)
{ }

void SemiTcpAgent::backoffHandler()
{
	if(p_to_mac->congested())
	{
		inr_cw(); 	// backoff if congested
		backoffTimer_.resched((Random::random() % cw_) * timeslot);
	}
	else
	{
        output(t_seqno_); 	// send a new packet
        t_seqno_++;
        decr_cw(); 	// FIXME: maybe decrease cw_ window is the better way?
		backoffTimer_.resched((Random::random() % cw_) * timeslot);
	}
}

int SemiTcpAgent::command ( int argc, const char*const* argv )
{
        if ( argc == 3 && strcmp ( argv[1], "semitcp-get-mac" ) == 0 ) 
		{
                p_to_mac = ( Mac802_11* ) TclObject::lookup ( argv[2] );		
				return p_to_mac == NULL ? TCL_ERROR : TCL_OK;

        } else if ( argc == 2 && strcmp ( argv[1], "get-highest-acked" ) == 0 ) 
		{
                printf ( "highest acked seqno: %d \n", ( int ) highest_ack_ );
                return TCL_OK;
        }
        return TcpAgent::command ( argc, argv );
}

void SemiTcpAgent::reset ()
{
        TcpAgent::reset ();

        //since we don't use congestion window in SemiTcp, we set the variable as negative.
        cwnd_ = -1;
        ssthresh_ = -1;
        wnd_restart_ = -1.;
        awnd_ = -1;
}

void
SemiTcpAgent::output ( int seqno, int reason )
{
        int force_set_rtx_timer = 0;
        Packet* p = allocpkt();

        ///record the number of unacked packets
        struct hdr_cmn* ch = HDR_CMN ( p );
        ch->num_acked() = highest_ack_;

        hdr_tcp *tcph = hdr_tcp::access ( p );
        int databytes = hdr_cmn::access ( p )->size();
        tcph->seqno() = seqno;
        tcph->ts() = Scheduler::instance().clock();
        tcph->ts_echo() = ts_peer_;
        tcph->reason() = reason;
        tcph->last_rtt() = int ( t_rtt_ *tcp_tick_*1000 );

        /* Check if this is the initial SYN packet. */
        if ( seqno == 0 ) {
                if ( syn_ ) {
                        databytes = 0;
                        curseq_ += 1;
                        hdr_cmn::access ( p )->size() = tcpip_base_hdr_size_;
                }
        } else if ( useHeaders_ == true ) {
                hdr_cmn::access ( p )->size() += headersize();
        }
        hdr_cmn::access ( p )->size();

        /* if no outstanding data, be sure to set rtx timer again */
        if ( highest_ack_ == maxseq_ )
                force_set_rtx_timer = 1;

        ++ndatapack_;
        ndatabytes_ += databytes;
        
        if ( seqno > curseq_)
		{
            idle();  // Tell application I have sent everything so far
			return;
		}
        if ( seqno > maxseq_ ) {
                maxseq_ = seqno;
                if ( !rtt_active_ ) {
                        rtt_active_ = 1;
                        if ( seqno > rtt_seq_ ) {
                                rtt_seq_ = seqno;
                                rtt_ts_ = Scheduler::instance().clock();
                        }
                }
        } else {
                ++nrexmitpack_;
                nrexmitbytes_ += databytes;
        }
        if (!(rtx_timer_.status() == TIMER_PENDING))
                /* No timer pending.  Schedule one. */
                set_rtx_timer();
	
	send(p, 0);   //really send the packet of p.
}

void SemiTcpAgent::recv_newack_helper ( Packet *pkt )
{
        newack ( pkt );

        /* if the connection is done, call finish() */
        if ( ( highest_ack_ >= curseq_-1 ) && !closed_ ) {
                closed_ = 1;
                finish();
        }
        if ( curseq_ == highest_ack_ +1 ) {
                cancel_rtx_timer();
        }
}
/*
 * Process a packet that acks previously unacknowleged data.
 */
void SemiTcpAgent::newack ( Packet* pkt )
{
        double now = Scheduler::instance().clock();
        hdr_tcp *tcph = hdr_tcp::access ( pkt );

        if ( timerfix_ )
                newtimer ( pkt );
        dupacks_ = 0;
        last_ack_ = tcph->seqno();
        prev_highest_ack_ = highest_ack_ ;
        highest_ack_ = last_ack_;

        if ( t_seqno_ < last_ack_ + 1 )
                t_seqno_ = last_ack_ + 1;
        /*
        * Update RTT only if it's OK to do so from info in the flags header.
        * This is needed for protocols in which intermediate agents
        * in the network intersperse acks (e.g., ack-reconstructors) for
        * various reasons (without violating e2e semantics).
        */
        hdr_flags *fh = hdr_flags::access ( pkt );
        if ( !fh->no_ts_ ) {
                if ( ts_option_ ) {
                        ts_echo_=tcph->ts_echo();
                        rtt_update ( now - tcph->ts_echo() );
                        if ( ts_resetRTO_ && ( !ect_ || !ecn_backoff_ ||
                                               !hdr_flags::access ( pkt )->ecnecho() ) ) {
                                // From Andrei Gurtov
                                /*
                                * Don't end backoff if still in ECN-Echo with
                                * a congestion window of 1 packet.
                                */
                                t_backoff_ = 1;
                                ecn_backoff_ = 0;
                        }
                }
                if ( rtt_active_ && tcph->seqno() >= rtt_seq_ ) {
                        if ( !ect_ || !ecn_backoff_ ||
                             !hdr_flags::access ( pkt )->ecnecho() ) {
                                /*
                                * Don't end backoff if still in ECN-Echo with
                                * a congestion window of 1 packet.
                                */
                                t_backoff_ = 1;
                                ecn_backoff_ = 0;
                        }
                        rtt_active_ = 0;
                        if ( !ts_option_ )
                                rtt_update ( now - rtt_ts_ );
                }
        }
        assert ( cwnd_ == -1 );
}

void SemiTcpAgent::recv ( Packet *pkt, Handler* )
{
        hdr_tcp *tcph = hdr_tcp::access ( pkt );

        /* W.N.: check if this is from a previous incarnation */
        if ( tcph->ts() < lastreset_ ) { //TIME_WAIT states can avoid this condition
                // Remove packet and do nothing
                Packet::free ( pkt );
                return;
        }
        ++nackpack_;
        if ( tcph->seqno() > highest_ack_) 
		{ 	//new ack
                if (t_seqno_ < highest_ack_ + 1) {
                        t_seqno_ = highest_ack_ + 1;
                }
                highest_ack_ = tcph->seqno();
                recv_newack_helper ( pkt ); 
				decr_cw();
				setBackoffTimer();
        }
        else if (tcph->seqno() == highest_ack_)	// duplicate ack
		{
			t_seqno_ = highest_ack_ + 1;
			output(t_seqno_);
			t_seqno_++;
			inr_cw();
			resetBackoffTimer();
		}
		        
        Packet::free ( pkt );
}

///Called when the retransimition timer times out
void SemiTcpAgent::timeout ( int tno )
{
        assert ( tno == TCP_TIMER_RTX );
        trace_event ( "TIMEOUT" );

        assert ( cwnd_ == -1 );
		
		t_seqno_ = highest_ack_ + 1;
		output(t_seqno_, 0);
		t_seqno_++;
		inr_cw();
		resetBackoffTimer();
}

/*
 * NOTE: send_much() is called by sendmsg which is call by application layer protocol,
 * when the app layer has data to send at first.
 */
void SemiTcpAgent::send_much ( int force, int reason, int maxburst )
{
	if (isFirstPacket_)
	{
		isFirstPacket_ = false;
		output(t_seqno_);
		t_seqno_++;
		
		assert(backoffTimer_.status() == TIMER_IDLE);
		backoffTimer_.sched((Random::random() % cw_) * timeslot);
	}
		output();
        if (!p_to_mac->congested()) 
		{
			decr_cw();
        }
        else
		{
			inr_cw();
		}
		setBackoffTimer();
}

void SemiTcpAgent::reset_rtx_timer ( int backoff )
{
        if ( backoff )
                rtt_backoff();
        set_rtx_timer();
        rtt_active_ = 0;
}

void SemiTcpAgent::set_rtx_timer()
{
        double rto = rtt_timeout();
        rtx_timer_.resched ( rto );
}
#endif
