#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>

#include "rlib.h"
#include "buffer.h"

struct reliable_state {
  rel_t *next;			/* Linked list for traversing all connections */
  rel_t **prev;

  conn_t *c;			/* This is the connection object */

  /* Add your own data fields below this */
  // ...
  buffer_t* send_buffer;
  // ...


  buffer_t* rec_buffer;

  // following fields are inherited from config_common cc in the rel_create call
  int maxwnd; // window size
  int timeout; 
  //
  int rcv_nxt; // expected sequence number
    
  int snd_una; // lowest seqno of unacknowledged packet
  int snd_nxt; // seqno of next packet to send
  int snd_wnd; // nxt - una, less or equal to maxwnd
    
  int small_sent; // 0 if no unacknowledged data frame with less than 500B sent, 1 otherwise
  int small_sent_seqno; // seqno of the small packet which was already sent
  
  int EOF_inp; // 1 if we read EOF from input
  int EOF_recv; // 1 if we received EOF from other side
  // ...
  packet_t *new_pack; // buffer for new packet to be sent
  int new_pack_size; // how many bytes of data already in the packet
  
  int highest_out; // indicates the largest seqno which was given to application + 1
};
rel_t *rel_list;


/* Creates a new reliable protocol session, returns NULL on failure.
 * ss is always NULL */
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
	    const struct config_common *cc)
{
  rel_t *r;

  r = xmalloc (sizeof (*r));
  memset (r, 0, sizeof (*r));

  if (!c) {
    c = conn_create (r, ss);
    if (!c) {
      free (r);
      return NULL;
    }
  }

  r->c = c;
  r->next = rel_list;
  r->prev = &rel_list;
  if (rel_list)
    rel_list->prev = &r->next;
  rel_list = r;

  /* Do any other initialization you need here... */
  // -----------------------------------------------
  // initialization for my own variables
    
  r->maxwnd = cc->window;
  r->timeout = cc->timeout;
  r->rcv_nxt = 1;
  r->highest_out = 2;
  
  r->snd_una = 1;
  r->snd_nxt = 1;
  r->snd_wnd = 0;
  r->small_sent = 0;
    
  r->EOF_inp = 0;
  r->EOF_recv = 0;
  
  r->new_pack = NULL;
  r->new_pack_size = 0;
  r->small_sent_seqno = 1;
  // -------------------------------------------------
  r->send_buffer = xmalloc(sizeof(buffer_t));
  r->send_buffer->head = NULL;
  // ...
  r->rec_buffer = xmalloc(sizeof(buffer_t));
  r->rec_buffer->head = NULL;
  // ...
  
  return r;
}

void
rel_destroy (rel_t *r)
{
  if (r->next) {
    r->next->prev = r->prev;
  }
  *r->prev = r->next;
  conn_destroy (r->c);

  /* Free any other allocated memory here */
  buffer_clear(r->send_buffer);
  free(r->send_buffer);
  buffer_clear(r->rec_buffer);
  free(r->rec_buffer);
  // ...

}

// n is the expected length of pkt
void
rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
  int len = ntohs(pkt->len);
  if(len < 8 || len > 512) {
    //fprintf(stderr, "garbage: n = %d, len = %d\n", n, len);
    return;
  }
  size_t old_cksum = pkt->cksum;
  pkt->cksum = 0;
  size_t new_cksum = cksum(pkt, len);
  
  // check corruption 
    
  if(new_cksum != old_cksum) { 
  
    //fprintf(stderr, "corruption cksum = %d, actual %d\n paket is: ", new_cksum, old_cksum);
    return;
  }
  
  // ACK packet ------------
  if(len == 8) {
    size_t ackno = ntohl(pkt->ackno);
    if(ackno > r->snd_una) {
      r->snd_una = ackno; // update UNA
    }
    if(ackno > r->small_sent_seqno) {
      r->small_sent = 0;
    }
    buffer_remove(r->send_buffer, ackno);
    rel_read(r); // buffer got smaller, so can read now
  // -----------------------
  // DATA packet -----------
  } else {
    
    size_t seqno = ntohl(pkt->seqno);
    if(seqno < r->rcv_nxt + r->maxwnd && seqno >= r->rcv_nxt) { // packet in window
     
     if(len == 12) { // EOF packet
             r->EOF_recv = 1;
     }
     if(!buffer_contains(r->rec_buffer, seqno)) { // insert if not duplicate
        buffer_insert(r->rec_buffer, pkt, 0);
     }
        
     if(seqno == r->rcv_nxt) { // get highest consecutive seqno in buffer
          while(buffer_contains(r->rec_buffer, r->rcv_nxt)) {
	          r->rcv_nxt += 1;
          }
          rel_output(r);
        }
    }
    // always send ACK
    // smaller of the 2 values for flow control
    int ackno = (r->highest_out < r->rcv_nxt) ? r->highest_out : r->rcv_nxt; 
    struct ack_packet *ack_pack = xmalloc(sizeof(packet_t));
    ack_pack->len = htons((uint16_t) 8);
    ack_pack->ackno = htonl((uint32_t) ackno);
    ack_pack->cksum = 0;
    ack_pack->cksum = cksum(ack_pack, 8);
    while(conn_sendpkt(r->c, (packet_t *) ack_pack, 8) != 8)
      ;
  }
}
// this function sends the packet which is stored in the new_pack field of the reliable connection
// ----------------------------------------------------------------------------------------------
void send_new_pack(rel_t *s) {
  int size = s->new_pack_size;
  s->new_pack->len = htons((uint16_t) (size + 12)); 
  s->new_pack->seqno = htonl((uint32_t) (s->snd_nxt));
  s->new_pack->cksum = 0;
  s->new_pack->cksum = cksum(s->new_pack, size + 12);
    
  struct timeval now;
  gettimeofday(&now, NULL);
  while (conn_sendpkt(s->c, s->new_pack, size + 12) != size + 12) { // loop until complete packet sent
    gettimeofday(&now, NULL);
  }
  long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
  buffer_insert(s->send_buffer, s->new_pack, now_ms);
  free(s->new_pack);
  s->new_pack = NULL;
  if(size < 500) { // if this is a small packet, no other small should be sent
    s->small_sent = 1;
    s->small_sent_seqno = s->snd_nxt;
  }
  s->new_pack_size = 0;
  s->snd_nxt += 1;
}
// -----------------------------------------------------------------------------------------------

void
rel_read (rel_t *s)
{
  //fprintf(stderr, "maxwnd = %d snd_nxt = %d, snd_una = %d\n", s->maxwnd, s->snd_nxt, s->snd_una);
  if(s->snd_nxt >= (s->snd_una + s->maxwnd) || buffer_size(s->send_buffer) == s->maxwnd) {
    return;
  }
  
  if(s->new_pack == NULL) {
    s->new_pack = xmalloc(sizeof(packet_t));
  }
  int length = conn_input(s->c, (s->new_pack->data) + s->new_pack_size, 500-(s->new_pack_size));
  //fprintf(stderr, "%s", s->new_pack->data);
  if(length == 0 && s->new_pack_size == 0) {
    return;
  }
  // no EOF or error -------------------------------------------------
  if(length != -1) {
    s->new_pack_size += length;
    if(s->new_pack_size < 500 && s->small_sent) { // do not send multiple packets with small data, however keep
                                                  // the packet as buffer
      return;
    }
    
    send_new_pack(s);
    rel_read(s);
    return;
    
  // EOF or error from input ----------------------------------------
  } else {
    if(s->new_pack_size > 0) { // send packet if it previously had data
      send_new_pack(s);
    }
    // do not send multiple EOFs or if out of window
    if(s->EOF_inp || (s->snd_nxt >= s->snd_una + s->maxwnd)) {
      return;
    } else {
      s->EOF_inp = 1;
      if(s->new_pack == NULL) {
        s->new_pack = xmalloc(sizeof(packet_t));
      }
      s->new_pack_size = 0;
      send_new_pack(s);
    }
  }
    
}

void
rel_output (rel_t *r)
{
  buffer_node_t *curr = buffer_get_first(r->rec_buffer);
  if(curr == NULL) { // buffer empty
    return;
  }
  size_t seqno = ntohl(curr->packet.seqno);
  size_t prev_seqno = seqno - 1;
  size_t bufspace = conn_bufspace(r->c);
  size_t buf_need = ntohs(curr->packet.len) - 12;
  while(buf_need < bufspace && (seqno - 1 == prev_seqno)) { // loop until packets are not in order
                                                            // or buffer full
    conn_output(r->c, &(curr->packet.data), buf_need); 
    curr = curr->next;
    buffer_remove_first(r->rec_buffer);
    r->highest_out = seqno + 1;
    if(curr == NULL) {
      return;
    }
    bufspace = conn_bufspace(r->c);
    buf_need = ntohs(curr->packet.len) - 12;
    prev_seqno = seqno;
    seqno = ntohl(curr->packet.seqno);
  }
        
}

void
rel_timer ()
{
  
  // Go over all reliable senders, and have them send out
  // all packets whose timer has expired
  
  
  rel_t *current = rel_list;
  //fprintf(stderr, "size = %d, rcv_nxt = %x\n", buffer_size(current->send_buffer), current->rcv_nxt);
  
  
  // check the four conditions which need to hold for rel_destroy
  if(current->EOF_recv && current->EOF_inp && (buffer_size(current->rec_buffer) == 0) && (buffer_size(current->send_buffer) == 0)) {
    //fprintf(stderr, "own call to destroy\n");
    rel_destroy(current);
    return;
  }
  
  while (current != NULL) {
    
    
    // traverse buffer and send those whose timer has expired;
    // since we use cumulative ACKs, we know that no ack'd packet will be in the buffer
  
    buffer_node_t *curr = buffer_get_first(current->send_buffer);
    while(curr != NULL) { // not out of window
      struct timeval now;
      gettimeofday(&now, NULL);
      long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
      if((now_ms - curr->last_retransmit) > current->timeout ) { // timeout
        size_t len = ntohs(curr->packet.len);
        
        while (conn_sendpkt(current->c, &(curr->packet), len) != len) { // loop until complete packet sent
	        gettimeofday(&now, NULL);
        }     
	    curr->last_retransmit = now.tv_sec * 1000 + now.tv_usec / 1000;
      }
      curr = curr->next;
    }
    current = rel_list->next;
  }
 
}


// here is some old code which I was not sure about, but want to keep for safety
// for line 365:
/*
	  size_t seqno = ntohl(curr->packet.seqno);
	  if(len < (500 - 12) && current->small_sent && current->small_sent_seqno != seqno) {
    	  curr = curr->next;
	  continue;
	  } */
	  
// line 266 : 
/* while(s->snd_nxt < (s->snd_una + s->maxwnd) && length != 0) {
     packet_t *new_pack = xmalloc(sizeof(packet_t));
     length = conn_input(s->c, new_pack->data, 500);
    
     if(length == -1) {
     if(s->EOF_inp) {
     free(new_pack);
     break;
     }
     s->EOF_inp = 1;
     length = 0;
     } else if(length == 0) {
     free(new_pack);
     break;
     }
    
     fprintf(stderr, "i = %d and data = '%s'\n",  i, new_pack->data);
     i+=1;
     new_pack->len = htons((uint16_t) (length + 12)); 
     new_pack->seqno = htonl((uint32_t) (s->snd_nxt));
     new_pack->cksum = 0;
     new_pack->cksum = cksum(new_pack, length + 12);
    
     struct timeval now;
     gettimeofday(&now, NULL);
     while (conn_sendpkt(s->c, new_pack, length + 12) != length + 12) { // loop until complete packet sent
     gettimeofday(&now, NULL);
     }
     long now_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
     buffer_insert(s->send_buffer, new_pack, now_ms);
     free(new_pack);
     s->snd_nxt += 1;
    
     }
  */
  //rel_timer(); // new packets now are in buffer (or not), go through buffer and do all necessary transmissions
