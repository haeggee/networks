/* Filename: dr_api.c */

/* include files */
#include <arpa/inet.h>  /* htons, ... */
#include <sys/socket.h> /* AF_INET */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#include "dr_api.h"
#include "rmutex.h"

/* internal data structures */
#define INFINITY 16

#define RIP_IP htonl(0xE0000009)

#define RIP_COMMAND_REQUEST  1
#define RIP_COMMAND_RESPONSE 2
#define RIP_VERSION          2

#define RIP_ADVERT_INTERVAL_SEC 10
#define RIP_TIMEOUT_SEC 20
#define RIP_GARBAGE_SEC 20

/** information about a route which is sent with a RIP packet */
typedef struct rip_entry_t {
    uint16_t addr_family;
    uint16_t pad;           /* just put zero in this field */
    uint32_t ip;
    uint32_t subnet_mask;
    uint32_t next_hop;
    uint32_t metric;
} __attribute__ ((packed)) rip_entry_t;

/** the RIP payload header */
typedef struct rip_header_t {
    char        command;
    char        version;
    uint16_t    pad;        /* just put zero in this field */
    rip_entry_t entries[0];
} __attribute__ ((packed)) rip_header_t;

/** a single entry in the routing table */
typedef struct route_t {
    uint32_t subnet;        /* destination subnet which this route is for */
    uint32_t mask;          /* mask associated with this route */
    uint32_t next_hop_ip;   /* next hop on on this route */
    uint32_t outgoing_intf; /* interface to use to send packets on this route */
    uint32_t cost;
    struct timeval last_updated;

    int is_garbage; /* boolean which notes whether this entry is garbage */
    
    int is_direct; // boolean to note whether this entry is to a direct subnet
    
    int changed_flag; // flag to indicate whether entry was changed and needs to be sent
    
    uint32_t intf_cost; // previously saved cost to use this intf

    route_t* next;  /* pointer to the next route in a linked-list */
} route_t;


/* internal variables */

/* a very coarse recursive mutex to synchronize access to methods */
static rmutex_t coarse_lock;

/** how mlong to sleep between periodic callbacks */
static unsigned secs_to_sleep_between_callbacks;
static unsigned nanosecs_to_sleep_between_callbacks;


/* these static functions are defined by the dr */

/*** Returns the number of interfaces on the host we're currently connected to.*/
static unsigned (*dr_interface_count)();

/*** Returns a copy of the requested interface.  All fields will be 0 if the an* invalid interface index is requested.*/
static lvns_interface_t (*dr_get_interface)(unsigned index);

/*** Sends specified dynamic routing payload.** @param dst_ip   The ultimate destination of the packet.
 ** @param next_hop_ip  The IP of the next hop (either a router or the final dst).** @param outgoing_intf  Index of the interface to send the packet from.
 ** @param payload  This will be sent as the payload of the DR packet.  The caller*                 is reponsible for managing the memory associated with buf*                 (e.g. this function will NOT free buf).
 ** @param len      The number of bytes in the DR payload.*/
static void (*dr_send_payload)(uint32_t dst_ip,
                               uint32_t next_hop_ip,
                               uint32_t outgoing_intf,
                               char* /* borrowed */,
                               unsigned);


/* internal functions */
long get_time();
void print_ip(int ip);
void print_routing_table(route_t *head);
/* internal lock-safe methods for the students to implement */
static next_hop_t safe_dr_get_next_hop(uint32_t ip);
static void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                                  char* buf /* borrowed */, unsigned len);
static void safe_dr_handle_periodic();
static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed);

/*** This simple method is the entry point to a thread which will periodically* make a callback to your dr_handle_periodic method.*/
static void* periodic_callback_manager_main(void* nil) {
    struct timespec timeout;

    timeout.tv_sec = secs_to_sleep_between_callbacks;
    timeout.tv_nsec = nanosecs_to_sleep_between_callbacks;
    while(1) {
        nanosleep(&timeout, NULL);
        dr_handle_periodic();
    }

    return NULL;
}

next_hop_t dr_get_next_hop(uint32_t ip) {
    next_hop_t hop;
    rmutex_lock(&coarse_lock);
    hop = safe_dr_get_next_hop(ip);
    rmutex_unlock(&coarse_lock);
    return hop;
}

void dr_handle_packet(uint32_t ip, unsigned intf, char* buf /* borrowed */, unsigned len) {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_packet(ip, intf, buf, len);
    rmutex_unlock(&coarse_lock);
}

void dr_handle_periodic() {
    rmutex_lock(&coarse_lock);
    safe_dr_handle_periodic();
    rmutex_unlock(&coarse_lock);
}

void dr_interface_changed(unsigned intf, int state_changed, int cost_changed) {
    rmutex_lock(&coarse_lock);
    safe_dr_interface_changed(intf, state_changed, cost_changed);
    rmutex_unlock(&coarse_lock);
}


/* ****** It is recommended that you only modify code below this line! ****** */
/********************************************************************************
*********************************************************************************
******************************************************************************** */

// -------------------------------own additions:
route_t *routing_table;
long last_periodic_updatetime;
unsigned tablesize;

void dr_advertisement(unsigned changed_count);

void collect_garbage();

//----------------------------------------------
void dr_init(unsigned (*func_dr_interface_count)(),
             lvns_interface_t (*func_dr_get_interface)(unsigned index),
             void (*func_dr_send_payload)(uint32_t dst_ip,
                                          uint32_t next_hop_ip,
                                          uint32_t outgoing_intf,
                                          char* /* borrowed */,
                                          unsigned)) {
    pthread_t tid;

    /* save the functions the DR is providing for us */
    dr_interface_count = func_dr_interface_count;
    dr_get_interface = func_dr_get_interface;
    dr_send_payload = func_dr_send_payload;

    /* initialize the recursive mutex */
    rmutex_init(&coarse_lock);

    /* initialize the amount of time we want between callbacks */
    secs_to_sleep_between_callbacks = 1;
    nanosecs_to_sleep_between_callbacks = 0;

    /* start a new thread to provide the periodic callbacks */
    if(pthread_create(&tid, NULL, periodic_callback_manager_main, NULL) != 0) {
        fprintf(stderr, "pthread_create failed in dr_initn");
        exit(1);
    }

    /* do initialization of your own data structures here */
    
    unsigned count = dr_interface_count();
    if(count == 0) {
        return;
    }
    lvns_interface_t curr_intf = dr_get_interface(0);
    routing_table = (route_t *) malloc(sizeof(route_t));
    if(!routing_table) {
        fprintf(stderr, "failed to allocate routing table entry");
        exit(1);
    }
    routing_table->subnet = curr_intf.ip;
    routing_table->mask = curr_intf.subnet_mask;
    routing_table->next_hop_ip = 0;
    routing_table->outgoing_intf = 0;
    routing_table->cost = curr_intf.cost;
    gettimeofday(&(routing_table->last_updated), NULL);
    routing_table->is_direct = 1;
    if(!curr_intf.enabled) {
        routing_table->cost = INFINITY;
        routing_table->is_direct = 0;
    }
    routing_table->next = NULL;
    routing_table->changed_flag = 0;
    routing_table->intf_cost = curr_intf.cost;
    
    route_t *prev = routing_table;
    
    
    
    unsigned i = 1;
    while(i < count) {
        route_t *curr;
        curr_intf = dr_get_interface(i);
        curr = (route_t *) malloc(sizeof(route_t));
        if(!curr) {
            fprintf(stderr, "failed to allocate routing table entry");
            exit(1);
        }
        curr->subnet = curr_intf.ip;
        curr->mask = curr_intf.subnet_mask;
        curr->next_hop_ip = 0;
        curr->outgoing_intf = i;
        curr->cost = curr_intf.cost;
        gettimeofday(&(curr->last_updated), NULL);
        curr->is_direct = 1;
        if(!curr_intf.enabled) {
            curr->cost = INFINITY;
            curr->is_direct = 0;
        }    
        prev->next = curr;
        prev = curr;
        curr->next = NULL;
        curr->changed_flag = 0;
        curr->intf_cost = curr_intf.cost;
        i++;
        
     }
     tablesize = count;
     //print_routing_table(routing_table);
}
unsigned counter;

next_hop_t safe_dr_get_next_hop(uint32_t ip) {
    
    /* determine the next hop in order to get to ip */
    next_hop_t hop;
   // if(counter++ % 4 == 0)
     //   print_routing_table(routing_table);
    hop.interface = 0;
    hop.dst_ip = 0xFFFFFFFF;
    uint32_t prev_cost = INFINITY;
    uint32_t prev_mask = 0;
    
    route_t *curr = routing_table;
    while(curr != NULL) {
        if((curr->subnet & curr->mask) == (ip & curr->mask)) { // check if prefix matches
            // check if longer prefix, or if prefix equal and cost cheaper, which is needed for duplic. entries
            // we can have as we always keep the local subnets
            if(ntohl(curr->mask) > prev_mask || ((ntohl(curr->mask) == prev_mask) && curr->cost < prev_cost)) {
                hop.interface = curr->outgoing_intf;
                hop.dst_ip = curr->next_hop_ip;
                prev_mask = ntohl(curr->mask);
                prev_cost = curr->cost;
            }
        }
        curr = curr->next;
    }

    return hop;
}

void safe_dr_handle_packet(uint32_t ip, unsigned intf,
                           char* buf /* borrowed */, unsigned len) {
    /* handle the dynamic routing payload in the buf buffer */
    // check command, version, len 

    
   // print_routing_table(routing_table);
    lvns_interface_t interface = dr_get_interface(intf);
    
    rip_header_t *header = (rip_header_t *) buf;
    if(interface.enabled == 0 || (interface.ip == ip) || (header->version != RIP_VERSION)
        || (header->command != RIP_COMMAND_RESPONSE)) {
        return;
    }
    
    unsigned size = (len - sizeof(rip_header_t)) / sizeof(rip_entry_t);
    rip_entry_t *curr = (rip_entry_t *) (buf + sizeof(rip_header_t));
    
    
    unsigned i = 0; 
    unsigned changed_count = 0;
    while(i < size) {
        
        int matching = 0; // will indicate if an existing entry has been updated, i.e. do not need a new entry
        uint32_t curr_ip = curr->ip;
        uint32_t curr_mask = curr->subnet_mask;
        uint32_t curr_met = curr->metric;
       
        if(1 <= curr_met && curr_met <= INFINITY) {
            curr_met = curr_met + interface.cost; // calc new metric by adding intf cost
            curr_met = (curr_met > INFINITY) ? INFINITY : curr_met; // can at maximal be infinity
            route_t *curr_entry = routing_table;
            while(curr_entry != NULL) {
                 if(((curr_entry->subnet & curr_entry->mask) == (curr_ip & curr_mask))
                    && (curr_entry->mask == curr_mask)) { // matching entry
                    
                      matching = 1;
                      if(curr_entry->is_direct == 1) {
                        // if the matching entry is a local one, check if the learnt metric is better;
                        // if yes, set matching zero, i.e. create a new entry
                        matching = (curr_entry->cost <= curr_met) ? 1 : 0; 
                        break;
                      }
                      if(curr_entry->next_hop_ip == ip) {
                            gettimeofday(&(curr_entry->last_updated), NULL);
                      }
                      
                      if((curr_entry->next_hop_ip == ip && curr_entry->cost != curr_met)
                           || curr_entry->cost > curr_met) {      

                            curr_entry->next_hop_ip = ip;
                            curr_entry->cost = curr_met;
                            curr_entry->outgoing_intf = intf;
                           // curr_entry->is_direct = 0;
                            changed_count += 1;
                            curr_entry->changed_flag = 1;
                            curr_entry->intf_cost = interface.cost;
                            gettimeofday(&(curr_entry->last_updated), NULL);
                     } 
                     break;
                 }
                 curr_entry = curr_entry->next;
           }
           
           // create new entry
           if(!matching && curr_met != INFINITY) {
              route_t *new_entry = (route_t *) malloc(sizeof(route_t));
              if(!new_entry) {
                fprintf(stderr, "failed to allocate routing table entry");
                exit(1);
              }
              new_entry->subnet = curr_ip;
              new_entry->mask = curr_mask;
              new_entry->next_hop_ip = ip;
              new_entry->outgoing_intf = intf;
              new_entry->changed_flag = 1;
              changed_count++;
              new_entry->cost = curr_met;
              gettimeofday(&(new_entry->last_updated), NULL);
              new_entry->is_direct = 0;
              new_entry->intf_cost = interface.cost;
              new_entry->next = routing_table;
              routing_table = new_entry;
              tablesize++;
           }
           
        }
        curr++;
        i++;
    
    }
        dr_advertisement(changed_count); // changed count
        
   //collect_garbage();
}

// ---------------------------------------------------------------------------------------own methods

void dr_advertisement(unsigned changed_count) {
    
    if(changed_count == 0) {
        return;
    }
    
    
    unsigned len = sizeof(rip_header_t) + changed_count * sizeof(rip_entry_t);
    
    char *buf = (char *) malloc(len);
    if(!buf) {
       fprintf(stderr, "failed to allocate sending buffer");
       exit(1);
    }
    
    rip_entry_t *curr = (rip_entry_t *) (buf + sizeof(rip_header_t));
    
    rip_header_t *header = (rip_header_t *) buf;
    header->command = RIP_COMMAND_RESPONSE;
    header->version = RIP_VERSION;
    
    unsigned i = 0;
    route_t *curr_entry = routing_table;
    
    while(i < changed_count) {
        // addr_family?
        if(curr_entry->changed_flag || (changed_count == tablesize)) { // either we have a triggered update,
                                                                      // or we have advertisem. with all entries
            curr->ip = curr_entry->subnet;
            curr->subnet_mask = curr_entry->mask;
            curr->next_hop = curr_entry->next_hop_ip;
            curr->metric = curr_entry->cost;
            i++;
            curr++;
        }
        
        curr_entry = curr_entry->next;
    }
    
    unsigned intf_no = 0;
    
    unsigned intf_cnt = dr_interface_count();
    
    while(intf_no < intf_cnt) {
        if(dr_get_interface(intf_no).enabled == 0) {
            intf_no++;
            continue;
        }
        i = 0;
        curr_entry = routing_table;
        curr = (rip_entry_t *) (buf + sizeof(rip_header_t));
        while(i < changed_count) { // poisoned reverse
            if(curr_entry->changed_flag || changed_count == tablesize) {
                if(curr_entry->is_direct == 0 && curr_entry->outgoing_intf == intf_no) {
                    curr->metric = INFINITY;
                }
                curr++;
                i++;
            }         
            curr_entry = curr_entry->next;
        }
        dr_send_payload(RIP_IP, RIP_IP, intf_no, buf, len);

        // restore correct metrics
        i = 0;
        curr_entry = routing_table;
        curr = (rip_entry_t *) (buf + sizeof(rip_header_t));
        while(i < changed_count) {
            if(curr_entry->changed_flag || changed_count == tablesize) {
                curr->metric = curr_entry->cost;
                i++;
                curr++;
            }
            curr_entry = curr_entry->next;
        }
        intf_no++;
        
    }
    
    curr_entry = routing_table;
    while(curr_entry != NULL) {
        curr_entry->changed_flag = 0;
        curr_entry = curr_entry->next;
    }
    free(buf);
    
    if(changed_count == tablesize) {
        last_periodic_updatetime = get_time();
    }
    
}

    
// go through routing table and delete those which have metric infinity
void collect_garbage() {
    route_t *curr = routing_table;
    route_t *prev = NULL;
    while(curr != NULL) {
        if(curr->cost == INFINITY) { // needs to be deleted
            print_ip(ntohl(curr->subnet));
            // case head of list
            if(prev == NULL) {
                routing_table = curr->next;
                free(curr);
                curr = routing_table;
            // case inside list
            } else {
                prev->next = curr->next;
                free(curr);
                curr = prev->next;
            }
        tablesize--;
        
        } else {
            prev = curr;
            curr = curr->next;
        }
    }
}

// ------------------------------------------------------------------------------------------end of own methods
void safe_dr_handle_periodic() {
    route_t *curr = routing_table;
    unsigned changed_count = 0;
    while(curr != NULL) {
        long time = curr->last_updated.tv_sec * 1000 + curr->last_updated.tv_usec / 1000;
        if((get_time() - time) > (RIP_TIMEOUT_SEC * 1000) && curr->is_direct == 0) { // timeout, delete entry
            curr->cost = INFINITY;
            curr->changed_flag = 1;
            changed_count += 1;
        }
        curr = curr->next;
    }
    // either we need to make an advertisement anyway, or just broadcast the entries to be deleted
    if((get_time() - last_periodic_updatetime) > RIP_ADVERT_INTERVAL_SEC * 1000) {
        dr_advertisement(tablesize);
    } else if (changed_count > 0) {
        dr_advertisement(changed_count); // changed count
    } 
    collect_garbage();
    //print_routing_table(routing_table);
    //printf("tablesize = %d\n========================\n", tablesize);
}

static void safe_dr_interface_changed(unsigned intf,
                                      int state_changed,
                                      int cost_changed) {
    /* handle an interface going down or being brought up */
    
    lvns_interface_t curr_interface = dr_get_interface(intf);
    
    if(state_changed) {
        if(curr_interface.enabled) { // interface brought up
            route_t *new_entry = (route_t *) malloc(sizeof(route_t));
            if(!new_entry) {
               fprintf(stderr, "failed to allocate routing table entry");
               exit(1);
            }
            new_entry->subnet = curr_interface.ip;
            new_entry->mask = curr_interface.subnet_mask;
            new_entry->next_hop_ip = 0;
            new_entry->outgoing_intf = intf;
            new_entry->cost = curr_interface.cost;
            gettimeofday(&(new_entry->last_updated), NULL);
            new_entry->next = routing_table;
            routing_table = new_entry;
            new_entry->is_direct = 1;
            new_entry->intf_cost = curr_interface.cost;
            new_entry->changed_flag = 1;
            tablesize++;
            dr_advertisement(1);
        } else {    // interface brought down
            route_t *curr = routing_table;
            unsigned changed_count = 0;
            while(curr != NULL) {
                if(curr->outgoing_intf == intf) {
                    curr->cost = INFINITY; // mark entry to be deleted
                    curr->is_direct = 0; // we need to delete the flag s.t. 
                    curr->changed_flag = 1;
                    changed_count += 1;
                }
                curr = curr->next;
            }
            dr_advertisement(changed_count);
        }
   } 
   if(cost_changed && curr_interface.enabled) { // only set new cost if intf is enabled
       route_t *curr = routing_table;
       unsigned changed_count = 0;
       while(curr != NULL) {
           if(curr->outgoing_intf == intf) {
                // subtract old intf cost, add new one
                curr->cost -= curr->intf_cost; 
                curr->cost += curr_interface.cost;
                curr->intf_cost = curr_interface.cost;
                curr->changed_flag = 1;
                changed_count += 1;
           }
           curr = curr->next;
       }
       dr_advertisement(changed_count);
   }
        
        
        
}

/* definition of internal functions */

// gives current time in milliseconds
long get_time(){
    // Now in milliseconds
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec / 1000;
}

// prints an ip address in the correct format
// this function is taken from: 
// https://stackoverflow.com/questions/1680365/integer-to-ip-address-c 
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);        
}

// prints the full routing table
void print_routing_table(route_t *head){
    printf("==================================================================\nROUTING TABLE:\n==================================================================\n");
    int counter = 0;
    route_t *current = head;
    while (current != NULL){
        printf("Entry %d:\n",counter);
        printf("\tSubnet: ");
        print_ip(ntohl(current->subnet));
        printf("\tMask: ");
        print_ip(ntohl(current->mask));
        printf("\tNext hop ip: ");
        print_ip(ntohl(current->next_hop_ip));
        printf("\tOutgoing interface: ");
        print_ip(current->outgoing_intf);
        //-----------------------
        printf("\tChanged: %d\n", current->changed_flag);
        //----------------------
        printf("\tCost: %d\n", current->cost);
        printf("\tLast updated (timestamp in microseconds): %li \n", current->last_updated.tv_usec);
        printf("==============================\n");
        counter ++;

        current = current->next;
    }
}
