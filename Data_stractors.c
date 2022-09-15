#include <string.h>
#include<stdlib.h>
#include <stdio.h>

struct Five_touple{
unsigned int Udp_client_port;
unsigned int Udp_server_port;
unsigned int Ip_protocol;
unsigned int Client_ip;
unsigned int Server_ip;
};

struct Transaction{
    //struct timeval Start_time;
    int tran_id;
    double min_diff_time_inbound;
    double max_diff_time_inbound;
    double last_inbound_transaction_time;
    double RTT;
    double Start_time;
    double last_packet_time_in_transaction;
    int tran_size;
    int num_inbound_packets_in_range;
    int num_outbound_packets_in_range;
    int min_packet_size_inbound;
    int max_packet_size_inbound;
};

typedef struct Connection{
    int Conn_id;
    int last_transaction_id;
    struct Five_touple* five_touple;
    struct List* transaction_list;
    int Minimum_video_connection_size;
    double last_transaction_time;

}connection;

struct Node {
    void* data;
    struct Node* next;
    struct Node* prev;
};

struct Video{
    double Average_duration_of_the_videos;
    double Average_size_of_the_videos;
    double Average_number_of_TDRs_per_video;
    double Average_size_of_the_TDRs_per_video;
    double Average_duration_of_the_TDRs_per_video;
    double Average_time_between_two_consecutive_TDRs_in_a_video_connection;
};

struct List {
    struct Node* head;
    struct Node* tail;
    int size;
};


static inline struct List* Create_new_list(){
    struct List* l = (struct List*) malloc(sizeof(struct List));
    l->size =0;
    l->head = NULL;
    l->tail = NULL;
    return l;
}
static inline void push_back(struct List* l, void* data)
{
    //printf("in push back push_back\n");
    if(data == NULL){
        printf("ERROR\n");
    }
     struct Node* n = (struct Node*)malloc(sizeof(struct Node));
     n->data = data;
     n->next = NULL;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
        n->prev = NULL;
    }
    else
    {
        n->prev = l->tail;
        l->tail->next = n;
        l->tail = n;
    }
    l->size++;
     //printf("after push back push_back\n");
}

static inline void push_front(struct List* l, void* data) {
    if (l == NULL)
    {
        return;
    }
    struct Node* n = (struct Node*)malloc(1);
    n->data = data;
    if (l->size == 0)
    {
        l->head = n;
        l->tail = n;
    }
    else
    {
        l->head->prev = n;
        n->next = l->head;
        l->head = n;
    }
    l->size++;
}

static inline void* pop_back(struct List* l) {
    if (l == NULL || l->size == 0)
    {
        return NULL;
    }
    void* data = l->tail->data;
    l->tail = l->tail->prev;
    if (l->size == 1)
    {
        l->head = NULL;
    }
    else
    {
        l->tail->next = NULL;
        free(l->tail->next);
    }
    l->size--;
    return data;
}

static inline void* pop_front(struct List* l) {
    if (l == NULL || l->size == 0)
    {
        return NULL;
    }
    void *data = l->head->data;
    l->head = l->head->next;
    if (l->size == 1)
    {
        l->tail = NULL;
    }
    else
    {
        l->head->prev = NULL;
        free(l->head->prev);
    }
    l->size--;
    return data;
}
static inline int is_empty(struct List* l)
{
    return l->size <= 0;
}

static inline void delete_middle_node(struct List* l, struct Node* n)
{
    if (l == NULL || l->size == 0)
    {
        return;
    }
    if (n == l->tail)
    {
        pop_back(l);
    }
    else if (n == l->head)
    {
        pop_front(l);
    }
    else
    {
        struct Node* next = n->next;
        struct Node* prev = n->prev;
        next->prev = prev;
        prev->next = next;
        free(n);
        l->size--;
    }
}