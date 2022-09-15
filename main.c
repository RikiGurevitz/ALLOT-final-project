#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <json-c/json.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <time.h>
#include "Data_stractors.c"

// function declarations
void read_configuration_file();
void open_tdr_file();
void new_request(struct Five_touple *, int);
void create_new_transaction(struct Five_touple *, int);
void new_response_from_server(struct Five_touple *);
static inline unsigned int create_hash_key(struct Five_touple *);
void create_new_connection(struct Five_touple *, int, struct Transaction *);
static inline int compare_five_touple(struct Five_touple *, struct Five_touple *);
void write_connection_to_file(struct Connection *);
void write_video_statistics();

struct pcap_pkthdr *pkt_header;

struct Video *video_st;
FILE *TDR;
struct List **hash_table;
static int conn_id = 0;
int all_connection_num = 0;

// variables for the configuration file
int int_request_packet_threshold;
int int_video_connection_timeout;
int int_max_number_of_transaction_per_video;
int int_inbound_packets_in_range_max;
int int_inbound_packets_in_range_min;
int int_max_number_of_connections;
int int_Minimum_video_connection_size;
char *char_pcap_file_name;

int main()
{
    
    const u_char *pkt_data;
    // read the configuration file and initilize the variables
    read_configuration_file();

    video_st = (struct Video *)calloc(1, sizeof(struct Video));
    // define the hash size According to the variable of max_number_of_connections
    hash_table = malloc(sizeof(struct List *) * int_max_number_of_connections);

    // open the input file
    int size_of_ethernet = sizeof(struct ethhdr);
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(char_pcap_file_name, error_buffer);
    if (handle == NULL)
    {
        printf("unable to open file\n");
        return 1;
    }

    // open the output file
    open_tdr_file();

    // loop that go over all the pcap file
    while (pcap_next_ex(handle, &pkt_header, &pkt_data) >= 0)
    {
        struct iphdr *ipHeader = (struct iphdr *)(pkt_data + size_of_ethernet);
        // if the protocol packet isnt udp protocol
        if (ipHeader->protocol != IPPROTO_UDP)
        {
            continue;
        }
        int size_of_ipHeader = ipHeader->ihl << 2;
        struct udphdr *udpHeader = (struct udphdr *)(pkt_data + size_of_ethernet + size_of_ipHeader);


    //parse the ip adressess
        struct Five_touple *current_packet_five_touple = (struct Five_touple *)malloc(sizeof(struct Five_touple));
        int src_ip = ntohs(ipHeader->saddr);
        current_packet_five_touple->Ip_protocol = ipHeader->protocol;
        int dest_ip = ntohs(ipHeader->daddr);
        int src_port = ntohs(udpHeader->source);
        int dest_port = ntohs(udpHeader->dest);

        //compute the packet size
        int current_packet_size = pkt_header->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);

        // if ths packer is a request from client to youtube server
        if (dest_port == 443)
        {
            current_packet_five_touple->Client_ip = src_ip;
            current_packet_five_touple->Server_ip = dest_ip;
            current_packet_five_touple->Udp_client_port = src_port;
            // sending to function that sort the function according to their size
            new_request(current_packet_five_touple, current_packet_size);
        }

        // response from the server
        else
        {
            if (src_port == 443)
            {
                current_packet_five_touple->Client_ip = dest_ip;
                current_packet_five_touple->Server_ip = src_ip;
                current_packet_five_touple->Udp_client_port = dest_port;
                new_response_from_server(current_packet_five_touple);
            }
        }
    }

    // after finish the pcap file write to the file all the open connections
    for (int i = 0; i < int_max_number_of_connections; i++)
    {
        if (hash_table[i] != NULL)
        {

            struct Node *temp = hash_table[i]->head;
            while (temp != NULL)
            {
                struct Connection *con = (struct Connection *)temp->data;
                if (con->Minimum_video_connection_size >= int_Minimum_video_connection_size) // )
                {
                    write_connection_to_file((struct Connection *)temp->data);
                }
                temp = temp->next;
            }
        }
    }
    fclose(TDR);
    write_video_statistics();
    printf("conn_id %d\n", conn_id);
    printf("all_connection_num %d\n", all_connection_num);
    return 0;
}

// the function search the right connection for the response and update the statistics vraiables
void new_response_from_server(struct Five_touple *current_packet_five_touple)
{
    int uniqe_key = create_hash_key(current_packet_five_touple);
    // there is a connection like this
    if (hash_table[uniqe_key] != NULL)
    {
        struct Node *head = hash_table[uniqe_key]->head;
        int flag = 0;
        // loop over all the connection in the current place and find if there is a same connection
        while (head != NULL)
        {
            connection *current_con = (connection *)(head->data);

            // we found this connection of this response
            if (compare_five_touple(current_packet_five_touple, current_con->five_touple) == 1)
            {
                flag = 1;
                double packet_response_time = pkt_header->ts.tv_sec + (double)pkt_header->ts.tv_usec / 1000000;
                if (packet_response_time - current_con->last_transaction_time < int_video_connection_timeout)
                {
                    struct Transaction *exi_tran = (struct Transaction *)(current_con->transaction_list->head->data);

                    // update the laat time in the connection
                    current_con->last_transaction_time = packet_response_time;

                    int packet_size = pkt_header->len - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr);
                    // if the packet is in range
                    if (packet_size >= int_inbound_packets_in_range_min && packet_size <= int_inbound_packets_in_range_max)
                    {
                        current_con->Minimum_video_connection_size += packet_size;
                        // update the max and min diff inboundtime variables
                        if (exi_tran->last_inbound_transaction_time != 0)
                        {
                            if (packet_response_time - exi_tran->last_inbound_transaction_time > exi_tran->max_diff_time_inbound)
                            {
                                exi_tran->max_diff_time_inbound = packet_response_time - exi_tran->last_inbound_transaction_time;
                            }
                            if (packet_response_time - exi_tran->last_inbound_transaction_time < exi_tran->min_diff_time_inbound)
                            {
                                exi_tran->min_diff_time_inbound = packet_response_time - exi_tran->last_inbound_transaction_time;
                            }
                        }
                        // if it is the first response of this transaction update the RTT varible
                        if (exi_tran->RTT == -1)
                        {
                            exi_tran->RTT = packet_response_time -exi_tran->Start_time;
                        }
                        exi_tran->last_inbound_transaction_time = packet_response_time;
                        // update the min and max packet size
                        if (exi_tran->max_packet_size_inbound < packet_size)
                        {
                            exi_tran->max_packet_size_inbound = packet_size;
                        }
                        if (exi_tran->min_packet_size_inbound > packet_size)
                        {
                            exi_tran->min_packet_size_inbound = packet_size;
                        }
                        exi_tran->tran_size += packet_size;
                        exi_tran->last_packet_time_in_transaction = packet_response_time;
                        exi_tran->last_inbound_transaction_time = packet_response_time;
                        exi_tran->num_inbound_packets_in_range++;
                    }
                }
                // this connecton us time out!!!!!!
                //  if this connection size greater than the int_Minimum_video_connection_size write it to the output file
                else
                {
                    if (current_con->Minimum_video_connection_size >= int_Minimum_video_connection_size)
                    {
                        write_connection_to_file(current_con);
                    }
                    // delete the connection from the memory -hash table
                    delete_middle_node(hash_table[uniqe_key], head);
                }
                break;
            }
            head = head->next;
        }
    }
}

// function to read the configuration variables from the configuration file
void read_configuration_file()
{
    FILE *configoration_file;
    char buffer[1024];
    struct json_object *parsed_json;
    struct json_object *request_packet_threshold;
    struct json_object *Minimum_video_connection_size;
    struct json_object *video_connection_timeout;
    struct json_object *max_number_of_connections;
    struct json_object *max_number_of_transaction_per_video;
    struct json_object *inbound_packets_in_range_max;
    struct json_object *inbound_packets_in_range_min;
    struct json_object *pcap_file_name;
    configoration_file = fopen("configuration.json", "r");
    if (configoration_file == NULL)
    {
        printf("Unable to open json file .\n");
    }
    fread(buffer, 1024, 1, configoration_file);
    fclose(configoration_file);
    parsed_json = json_tokener_parse(buffer);
    json_object_object_get_ex(parsed_json, "request_packet_threshold", &request_packet_threshold);
    json_object_object_get_ex(parsed_json, "video_connection_timeout", &video_connection_timeout);
    json_object_object_get_ex(parsed_json, "max_number_of_connections", &max_number_of_connections);
    json_object_object_get_ex(parsed_json, "max_number_of_transaction_per_video", &max_number_of_transaction_per_video);
    json_object_object_get_ex(parsed_json, "inbound_packets_in_range_max", &inbound_packets_in_range_max);
    json_object_object_get_ex(parsed_json, "inbound_packets_in_range_min", &inbound_packets_in_range_min);
    json_object_object_get_ex(parsed_json, "Minimum_video_connection_size", &Minimum_video_connection_size);
    json_object_object_get_ex(parsed_json, "pcap_file_name", &pcap_file_name);
    int_request_packet_threshold = json_object_get_int(request_packet_threshold);
    int_video_connection_timeout = json_object_get_int(video_connection_timeout);
    int_max_number_of_connections = json_object_get_int(max_number_of_connections);
    int_max_number_of_transaction_per_video = json_object_get_int(max_number_of_transaction_per_video);
    int_inbound_packets_in_range_max = json_object_get_int(inbound_packets_in_range_max);
    int_inbound_packets_in_range_min = json_object_get_int(inbound_packets_in_range_min);
    int_Minimum_video_connection_size = json_object_get_int(Minimum_video_connection_size);
    char_pcap_file_name = (char *)json_object_get_string(pcap_file_name);
}

// function that open the output file and  write the titles
void open_tdr_file()
{
    TDR = fopen("TDR.csv", "w+");
    if (TDR == NULL)
    {
        printf("Unable to open TDR file .\n");
    }
    fprintf(TDR, "Conn_id, Client_ip, Server_ip,Ip_protocol ,Udp_client_port,server,Tran_id ,Start_time ,num_inbound_packets_in_range,num_oubound_packets_in_range,max_packet_size_inbound,min_packet_size_inbound ,max_diff_time_inbound_threshold, min_diff_time_inbound_threshold, RTT\n");
}

// function that create from the five topules key to the hasg table
static inline unsigned int create_hash_key(struct Five_touple *five_touple)
{

    int unique_five_toupple_key = five_touple->Client_ip + five_touple->Server_ip +
                                  five_touple->Ip_protocol + five_touple->Server_ip + five_touple->Udp_client_port + five_touple->Udp_server_port;

    return unique_five_toupple_key % int_max_number_of_connections;
}

// function that create new transaction and initilize its variables
void create_new_transaction(struct Five_touple *five_touple ,int packet_size)
{
    // allocate new transaction
    struct Transaction *transaction = (struct Transaction *)malloc(sizeof(struct Transaction));

    // parse the time from struct timeval to double time
    double transaction_time = pkt_header->ts.tv_sec + (double)pkt_header->ts.tv_usec / 1000000;
    // initilize the transaction variables
    transaction->Start_time = transaction_time;
    transaction->max_packet_size_inbound = 0;
    transaction->num_outbound_packets_in_range = 0;
    transaction->num_inbound_packets_in_range = 0;
    transaction->min_packet_size_inbound = int_inbound_packets_in_range_max;
    transaction->last_inbound_transaction_time = 0;
    transaction->max_diff_time_inbound = 0;
    transaction->min_diff_time_inbound = int_video_connection_timeout;
    transaction->RTT = -1;
    transaction->tran_size = packet_size;
    transaction->last_packet_time_in_transaction = transaction_time;
    int uniqe_key = create_hash_key(five_touple);

    // new connection in this place
    if (hash_table[uniqe_key] == NULL)
    {
        // initlize the place and create new connection
        hash_table[uniqe_key] = Create_new_list();
        if (conn_id <= int_max_number_of_connections)
        {
            create_new_connection(five_touple, uniqe_key, transaction);
        }
    }
    // this place is not empty
    else
    {
        struct Node *head = hash_table[uniqe_key]->head;
        int flag = 0;
        // go over all the connections in the specific place
        while (head != NULL)
        {
            if (head->data == NULL)
            {
                return;
            }
            connection *current_conn_from_hash = (connection *)(head->data);
            // we found theis connection
            if (compare_five_touple(five_touple, current_conn_from_hash->five_touple) == 1)
            {
                if (transaction->Start_time - current_conn_from_hash->last_transaction_time < int_video_connection_timeout && current_conn_from_hash->last_transaction_id < int_max_number_of_transaction_per_video - 1)
                {
                    // update the variables and push this transaction to the connection list
                    current_conn_from_hash->last_transaction_id++;
                    transaction->tran_id = current_conn_from_hash->last_transaction_id;
                    current_conn_from_hash->last_transaction_time = transaction->Start_time;
                    push_front(current_conn_from_hash->transaction_list, transaction);
                }
                // the connection does not meet the conditions
                // its have to be closed
                else
                {
                    struct Five_touple *ezer_five_touple = current_conn_from_hash->five_touple;
                    write_connection_to_file(current_conn_from_hash);
                    // delete the connection from the connections list
                    delete_middle_node(hash_table[uniqe_key], head);
                    ////////////////////////////////
                    create_new_connection(ezer_five_touple, uniqe_key, transaction);
                }
                flag = 1;
                break;
            }
            head = head->next;
        }
        // this connection not exist in the hash table
        // then create a new connection
        if (!flag)
        {
            if (conn_id <= int_max_number_of_connections)
            {
                create_new_connection(five_touple, uniqe_key, transaction);
            }
        }
    }
}

// input : connection five touple
//         key in the hash table where the connection have to be
//         the transaction that have to be inserted to this connection
// function that create new connection
void create_new_connection(struct Five_touple *five_touple, int uniqe_key, struct Transaction *transaction)
{
    all_connection_num++;

    // allocate the new connection
    struct Connection *new_conn = (struct Connection *)malloc(sizeof(struct Connection));
    // update the connections details
    new_conn->five_touple = five_touple;
    new_conn->last_transaction_id = 0;
    new_conn->transaction_list = Create_new_list();
    new_conn->last_transaction_time = transaction->Start_time;
    new_conn->Minimum_video_connection_size = 0;

    // push the current transaction to the connection transaction list
    push_front(new_conn->transaction_list, transaction);
    // push_back(new_conn->transaction_list, transaction);
    if (hash_table[uniqe_key] != NULL)
    {
        // push the connection to the connection list
        push_back(hash_table[uniqe_key], new_conn);
    }
}

// function that compare between five touple reuest and five touple cnnection
static inline int compare_five_touple(struct Five_touple *new_transaction, struct Five_touple *exist_transaction)
{
    if (new_transaction->Client_ip == exist_transaction->Client_ip)
        if (new_transaction->Server_ip == exist_transaction->Server_ip)
            if (new_transaction->Udp_client_port == exist_transaction->Udp_client_port)
            {
                return 1;
            }
    return 0;
}

// function that print all transaction in the connection
void write_connection_to_file(struct Connection *conn)
{
    if (conn->transaction_list == NULL)
    {
        return;
    }
    conn->Conn_id = conn_id++;
    int number_transaction_per_video = 0;
    int prev_transaction_start_time = 0;
    // double epoch_time = conn.transaction->Start_time.tv_sec + conn.transaction->Start_time.tv_usec / 1000000;
    // go throught the whole transaction list and print transaction details
    struct Node *head = conn->transaction_list->tail;
    struct Transaction *current_tran = (struct Transaction *)(head->data);
    video_st->Average_duration_of_the_videos += conn->last_transaction_time - current_tran->Start_time;
    video_st->Average_size_of_the_videos += conn->Minimum_video_connection_size;
    prev_transaction_start_time = current_tran->Start_time;
    while (head != NULL)
    {
        current_tran = (struct Transaction *)(head->data);
        number_transaction_per_video++;
        
        //parse the time for human readable time
        time_t tran_time = current_tran->Start_time;
        struct tm *time = malloc(sizeof(struct tm));
        time = gmtime(&tran_time);

         //parse the ip adresess 
        struct in_addr server, client;
        client.s_addr = ntohs((*conn->five_touple).Client_ip);
        char client_ip[100];
        strcpy(client_ip, inet_ntoa(client));
        server.s_addr = ntohs((*conn->five_touple).Server_ip);

        //check if was a variabes that dont change 
        if(current_tran->min_packet_size_inbound == 2000){
            current_tran->min_packet_size_inbound = 0;
        }
        if(current_tran->RTT == -1)
        {
            current_tran->RTT == 0;
        }
        if(current_tran->min_diff_time_inbound == int_video_connection_timeout){
            current_tran->min_diff_time_inbound =0;
        }
        //update the variables for the video statistics 
        video_st->Average_size_of_the_TDRs_per_video += current_tran->tran_size;
        video_st->Average_duration_of_the_TDRs_per_video += current_tran->last_packet_time_in_transaction -current_tran->Start_time;
        video_st->Average_time_between_two_consecutive_TDRs_in_a_video_connection += current_tran->Start_time - prev_transaction_start_time;
        prev_transaction_start_time = current_tran->Start_time;
        fprintf(TDR, "%d,%s,%s,%d,%d,%d,%d ,%d:%d:%d ,%d,%d,%d,%d ,%f ,%f ,%f\n", conn->Conn_id, client_ip, inet_ntoa(server), conn->five_touple->Ip_protocol, conn->five_touple->Udp_client_port, conn->five_touple->Udp_server_port, current_tran->tran_id, time->tm_hour, time->tm_min, time->tm_sec,
                current_tran->num_inbound_packets_in_range, current_tran->num_outbound_packets_in_range, current_tran->max_packet_size_inbound, current_tran->min_packet_size_inbound, current_tran->max_diff_time_inbound, current_tran->min_diff_time_inbound, current_tran->RTT);
        head = head->prev;
    }
    video_st->Average_number_of_TDRs_per_video += number_transaction_per_video;
}

// function that get all the request from the clien to server and sort them
void new_request(struct Five_touple *current_packet_five_touple, int current_packet_size)
{

    // if packet size greater than the request_packet_threshold
    // so create a new transaction
    if (current_packet_size >= int_request_packet_threshold)
    {
        create_new_transaction(current_packet_five_touple ,current_packet_size);
    }
    // if the packet size smaller than the request_packet_threshold
    // search this current transaction and increase the num_outbound_packets_in_range
    else
    {
        int uniqe_key = create_hash_key(current_packet_five_touple);
        if (hash_table[uniqe_key] != NULL)
        {
            struct Node *head = hash_table[uniqe_key]->head;
            // go over all the connections in the specific place
            while (head != NULL)
            {
                if (head->data == NULL)
                {
                    return;
                }
                connection *current_conn_from_hash = (connection *)(head->data);
                // we found this connection
                if (compare_five_touple(current_packet_five_touple, current_conn_from_hash->five_touple) == 1)
                {
                    double packet_request_time = pkt_header->ts.tv_sec + (double)pkt_header->ts.tv_usec / 1000000;
                    struct Transaction *t = (struct Transaction *)current_conn_from_hash->transaction_list->head->data;
                    current_conn_from_hash->last_transaction_time = packet_request_time;
                    t->num_outbound_packets_in_range++;
                    t->last_packet_time_in_transaction = packet_request_time;
                }
                head = head->next;
            }
        }
    }
}

void write_video_statistics()
{
    FILE *Video_file = fopen("Video_file.csv", "w+");
    if (Video_file == NULL)
    {
        printf("Unable to open Video_file \n");
    }
    fprintf(Video_file, "Connections num,Average duration of the videos ,Average size of the videos ,Average number of TDRs per video,Average size of the TDRs per video,Average duration of the TDRs per video,Average time between two consecutive TDRs in a video connection\n");
    fprintf(Video_file,"%d ,%f ,%f ,%f ,%f ,%f ,%f " ,conn_id,
    video_st->Average_duration_of_the_videos /conn_id,
    video_st->Average_size_of_the_videos/conn_id,
    video_st->Average_number_of_TDRs_per_video/conn_id ,
    video_st->Average_size_of_the_TDRs_per_video/video_st->Average_number_of_TDRs_per_video, 
    video_st->Average_duration_of_the_TDRs_per_video/video_st->Average_number_of_TDRs_per_video,
    video_st->Average_time_between_two_consecutive_TDRs_in_a_video_connection/video_st->Average_number_of_TDRs_per_video);
    fclose(Video_file);
}