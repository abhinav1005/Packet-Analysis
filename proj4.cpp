/*
    Abhinav Khanna
    axk1312
    CSDS 325
    Project 4

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string>
#include <arpa/inet.h>
#include <unordered_map>

#define ERROR 1
#define REQUIRED_CMDS 4
#define ALLOWED_INVALID_CMDS 2      // the two invalid commands are the project filename, trace_filename
#define CONVERSION_FACTOR 1000000.0 // for meta.usecs to meta.secs conversion
#define MAX_PKT_SIZE 1600
#define CONVERT_BYTES 4

bool rOption, sMode, lMode, pMode, cMode = false;
char *traceFile = NULL;

/* meta information, using same layout as trace file */
struct meta_info
{
    unsigned int usecs;
    unsigned int secs;
    unsigned short ignored;
    unsigned short caplen;
};

struct TrafficData
{
    unsigned long total_pkts = 0;
    unsigned long traffic_volume = 0;
};

/* record of information about the current packet */
struct pkt_info
{
    unsigned short caplen; /* from meta info */
    double now;            /* from meta info */
    unsigned char pkt[MAX_PKT_SIZE];
    struct ether_header *ethh; /* ptr to ethernet header, if present,
                                  otherwise NULL */
    struct iphdr *iph;         /* ptr to IP header, if present,
                                  otherwise NULL */
    struct tcphdr *tcph;       /* ptr to TCP header, if present,
                                  otherwise NULL */
    struct udphdr *udph;       /* ptr to UDP header, if present,
                                  otherwise NULL */
};

int usage(char *progname)
{
    fprintf(stderr, "usage: %s host port\n", progname);
    exit(ERROR);
}

int errexit(const char *format, const char *arg)
{
    fprintf(stderr, format, arg);
    fprintf(stderr, "\n");
    exit(ERROR);
}

/* fd - an open file to read packets from
   pinfo - allocated memory to put packet info into for one packet

   returns:
   1 - a packet was read and pinfo is setup for processing the packet
   0 - we have hit the end of the file and no packet is available
 */
unsigned short next_packet(int fd, struct pkt_info *pinfo)
{
    struct meta_info meta;
    int bytes_read;

    memset(pinfo, 0x0, sizeof(struct pkt_info));
    memset(&meta, 0x0, sizeof(struct meta_info));

    /* read the meta information */
    bytes_read = read(fd, &meta, sizeof(meta));
    if (bytes_read == 0)
        return (0);
    if (bytes_read < static_cast<int>(sizeof(meta)))
        errexit("cannot read meta information", NULL);
    pinfo->caplen = ntohs(meta.caplen);
    /* TODO: set pinfo->now based on meta.secs & meta.usecs */
    pinfo->now = ntohl(meta.secs) + (ntohl(meta.usecs) / CONVERSION_FACTOR);
    if (pinfo->caplen == 0)
        return (1);
    if (pinfo->caplen > MAX_PKT_SIZE)
        errexit("packet too big", NULL);
    /* read the packet contents */
    bytes_read = read(fd, pinfo->pkt, pinfo->caplen);
    if (bytes_read < 0)
        errexit("error reading packet", NULL);
    if (bytes_read < pinfo->caplen)
        errexit("unexpected end of file encountered", NULL);
    if (bytes_read < static_cast<int>(sizeof(struct ether_header)))
        return (1);

    pinfo->ethh = (struct ether_header *)pinfo->pkt;
    pinfo->ethh->ether_type = ntohs(pinfo->ethh->ether_type);
    if (pinfo->ethh->ether_type != ETHERTYPE_IP)
        /* nothing more to do with non-IP packets */
        return (1);
    if (pinfo->caplen == sizeof(struct ether_header))
        /* we don't have anything beyond the ethernet header to process */
        return (1);

    pinfo->iph = (struct iphdr *)(pinfo->pkt + sizeof(struct ether_header));

    if (pinfo->iph->protocol == IPPROTO_TCP)
    {
        pinfo->tcph = (struct tcphdr *)((unsigned char *)pinfo->iph + (pinfo->iph->ihl * CONVERT_BYTES));
    }
    else if (pinfo->iph->protocol == IPPROTO_UDP)
    {
        pinfo->udph = (struct udphdr *)((unsigned char *)pinfo->iph + (pinfo->iph->ihl * CONVERT_BYTES));
    }
    return (1);
}

void handle_length_mode(int fd, struct pkt_info packet)
{
    while (next_packet(fd, &packet))
    {
        // Check if the ethernet protocol exists and is IP
        if (packet.ethh && packet.ethh->ether_type == ETHERTYPE_IP)
        {
            double ts = packet.now;
            unsigned short caplen = packet.caplen;
            char ip_len_str[16] = "-";
            char iphl_str[16] = "-";
            char transport_str[2] = "-";
            char trans_hl_str[16] = "-";
            char payload_len_str[16] = "-";

            // if there is a header
            if (packet.iph)
            {
                unsigned short ip_len = ntohs(packet.iph->tot_len);
                unsigned short iphl = packet.iph->ihl * CONVERT_BYTES;
                sprintf(ip_len_str, "%hu", ip_len);
                sprintf(iphl_str, "%hu", iphl);

                if (packet.iph->protocol == IPPROTO_TCP)
                {
                    strcpy(transport_str, "T");
                    int headerlength = (packet.caplen) - sizeof(iphdr) - sizeof(ether_header);
                    // check if there is a tcp header
                    if (headerlength != 0)
                    {
                        unsigned short trans_hl = packet.tcph->doff * CONVERT_BYTES;
                        unsigned short payload_len = ip_len - iphl - trans_hl;
                        sprintf(trans_hl_str, "%hu", trans_hl);
                        sprintf(payload_len_str, "%hu", payload_len);
                    }
                    else
                    {
                        strcpy(trans_hl_str, "-");
                        strcpy(payload_len_str, "-");
                    }
                }
                else if (packet.iph->protocol == IPPROTO_UDP)
                {
                    strcpy(transport_str, "U");
                    int headerlength = (packet.caplen) - sizeof(iphdr) - sizeof(ether_header);
                    if (headerlength != 0)
                    {
                        unsigned short trans_hl = sizeof(struct udphdr);
                        unsigned short payload_len = ip_len - iphl - trans_hl;
                        sprintf(trans_hl_str, "%hu", trans_hl);
                        sprintf(payload_len_str, "%hu", payload_len);
                    }
                    else
                    {
                        strcpy(trans_hl_str, "-");
                        strcpy(payload_len_str, "-");
                    }
                }
                else
                {
                    strcpy(transport_str, "?");
                    strcpy(trans_hl_str, "?");
                    strcpy(payload_len_str, "?");
                }
            }

            // Print the information with IP header fields
            printf("%.6f %hu %s %s %s %s %s\n", ts, caplen, ip_len_str, iphl_str, transport_str, trans_hl_str, payload_len_str);
        }
    }
}

void handle_summary_mode(int fd, struct pkt_info pinfo)
{
    double trace_duration = 0.0;
    double first_packet = 0.0;
    double last_packet = 0.0;
    int total_packet = 0;
    int IP_packet = 0;

    while (next_packet(fd, &pinfo))
    {
        if (total_packet == 0)
        {
            first_packet = pinfo.now;
        }
        last_packet = pinfo.now;

        if (pinfo.ethh != NULL && pinfo.ethh->ether_type == ETHERTYPE_IP)
        {
            IP_packet++;
        }
        total_packet += 1;
    }

    trace_duration = last_packet - first_packet;
    printf("time: first: %.6f last: %.6f duration: %.6f\n", first_packet, last_packet, trace_duration);
    printf("pkts: total: %d ip: %d\n", total_packet, IP_packet);
}

void handle_printing_mode(int fd, struct pkt_info packet)
{
    while (next_packet(fd, &packet))
    {
        // Check for IP and TCP packets
        if (packet.ethh && packet.ethh->ether_type == ETHERTYPE_IP &&
            packet.iph && packet.iph->protocol == IPPROTO_TCP &&
            packet.tcph)
        {
            double ts = packet.now;
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

            // Convert IP addresses to human-readable format
            inet_ntop(AF_INET, &(packet.iph->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(packet.iph->daddr), dst_ip, INET_ADDRSTRLEN);

            // Extracting other fields
            unsigned short src_port = ntohs(packet.tcph->source);
            unsigned short dst_port = ntohs(packet.tcph->dest);
            unsigned short ip_id = ntohs(packet.iph->id);
            unsigned short ip_ttl = packet.iph->ttl;
            unsigned short window = ntohs(packet.tcph->window);
            char ackno_str[32];

            // Check for the ACK flag
            if (packet.tcph->ack)
                snprintf(ackno_str, sizeof(ackno_str), "%u", ntohl(packet.tcph->ack_seq));
            else
                strcpy(ackno_str, "-");

            // Print the packet information
            if (dst_port != 0)
            {
                printf("%.6f %s %hu %s %hu %hu %hu %hu %s\n",
                       ts, src_ip, src_port, dst_ip, dst_port, ip_id, ip_ttl, window, ackno_str);
            }
        }
    }
}

void handle_packet_counting_mode(int fd, struct pkt_info packet)
{
    std::unordered_map<std::string, TrafficData> traffic_map;

    while (next_packet(fd, &packet))
    {
        int headerlength = (packet.caplen) - sizeof(iphdr) - sizeof(ether_header);
        if (packet.ethh && packet.ethh->ether_type == ETHERTYPE_IP &&
            packet.iph && packet.iph->protocol == IPPROTO_TCP &&
            packet.tcph && headerlength != 0)
        {
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(packet.iph->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(packet.iph->daddr), dst_ip, INET_ADDRSTRLEN);

            std::string key = std::string(src_ip) + " " + std::string(dst_ip);
            unsigned short ip_len = ntohs(packet.iph->tot_len);
            unsigned short iphl = packet.iph->ihl * CONVERT_BYTES;
            unsigned short trans_hl = packet.tcph->doff * CONVERT_BYTES;
            unsigned long payload_len = ip_len - iphl - trans_hl;

            if (traffic_map.find(key) != traffic_map.end())
            {
                traffic_map[key].total_pkts += 1;
                traffic_map[key].traffic_volume += payload_len;
            }
            else
            {
                traffic_map[key].total_pkts = 1;
                traffic_map[key].traffic_volume = payload_len;
            }
        }
    }
    // Print the traffic data
    for (auto &pair : traffic_map)
    {
        printf("%s %lu %lu\n", pair.first.c_str(), pair.second.total_pkts, pair.second.traffic_volume);
    }
}

/* Main method which basically checks the arguments and updates the flags for the commands*/
int main(int argc, char *argv[])
{
    bool modeSelected = false;

    if (argc != REQUIRED_CMDS)
    {
        errexit("ERROR: Invalid Number of arguments. You must give atleast filename, -r, trace_file and a mode [-s|-l|-p|-c] . \n", NULL);
    }
    else
    {
        int invalid = 0;
        for (int index = 0; index < argc; index++)
        {
            if (!strcmp(argv[index], "-r"))
            {
                rOption = true;
                traceFile = argv[index + 1];
            }
            else if (!strcmp(argv[index], "-s"))
            {
                if (modeSelected)
                {
                    errexit("ERROR: Too many mode arguments. Can only specify one mode at a time", NULL);
                }
                sMode = true;
                modeSelected = true;
            }
            else if (!strcmp(argv[index], "-l"))
            {
                if (modeSelected)
                {
                    errexit("ERROR: Too many mode arguments. Can only specify one mode at a time", NULL);
                }
                lMode = true;
                modeSelected = true;
            }
            else if (!strcmp(argv[index], "-p"))
            {
                if (modeSelected)
                {
                    errexit("ERROR: Too many mode arguments. Can only specify one mode at a time", NULL);
                }
                pMode = true;
                modeSelected = true;
            }
            else if (!strcmp(argv[index], "-c"))
            {
                if (modeSelected)
                {
                    errexit("ERROR: Too many mode arguments. Can only specify one mode at a time", NULL);
                }
                cMode = true;
                modeSelected = true;
            }
            else
            {
                invalid++;
            }
        }

        if (invalid > ALLOWED_INVALID_CMDS)
        {
            errexit("Error. Invalid Arguments have been specified", NULL);
        }

        if (!rOption)
        {
            errexit(" -r and trace_file must be present", NULL);
        }

        if (!modeSelected)
        {
            errexit(" Atleast one mode must be selected [-s | -l | -p | -c]", NULL);
        }
    }

    int fd;
    struct pkt_info pinfo;
    if ((fd = open(traceFile, O_RDONLY)) < 0)
        errexit("ERROR: Unable to open trace file %s", traceFile);

    if (sMode)
    {
        handle_summary_mode(fd, pinfo);
    }
    else if (lMode)
    {
        handle_length_mode(fd, pinfo);
    }
    else if (pMode)
    {
        handle_printing_mode(fd, pinfo);
    }
    else if (cMode)
    {
        handle_packet_counting_mode(fd, pinfo);
    }
}

