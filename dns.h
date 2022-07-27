//
// Created by Matthew Emerson on 7/23/22.
//

#ifndef PALANTIR_DNS_H
#define PALANTIR_DNS_H

#include <stdint.h>

#define DNS_MAX_UDP_SIZE 512
#define DNS_MAX_LABEL_SIZE 63
#define DNS_MAX_NAME_SIZE 255

/**
 * DNS Header
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      ID                       |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    QDCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ANCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    NSCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                    ARCOUNT                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct header {
    uint16_t id;  // assigned by program generating the query
    uint8_t qr;  // query = 0, reply = 1
    uint8_t opcode;  // 0 = QUERY, 1 = IQUERY, 2 = STATUS, 3-15 reserved
    uint8_t aa;  // specifies that the responding name server is an authority for the domain name in question section
    uint8_t tc;  // message was truncated
    uint8_t rd;  // Recursion Desired (optional)
    uint8_t ra;  // Recursion Available
    uint8_t z;  // Not used, must be 0
    uint8_t rcode;  // 0 = Success, 1 = format error, 2 = server failure, 3 = name error, 5 = refused
    uint16_t qdcount;  // number of entries in the question section
    uint16_t ancount;  // number of entries in the answer section
    uint16_t nscount;  // number of ns records in the authority section
    uint16_t arcount;  // number of resource records in the additional records section
};

#define DNS_HEADER_SIZE 12

/**
 * DNS question section
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                     QNAME                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QTYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     QCLASS                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct question {
    const char *qname;  // 48 bits QUESTION_QNAME_SIZE
    size_t qname_len;
    uint16_t qtype;
    uint16_t qclass;
};

#define DNS_QUESTION_SIZE 10
// was 6
#define DNS_QUESTION_QNAME_SIZE 12


/**
 * DNS resource record used by answer, authority, and additional sections.
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                                               |
 *     /                                               /
 *     /                      NAME                     /
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TYPE                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                     CLASS                     |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                      TTL                      |
 *     |                                               |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *     |                   RDLENGTH                    |
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *     /                     RDATA                     /
 *     /                                               /
 *     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
struct resource {
    const char *name;  // 64 bits RESOURCE_NAME_SIZE
    size_t name_len;  // len of name
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
};

#define DNS_RESOURCE_SIZE 22
#define DNS_RESOURCE_NAME_SIZE 8

/**
 * DNS message
 * @see https://datatracker.ietf.org/doc/html/rfc1035
 *
 *     +---------------------+
 *     |        Header       |
 *     +---------------------+
 *     |       Question      | the question for the name server
 *     +---------------------+
 *     |        Answer       | RRs answering the question
 *     +---------------------+
 *     |      Authority      | RRs pointing toward an authority
 *     +---------------------+
 *     |      Additional     | RRs holding additional information
 *     +---------------------+
 */
struct message {
    struct header *header;
    struct question **questions;
    struct resource **answers;
    struct resource **authorities;
    struct resource **additionals;
};

char *get_class(uint16_t class);
char *get_type(uint16_t type);

struct header *get_header(const char *buffer, size_t size);
struct question *get_question(const char *buffer, size_t size);
struct resource *get_resource(const char *buffer, size_t size);

void print_header(struct header *header);
void print_question(struct question *question);
void print_resource(struct resource *resource);



#endif //PALANTIR_DNS_H
