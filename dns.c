//
// Created by Matthew Emerson on 7/23/22.
//

#include <printf.h>
#include <stdlib.h>
#include <string.h>
#include "dns.h"

/**
 * Extracts (deserializes) DNS header from buffer
 *
 * @param buffer UDP DNS message
 * @param size of buffer
 * @return pointer to heap allocated header
 */
struct header *get_header(const char *buffer, size_t size) {
    if (size < DNS_HEADER_SIZE) {
        printf("Error: malformed header\n");
        exit(1);
    }
    struct header *header = malloc(sizeof(struct header));
    header->id = (uint16_t) ((uint16_t)buffer[0] << 8) | buffer[1];
    header->qr = (uint8_t) ((buffer[2] & 0x80) >> 7);
    header->opcode = (uint8_t) ((buffer[2] & 0x78) >> 3);
    header->aa = (uint8_t) ((buffer[2] & 0x4) >> 2);
    header->tc = (uint8_t) ((buffer[2] & 0x2) >> 1);
    header->rd = (uint8_t) (buffer[2] & 0x1);
    header->ra = (uint8_t) ((buffer[3] & 0x80) >> 7);
    header->z = (uint8_t) ((buffer[3] & 0x70) >> 4);
    header->rcode = (uint8_t) (buffer[3] & 0xF);
    header->qdcount = (uint16_t) (buffer[4] << 8) | buffer[5];
    header->ancount = (uint16_t) (buffer[6] << 8) | buffer[7];
    header->nscount = (uint16_t) (buffer[8] << 8) | buffer[9];
    header->arcount = (uint16_t) (buffer[10] << 8) | buffer[11];
    return header;
}

/**
 * Print DNS header
 * @param header
 */
void print_header(struct header *header) {
    printf("DNS Headers: {\n"
           "  id: %u,\n"
           "  qr: %d,\n"
           "  opcode: %d,\n"
           "  aa: %d,\n"
           "  tc: %d,\n"
           "  rd: %d,\n"
           "  ra: %d,\n"
           "  z: %d,\n"
           "  rcode: %d,\n"
           "  qdcount: %u,\n"
           "  ancount: %u,\n"
           "  nscount: %u,\n"
           "  arcount: %u\n"
           "}\n",
           header->id, header->qr,
           header->opcode, header->aa, header->tc, header->rd, header->ra, header->z, header->rcode, header->qdcount,
           header->ancount, header->nscount, header->arcount);
}

/**
 * Extracts (deserializes) DNS question from a buffer
 *
 * @param buffer UDP DNS message
 * @param size of buffer
 * @return pointer to heap allocated question
 */
struct question *get_question(const char *buffer, size_t size) {
    if (size < 11) {
        printf("Error: malformed question\n");
//        exit(1);
    }
    struct question *question = malloc(sizeof(struct question));
    question->qname = buffer;
    size_t qname_len = strlen(buffer) + 1;
    question->qname_len = qname_len;
    question->qtype = (uint16_t) (buffer[qname_len] << 8) | buffer[qname_len + 1];
    question->qclass = (uint16_t) (buffer[qname_len + 2] << 8) | buffer[qname_len + 3];
    return question;
}

/**
 * Decodes the qname field
 *
 * Each segment starts with a byte containing the length of
 * the segment. Immediately following the segment text is another
 * length value or null indicating the end of the name.
 *
 * For example:
 * \x06google\x03com\x00 = google.com.
 *
 * @param qname question name
 * @param len length of qname
 * @return heap allocated name
 */
char *get_name(const char *qname, size_t len) {
    char *out = malloc(len + 1);
    size_t out_offset = 0;
    uint8_t remaining = (uint8_t) qname[0];
    size_t qname_offset = 1;
    while (remaining != 0) {
        memcpy(out + out_offset, qname + qname_offset, remaining);
        out_offset += remaining;
        out[out_offset] = '.';
        out_offset += 1;
        qname_offset += remaining;
        remaining = (uint8_t) qname[qname_offset];
        qname_offset += 1;
    }
    out[out_offset] = '\0';
    return out;
}

/**
 * Prints a DNS question record
 * @param question
 */
void print_question(struct question *question) {
    char *name = get_name(question->qname, question->qname_len);
    printf("DNS Question: {\n"
           "  qname: %s\n"
           "  qtype: %s (%04X)\n"
           "  qclass: %s (%04X)\n"
           "}\n", name, get_type(question->qtype), question->qtype,
           get_class(question->qclass), question->qclass);
    free(name);
}

/**
 * Extracts (deserializes) DNS resource record from a buffer
 *
 * DNS Resource Records (RR) are used for answer, authority, and
 * additional record sections for all DNS messages.
 *
 * @param buffer UDP DNS message
 * @param size of buffer
 * @return pointer to heap allocated question
 */
struct resource *get_resource(const char *buffer, size_t size) {
    if (size < 11) {
        printf("Error: malformed resource\n");
//        exit(1);
    }
    struct resource *resource = malloc(sizeof(struct resource));
    resource->name = buffer;
    size_t name_len = strlen(buffer) + 1;
    resource->name_len = name_len;
    resource->type = (uint16_t) (buffer[name_len] << 8) | buffer[name_len + 1];
    resource->class = (uint16_t) (buffer[name_len + 2] << 8) | buffer[name_len + 3];
    for (int i = 0; i < 4; i++) {
        resource->ttl |= buffer[name_len + i + 4];
        resource->ttl <<= 8;
    }
    resource->rdlength = (uint16_t) (buffer[name_len + 8] << 8) | buffer[name_len + 9];
    for (int i = 0; i < resource->rdlength && i < 4; i++) {
        resource->rdata |= buffer[name_len + i + 10];
        resource->rdata <<= 8;
    }
    return resource;
}

/**
 * Print a resource record
 *
 * @param resource
 */
void print_resource(struct resource *resource) {
    printf("DNS Resource: {\n"
           "  name: ");
    for (int i = 0; i < resource->name_len; i++)
        printf("%02X ", resource->name[i]);
    printf("\t| ");
    for (int i = 0; i < resource->name_len; i++)
        printf("%c ", resource->name[i]);
    printf("\n  type: %s (%d)\n"
           "  class: %s (%d)\n"
           "  ttl: %d\n"
           "  rdlength: %d\n"
           "  rdata: %d\n", get_type(resource->type), resource->type, get_class(resource->class), resource->class,
           resource->ttl, resource->rdlength, resource->rdata);
}

/**
 * Convert int class to string representation
 *
 * @param class DNS class
 * @return string representation of the DNS class
 */
char *get_class(uint16_t class) {
    switch (class) {
        case 1:
            return "IN";
        case 2:
            return "CSNET";
        case 3:
            return "CHAOS";
        case 4:
            return "Hesiod";
        case 255:
            return "*";
        default:
            return "Unknown";
    }
}

/**
 * Convert int type to string representation
 *
 * @param class DNS type
 * @return string representation of the DNS type
 */
char *get_type(uint16_t type) {
    switch (type) {
        case 1:
            return "A";
        case 2:
            return "NS";
        case 3:
            return "MD";
        case 4:
            return "MF";
        case 5:
            return "CNAME";
        case 6:
            return "SOA";
        case 7:
            return "MB";
        case 8:
            return "MG";
        case 9:
            return "MR";
        case 10:
            return "NULL";
        case 11:
            return "WKS";
        case 12:
            return "PTR";
        case 13:
            return "HINFO";
        case 14:
            return "MINFO";
        case 15:
            return "MX";
        case 16:
            return "TXT";
        case 252:
            return "AXFR";
        case 253:
            return "MAILB";
        case 254:
            return "MAILA";
        case 255:
            return "*";
        default:
            return "Unknown";
    }
}