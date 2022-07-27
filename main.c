#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <errno.h>
#include "dns.h"


#define MAX_QUESTIONS 10
#define MAX_ADDITIONAL_RECORDS 10
#define MAX_ANSWERS_RECORDS 10
#define MAX_AUTHORITIES_RECORDS 10


int start_server();


struct message *get_message(struct sockaddr_storage *src_addr, char *buffer, ssize_t count);
void free_message(struct message *message);
void print_datagram(char *buf, ssize_t count);

void send_reply(struct sockaddr_storage *src_addr, struct message *message, int fd);


int main() {
    return start_server();
}

/**
 * Make it so
 * @return
 */
int start_server() {
    const char *hostname = 0;
    const char *portname = "domain";
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    struct addrinfo *res = 0;
    int err = getaddrinfo(hostname, portname, &hints, &res);
    if (err != 0) {
        printf("failed to resolve local socket address (err=%d)", err);
        exit(err);
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == -1) {
        printf("%s", strerror(errno));
        exit(errno);
    }

    if (bind(fd, res->ai_addr, res->ai_addrlen) == -1) {
        printf("%s", strerror(errno));
        exit(errno);
    }
    freeaddrinfo(res);

    printf("Bind finished\n");
    printf("Listening on port 53\n");

    char buffer[DNS_MAX_UDP_SIZE];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    ssize_t count = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &src_addr, &src_addr_len);
    if (count == -1) {
        printf("%s", strerror(errno));
        exit(errno);
    } else if (count == sizeof(buffer)) {
        printf("datagram too large for buffer: truncated");
    } else {
        struct message *message = get_message(&src_addr, buffer, count);
        printf("Message received.\n");
        send_reply(&src_addr, message, fd);
        printf("Reply sent.\n");
        free_message(message);
    }

    return 0;
}


/**
 * Formats the raw UDP buffer into a message structure
 * @param src_addr source address of the DNS message
 * @param buffer raw DNS message bytes
 * @param count length of the buffer
 * @return heap allocated message
 */
struct message *get_message(struct sockaddr_storage *src_addr, char *buffer, ssize_t count) {
    char host[NI_MAXHOST];
    getnameinfo((struct sockaddr *) src_addr, src_addr->ss_len, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
    printf("Received %zd bytes from host: %s\n", count, host);

    struct message *message = malloc(sizeof(struct message));
    size_t offset = 0;

    struct header *header = get_header(buffer, count);
    offset += DNS_HEADER_SIZE;
    message->header = header;
    print_header(header);

    struct question **questions = malloc(sizeof(struct question *) * MAX_QUESTIONS);
    for (int i = 0; i < message->header->qdcount && i < MAX_QUESTIONS; i++) {
        struct question *question = get_question(buffer + offset, count - offset);
        questions[i] = question;
        offset += question->qname_len + 4;
        print_question(question);
    }
    message->questions = questions;


    struct resource **answers = malloc(sizeof(struct resource *) * MAX_ANSWERS_RECORDS);
    for (int i = 0; i < message->header->ancount && i < MAX_ANSWERS_RECORDS; i++) {
        struct resource *answer = get_resource(buffer + DNS_HEADER_SIZE + DNS_QUESTION_SIZE, count - offset);
        answers[i] = answer;
        offset += DNS_RESOURCE_SIZE;
        print_resource(answer);
    }
    message->answers = answers;


    struct resource **authorities = malloc(sizeof(struct resource *) * MAX_AUTHORITIES_RECORDS);
    for (int i = 0; i < message->header->nscount && i < MAX_AUTHORITIES_RECORDS; i++) {
        struct resource *answer = get_resource(buffer + offset, count - offset);
        answers[i] = answer;
        offset += DNS_RESOURCE_SIZE;
        print_resource(answer);
    }
    message->authorities = authorities;


    struct resource **additionals = malloc(sizeof(struct resource *) * MAX_ADDITIONAL_RECORDS);
    for (int i = 0; i < message->header->arcount && i < MAX_ADDITIONAL_RECORDS; i++) {
        struct resource *additional = get_resource(buffer + offset, count - offset);
        additionals[i] = additional;
        offset += DNS_RESOURCE_SIZE;
        print_resource(additional);
    }
    message->additionals = additionals;

    return message;
}

/**
 * Free the message structure
 * @param message DNS message
 */
void free_message(struct message *message) {
    for (int i = 0; i < (*message).header->arcount && i < MAX_ANSWERS_RECORDS; i++) {
        free((*message).additionals[i]);
    }
    for (int i = 0; i < (*message).header->nscount && i < MAX_ANSWERS_RECORDS; i++) {
        free((*message).authorities[i]);
    }
    for (int i = 0; i < (*message).header->ancount && i < MAX_ANSWERS_RECORDS; i++) {
        free((*message).answers[i]);
    }
    for (int i = 0; i < (*message).header->qdcount && i < MAX_QUESTIONS; i++) {
        free((*message).questions[i]);
    }
    free((*message).header);
    free(message);
}

/**
 * Sends a UDP DNS reponse to the src_addr
 * @param src_addr Source address from the DNS query
 * @param message Full DNS message containing the query
 * @param fd source fd
 */
void send_reply(struct sockaddr_storage *src_addr, struct message *message, int fd) {
    char host[NI_MAXHOST];
    char service[NI_MAXSERV];
    getnameinfo((struct sockaddr *) src_addr, src_addr->ss_len, host, sizeof(host), service, sizeof(service),
                NI_NUMERICHOST);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_ADDRCONFIG;
    struct addrinfo *res = 0;
    int err = getaddrinfo(host, service, &hints, &res);
    if (err != 0) {
        printf("failed to resolve remote socket address (err=%d)", err);
    }

    uint8_t reply[30];
    memset(reply, 0, 30);
    reply[0] = (uint8_t) (message->header->id >> 8 & 0xFF);
    reply[1] = (uint8_t) (message->header->id & 0xFF);
    reply[3] = (uint8_t) 0x03;
    reply[7] = 1;  // ancount low byte, 1 answer

    // Encoded the same way qnames are, need to check if this is valid
    // Each segment contains a length and terminates in a null byte
    // <Length(6)>google<Length(3)>com<null(0)> = google.com.
    char name[] = {0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00};
    memcpy(reply + DNS_HEADER_SIZE + 1, name, sizeof(name));
    size_t offset = DNS_HEADER_SIZE + sizeof(name);
    reply[offset + 1] = 1; // Low byte of type, 1 = A record
    reply[offset + 3] = 1;  // Low byte of class, 1 = IN internet
    reply[offset + 7] = 0;  // Low byte of TTL, time in seconds, 0 means no caching
    reply[9] = 4;  // Low byte of rdlength, length in octets of the rdata field
    // reply[10] rdata, for IN A records, 32 bit Internet Address
    reply[10] = 0x8E;
    reply[11] = 0xFB;
    reply[12] = 0x10;
    reply[13] = 0x66;

    ssize_t result = sendto(fd, reply, sizeof(reply), 0, res->ai_addr, res->ai_addrlen);
    printf("\nResult %zd, sizeof(reply): %lu\n", result, sizeof(reply));
    if (result == -1) {
        printf("%s", strerror(errno));
        exit(1);
    }


}

